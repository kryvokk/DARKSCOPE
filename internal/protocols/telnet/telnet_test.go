package telnet

import (
	"bufio"
	"context"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"darkscope/honeypot/internal/config"
	"darkscope/honeypot/internal/event"
	"darkscope/honeypot/internal/session"
)

type recorder struct {
	mu     sync.Mutex
	events []*event.Event
}

func (r *recorder) Publish(e *event.Event) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, e)
	return nil
}
func (r *recorder) snapshot() []*event.Event {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]*event.Event(nil), r.events...)
}

func TestReadTelnetLineFiltersIACAndBounds(t *testing.T) {
	r := bufio.NewReader(strings.NewReader("ro\xff\xfb\x01ot\r\n"))
	got, err := readTelnetLine(r, 8)
	if err != nil || got != "root" {
		t.Fatalf("got %q, %v", got, err)
	}
	if _, err := readTelnetLine(bufio.NewReader(strings.NewReader("12345\n")), 4); err == nil {
		t.Fatal("expected line length error")
	}
}

func TestTelnetCapturesCredentialsWithoutShellAndStopsActiveConn(t *testing.T) {
	recorder := &recorder{}
	mgr := session.NewManager()
	c, err := New(&config.TelnetConfig{ListenAddress: "127.0.0.1:0", MaxConnections: 2, LoginTimeout: 3 * time.Second, IdleTimeout: time.Second}, recorder, mgr, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = c.Stop(ctx)
	}()

	conn, err := net.Dial("tcp", c.ListenAddr())
	if err != nil {
		t.Fatal(err)
	}
	r := bufio.NewReader(conn)
	readUntil := func(want string) {
		t.Helper()
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		line, e := r.ReadString(':')
		if e != nil || !strings.Contains(line, want) {
			t.Fatalf("prompt %q, %v (want %q)", line, e, want)
		}
	}
	_, _ = r.ReadString('\n')
	readUntil("login:")
	_, _ = io.WriteString(conn, "root\r\n")
	readUntil("Password:")
	_, _ = io.WriteString(conn, "s3cret\r\n")
	readUntil("login:")
	var login *event.Event
	for _, e := range recorder.snapshot() {
		if e.EventType == event.EventTypeLoginAttempt {
			login = e
			break
		}
	}
	if login == nil {
		t.Fatal("missing login attempt")
	}
	if want := c.listener.Addr().(*net.TCPAddr).Port; login.DestPort != want {
		t.Errorf("login attempt dest port = %d, want bound port %d", login.DestPort, want)
	}
	p := login.Payload.(map[string]interface{})
	if p["username"] != "root" || p["password"] != "***" || p["password_length"] != 6 {
		t.Fatalf("unexpected credential payload: %#v", p)
	}
	// A command is treated as the next username and can never invoke a shell.
	_, _ = io.WriteString(conn, "id\r\n")
	readUntil("Password:")
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := c.Stop(ctx); err != nil {
		t.Fatalf("Stop with active connection: %v", err)
	}
	_ = conn.Close()
	for _, e := range recorder.snapshot() {
		if e.EventType == event.EventTypeCommand {
			t.Fatal("Telnet must not publish or execute commands")
		}
	}
}
