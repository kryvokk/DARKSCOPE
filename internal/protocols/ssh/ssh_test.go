package ssh

import (
	"context"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"darkscope/honeypot/internal/config"
	"darkscope/honeypot/internal/event"
	"darkscope/honeypot/internal/session"
)

// captureProcessor captures events for testing.
type captureProcessor struct {
	mu     sync.Mutex
	events []*event.Event
}

func (c *captureProcessor) Publish(ev *event.Event) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.events = append(c.events, ev)
	return nil
}

func (c *captureProcessor) Events() []*event.Event {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]*event.Event, len(c.events))
	copy(out, c.events)
	return out
}

func TestSSHCollectorStartStop(t *testing.T) {
	cfg := &config.SSHConfig{
		Enabled:        true,
		ListenAddress:  "127.0.0.1:0",
		AuthTimeout:    5 * time.Second,
		MaxConnections: 10,
		Banner:         "SSH-2.0-test",
	}
	capture := &captureProcessor{}
	sessMgr := session.NewManager()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	coll, err := New(cfg, capture, sessMgr, logger)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := coll.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if !coll.IsRunning() {
		t.Error("collector should be running")
	}

	addr := coll.ListenAddr()
	if addr == "" {
		t.Error("listen addr should not be empty")
	}

	if err := coll.Stop(ctx); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if coll.IsRunning() {
		t.Error("collector should be stopped")
	}
}

func TestSSHCollectorConnectionAndEvents(t *testing.T) {
	cfg := &config.SSHConfig{
		Enabled:        true,
		ListenAddress:  "127.0.0.1:0",
		AuthTimeout:    5 * time.Second,
		MaxConnections: 10,
		Banner:         "SSH-2.0-test",
	}
	capture := &captureProcessor{}
	sessMgr := session.NewManager()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	coll, err := New(cfg, capture, sessMgr, logger)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := coll.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer func() {
		stopCtx, stopCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer stopCancel()
		_ = coll.Stop(stopCtx)
	}()

	addr := coll.ListenAddr()

	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	sshConn, chans, reqs, err := ssh.NewClientConn(conn, addr, &ssh.ClientConfig{
		User:            "testuser",
		Auth:            []ssh.AuthMethod{ssh.Password("testpass")},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	})
	if err != nil {
		t.Fatalf("ssh client handshake: %v", err)
	}
	sshConn.Close()
	go ssh.DiscardRequests(reqs)
	for range chans {
		// drain channels
	}

	time.Sleep(300 * time.Millisecond)

	events := capture.Events()
	if len(events) == 0 {
		t.Error("expected at least one event to be published")
	}

	hasConnect := false
	hasLoginAttempt := false
	for _, ev := range events {
		if ev.EventType == event.EventTypeConnect {
			hasConnect = true
		}
		if ev.EventType == event.EventTypeLoginAttempt {
			hasLoginAttempt = true
		}
	}
	if !hasConnect {
		t.Error("expected connect event")
	}
	if !hasLoginAttempt {
		t.Error("expected login_attempt event")
	}
}

func TestSSHCollectorConcurrentConnections(t *testing.T) {
	cfg := &config.SSHConfig{
		Enabled:        true,
		ListenAddress:  "127.0.0.1:0",
		AuthTimeout:    5 * time.Second,
		MaxConnections: 10,
		Banner:         "SSH-2.0-test",
	}
	capture := &captureProcessor{}
	sessMgr := session.NewManager()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	coll, err := New(cfg, capture, sessMgr, logger)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := coll.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer func() {
		stopCtx, stopCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer stopCancel()
		_ = coll.Stop(stopCtx)
	}()

	addr := coll.ListenAddr()
	var wg sync.WaitGroup
	var connected int64

	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
			if err != nil {
				return
			}
			conn.Close()
			atomic.AddInt64(&connected, 1)
		}()
	}
	wg.Wait()

	if got := atomic.LoadInt64(&connected); got < 5 {
		t.Errorf("expected at least 5 connections, got %d", got)
	}
}

// stopCollector останавливает коллектор с ограниченным по времени контекстом.
func stopCollector(t *testing.T, coll *Collector, d time.Duration) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), d)
	defer cancel()
	return coll.Stop(ctx)
}

// TestSSHAuthCapture проверяет захват username/длины пароля и версий в событиях.
func TestSSHAuthCapture(t *testing.T) {
	cfg := &config.SSHConfig{
		Enabled:        true,
		ListenAddress:  "127.0.0.1:0",
		AuthTimeout:    5 * time.Second,
		MaxConnections: 10,
		Banner:         "SSH-2.0-test",
	}
	capture := &captureProcessor{}
	sessMgr := session.NewManager()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	coll, err := New(cfg, capture, sessMgr, logger)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := coll.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer func() { _ = stopCollector(t, coll, 5*time.Second) }()

	addr := coll.ListenAddr()

	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	sshConn, chans, reqs, err := ssh.NewClientConn(conn, addr, &ssh.ClientConfig{
		User:            "root",
		Auth:            []ssh.AuthMethod{ssh.Password("toor1234")},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	})
	if err != nil {
		t.Fatalf("ssh client handshake: %v", err)
	}
	sshConn.Close()
	go ssh.DiscardRequests(reqs)
	for range chans {
	}

	// Ожидание доставки событий capture-процессору.
	deadline := time.Now().Add(3 * time.Second)
	var events []*event.Event
	for time.Now().Before(deadline) {
		events = capture.Events()
		if len(events) >= 3 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	events = capture.Events()
	var loginAttempt, loginSuccess, connect *event.Event
	for _, ev := range events {
		switch ev.EventType {
		case event.EventTypeConnect:
			if connect == nil {
				connect = ev
			}
		case event.EventTypeLoginAttempt:
			if loginAttempt == nil {
				loginAttempt = ev
			}
		case event.EventTypeLoginSuccess:
			if loginSuccess == nil {
				loginSuccess = ev
			}
		}
	}

	if connect == nil {
		t.Fatal("expected connect event")
	}
	if cv, ok := connect.Metadata["client_version"].(string); !ok || cv == "" {
		t.Errorf("connect event must have client_version metadata, got %v", connect.Metadata)
	}

	if loginAttempt == nil {
		t.Fatal("expected login_attempt event")
	}
	if want := coll.listener.Addr().(*net.TCPAddr).Port; loginAttempt.DestPort != want {
		t.Errorf("login_attempt dest port = %d, want bound port %d", loginAttempt.DestPort, want)
	}
	if got := loginAttempt.Payload.(map[string]interface{})["user"]; got != "root" {
		t.Errorf("login_attempt user = %v, want root", got)
	}
	if got := loginAttempt.Payload.(map[string]interface{})["password_length"]; got != len("toor1234") {
		t.Errorf("login_attempt password_length = %v, want %d", got, len("toor1234"))
	}
	if got := loginAttempt.Payload.(map[string]interface{})["password"]; got != "***" {
		t.Errorf("password must be masked, got %v", got)
	}

	if loginSuccess == nil {
		t.Fatal("expected login_success event")
	}
	if got := loginSuccess.Payload.(map[string]interface{})["user"]; got != "root" {
		t.Errorf("login_success user = %v, want root", got)
	}
}

func TestSSHVirtualShellHoneytoken(t *testing.T) {
	capture := &captureProcessor{}
	cfg := &config.SSHConfig{ListenAddress: "127.0.0.1:0", AuthTimeout: 5 * time.Second, MaxConnections: 4}
	c, err := New(cfg, capture, session.NewManager(), slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err = c.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer c.Stop(context.Background())
	conn, err := net.Dial("tcp", c.ListenAddr())
	if err != nil {
		t.Fatal(err)
	}
	clientConn, chans, reqs, err := ssh.NewClientConn(conn, c.ListenAddr(), &ssh.ClientConfig{User: "u", Auth: []ssh.AuthMethod{ssh.Password("p")}, HostKeyCallback: ssh.InsecureIgnoreHostKey(), Timeout: 3 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	client := ssh.NewClient(clientConn, chans, reqs)
	defer client.Close()
	ch, in, err := client.OpenChannel("session", nil)
	if err != nil {
		t.Fatal(err)
	}
	go ssh.DiscardRequests(in)
	_, err = ch.SendRequest("shell", true, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = ch.Write([]byte("cat /etc/shadow\r"))
	buf := make([]byte, 4096)
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	var output strings.Builder
	for !strings.Contains(output.String(), "not-a-real-hash") {
		n, readErr := ch.Read(buf)
		if readErr != nil {
			t.Fatalf("shell output %q: %v", output.String(), readErr)
		}
		output.Write(buf[:n])
	}
	if !strings.Contains(output.String(), "not-a-real-hash") {
		t.Fatalf("unexpected shell output %q", output.String())
	}
	ch.Close()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		for _, e := range capture.Events() {
			if e.EventType == event.EventTypeHoneytokenAccess {
				return
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("missing honeytoken event")
}

// TestSSHStopClosesActiveConnections проверяет, что Stop завершает
// соединение с активным SSH-сеансом за ограниченное время.
func TestSSHStopClosesActiveConnections(t *testing.T) {
	cfg := &config.SSHConfig{
		Enabled:        true,
		ListenAddress:  "127.0.0.1:0",
		AuthTimeout:    10 * time.Second,
		MaxConnections: 10,
		Banner:         "SSH-2.0-test",
	}
	capture := &captureProcessor{}
	sessMgr := session.NewManager()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	coll, err := New(cfg, capture, sessMgr, logger)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := coll.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}

	addr := coll.ListenAddr()

	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	sshConn, _, _, err := ssh.NewClientConn(conn, addr, &ssh.ClientConfig{
		User:            "user",
		Auth:            []ssh.AuthMethod{ssh.Password("pass")},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	})
	if err != nil {
		t.Fatalf("ssh client handshake: %v", err)
	}
	defer sshConn.Close()

	// Stop обязан принудительно закрыть живое соединение и дождаться
	// обработчика — без этого он упёрся бы в AuthTimeout (10 c).
	start := time.Now()
	if err := stopCollector(t, coll, 3*time.Second); err != nil {
		t.Fatalf("Stop with active connection: %v (elapsed %s)", err, time.Since(start))
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Errorf("Stop took too long: %s", elapsed)
	}
}

// TestSSHHandshakeGarbage проверяет публикацию protocol_error
// при некорректном поведении клиента до SSH-handshake.
func TestSSHHandshakeGarbage(t *testing.T) {
	cfg := &config.SSHConfig{
		Enabled:        true,
		ListenAddress:  "127.0.0.1:0",
		AuthTimeout:    5 * time.Second,
		MaxConnections: 10,
		Banner:         "SSH-2.0-test",
	}
	capture := &captureProcessor{}
	sessMgr := session.NewManager()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	coll, err := New(cfg, capture, sessMgr, logger)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := coll.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer func() { _ = stopCollector(t, coll, 5*time.Second) }()

	addr := coll.ListenAddr()

	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	// Отправляем мусор вместо строки версии SSH.
	_, _ = conn.Write([]byte("GET / HTTP/1.1\r\nHost: localhost\r\n\r\n"))
	time.Sleep(100 * time.Millisecond)
	conn.Close()

	deadline := time.Now().Add(3 * time.Second)
	found := false
	for time.Now().Before(deadline) && !found {
		for _, ev := range capture.Events() {
			if ev.EventType == event.EventTypeProtocolError {
				found = true
				break
			}
		}
		if !found {
			time.Sleep(20 * time.Millisecond)
		}
	}
	if !found {
		t.Error("expected protocol_error event on garbage handshake")
	}
}

// TestSanitizeServerVersion проверяет валидацию SSH-баннера.
func TestSanitizeServerVersion(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"", "SSH-2.0-DARKSCOPE"},
		{"SSH-2.0-Custom", "SSH-2.0-Custom"},
		{"SSH-1.99-old", "SSH-1.99-old"},
		{"invalid-banner", "SSH-2.0-DARKSCOPE"},
		{"SSH-2.0-bad\r\nInject", "SSH-2.0-DARKSCOPE"},
		{"SSH-2.0-" + strings.Repeat("x", 100), "SSH-2.0-DARKSCOPE"},
	}
	for _, tc := range cases {
		if got := sanitizeServerVersion(tc.in); got != tc.want {
			t.Errorf("sanitizeServerVersion(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
