package ssh

import (
	"context"
	"io"
	"log/slog"
	"net"
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
	mu      sync.Mutex
	events  []*event.Event
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
		Enabled:       true,
		ListenAddress: "127.0.0.1:0",
		AuthTimeout:   5 * time.Second,
		MaxConnections:  10,
		Banner:        "SSH-2.0-test",
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
		Enabled:       true,
		ListenAddress: "127.0.0.1:0",
		AuthTimeout:   5 * time.Second,
		MaxConnections:  10,
		Banner:        "SSH-2.0-test",
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
	defer coll.Stop(context.Background())

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
		Enabled:       true,
		ListenAddress: "127.0.0.1:0",
		AuthTimeout:   5 * time.Second,
		MaxConnections:  10,
		Banner:        "SSH-2.0-test",
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
	defer coll.Stop(context.Background())

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

