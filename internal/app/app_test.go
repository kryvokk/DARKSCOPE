package app

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"darkscope/honeypot/internal/config"
	"darkscope/honeypot/internal/storage"
	"golang.org/x/crypto/ssh"
)

func TestAppProtocolEventPipelineAndShutdown(t *testing.T) {
	cfg := &config.Config{
		Storage:  config.Storage{Path: filepath.Join(t.TempDir(), "events.db")},
		EventBus: config.EventBus{BufferSize: 128, Workers: 1},
		Protocols: config.Protocols{
			SSH:    config.SSHConfig{Enabled: true, ListenAddress: "127.0.0.1:0", MaxConnections: 8, AuthTimeout: 3 * time.Second},
			HTTP:   config.HTTPConfig{Enabled: true, ListenAddress: "127.0.0.1:0", MaxConnections: 8, ReadTimeout: time.Second, WriteTimeout: time.Second, IdleTimeout: time.Second, MaxBodySize: 1024},
			Telnet: config.TelnetConfig{Enabled: true, ListenAddress: "127.0.0.1:0", MaxConnections: 8, LoginTimeout: 3 * time.Second, ReadTimeout: time.Second, WriteTimeout: time.Second},
		},
	}
	a, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- a.Run(ctx) }()
	addrs := make(map[string]string)
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		for _, collector := range a.collectors {
			if collector.IsRunning() {
				addrs[collector.Name()] = collector.ListenAddr()
			}
		}
		if len(addrs) == 3 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if len(addrs) != 3 {
		cancel()
		t.Fatalf("collectors did not start: %v", addrs)
	}
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get("http://" + addrs["http"] + "/login?probe=1")
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	_ = resp.Body.Close()

	sshRaw := mustDial(t, addrs["ssh"])
	sshConn, chans, reqs, err := ssh.NewClientConn(sshRaw, addrs["ssh"], &ssh.ClientConfig{
		User: "audit", Auth: []ssh.AuthMethod{ssh.Password("secret")}, HostKeyCallback: ssh.InsecureIgnoreHostKey(), Timeout: 2 * time.Second,
	})
	if err != nil {
		cancel()
		t.Fatalf("SSH handshake: %v", err)
	}
	sshClient := ssh.NewClient(sshConn, chans, reqs)
	defer sshClient.Close()
	sshCh, sshReqs, err := sshClient.OpenChannel("session", nil)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	go ssh.DiscardRequests(sshReqs)
	_, err = sshCh.SendRequest("shell", true, nil)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	_, _ = io.WriteString(sshCh, "cat /etc/shadow\r")
	_ = sshRaw.SetReadDeadline(time.Now().Add(2 * time.Second))
	sshOut := make([]byte, 8192)
	var got strings.Builder
	for !strings.Contains(got.String(), "not-a-real-hash") {
		n, e := sshCh.Read(sshOut)
		if e != nil {
			cancel()
			t.Fatalf("SSH command output %q: %v", got.String(), e)
		}
		got.Write(sshOut[:n])
	}
	_ = sshCh.Close()

	telnetConn, err := net.DialTimeout("tcp", addrs["telnet"], 2*time.Second)
	if err != nil {
		cancel()
		t.Fatalf("Telnet dial: %v", err)
	}
	_ = telnetConn.SetDeadline(time.Now().Add(2 * time.Second))
	reader := bufio.NewReader(telnetConn)
	if _, err = reader.ReadString(':'); err != nil {
		cancel()
		t.Fatalf("Telnet login prompt: %v", err)
	}
	_, _ = io.WriteString(telnetConn, "audit\r\n")
	if _, err = reader.ReadString(':'); err != nil {
		cancel()
		t.Fatalf("Telnet password prompt: %v", err)
	}
	for i := 0; i < 2; i++ {
		_, _ = io.WriteString(telnetConn, "secret\r\n")
		if _, err = reader.ReadString(':'); err != nil {
			cancel()
			t.Fatal(err)
		}
		_, _ = io.WriteString(telnetConn, "audit\r\n")
		if _, err = reader.ReadString(':'); err != nil {
			cancel()
			t.Fatal(err)
		}
	}
	_, _ = io.WriteString(telnetConn, "secret\r\n")
	_, _ = reader.ReadString('$')
	_, _ = io.WriteString(telnetConn, "cat /etc/shadow\r\n")
	telOut := ""
	for !strings.Contains(telOut, "not-a-real-hash") {
		line, e := reader.ReadString('\n')
		if e != nil {
			cancel()
			t.Fatalf("Telnet output %q: %v", telOut, e)
		}
		telOut += line
	}
	_ = telnetConn.Close()
	cancel()
	select {
	case err := <-done:
		if err != context.Canceled {
			t.Fatalf("Run returned %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("App shutdown timed out")
	}
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}
	store, err := storage.Open(cfg.Storage.Path)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	for _, protocol := range []string{"ssh", "http", "telnet"} {
		var count int
		if err := store.DB().QueryRow(`SELECT COUNT(*) FROM events WHERE protocol=?`, protocol).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count == 0 {
			t.Fatalf("no %s events stored", protocol)
		}
	}
	var requestCount int
	if err := store.DB().QueryRow(`SELECT COUNT(*) FROM events WHERE protocol='http' AND event_type='request'`).Scan(&requestCount); err != nil {
		t.Fatal(err)
	}
	if requestCount != 1 {
		t.Fatalf("stored HTTP request events = %d, want 1", requestCount)
	}
	for _, protocol := range []string{"ssh", "telnet"} {
		var n int
		if err = store.DB().QueryRow(`SELECT COUNT(*) FROM events WHERE protocol=? AND event_type='honeytoken_access'`, protocol).Scan(&n); err != nil {
			t.Fatal(err)
		}
		if n < 1 {
			t.Fatalf("no %s honeytoken events stored", protocol)
		}
	}
}

func mustDial(t *testing.T, address string) net.Conn {
	t.Helper()
	conn, err := net.DialTimeout("tcp", address, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	return conn
}
