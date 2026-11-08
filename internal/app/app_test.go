package app

import (
	"context"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"darkscope/honeypot/internal/config"
	"darkscope/honeypot/internal/storage"
)

func TestAppHTTPEventPipelineAndShutdown(t *testing.T) {
	cfg := &config.Config{
		Storage:   config.Storage{Path: filepath.Join(t.TempDir(), "events.db")},
		EventBus:  config.EventBus{BufferSize: 128, Workers: 1},
		Protocols: config.Protocols{HTTP: config.HTTPConfig{Enabled: true, ListenAddress: "127.0.0.1:0", MaxConnections: 8, ReadTimeout: time.Second, WriteTimeout: time.Second, IdleTimeout: time.Second, MaxBodySize: 1024}},
	}
	a, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- a.Run(ctx) }()
	var addr string
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if a.collectors[0].IsRunning() {
			addr = a.collectors[0].ListenAddr()
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if addr == "" {
		cancel()
		t.Fatal("HTTP collector did not start")
	}
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get("http://" + addr + "/login?probe=1")
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	_ = resp.Body.Close()
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
	var count int
	if err := store.DB().QueryRow(`SELECT COUNT(*) FROM events WHERE protocol='http' AND event_type='request'`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("stored request event count = %d, want 1", count)
	}
}
