package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadValidConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	content := `
listen:
  ssh: "0.0.0.0:2222"
  http: "0.0.0.0:8080"
  telnet: "0.0.0.0:2323"
api:
  listen: "127.0.0.1:9090"
  authentication: true
storage:
  driver: sqlite
  path: "./data/honeypot.db"
  max_upload_size: 10485760
  retention_days: 30
event_bus:
  buffer_size: 1000
  workers: 4
detection:
  brute_force:
    enabled: true
    max_attempts: 20
    window_seconds: 60
  suspicious_commands: true
alerts:
  telegram:
    enabled: false
    bot_token_env: TELEGRAM_BOT_TOKEN
    chat_id_env: TELEGRAM_CHAT_ID
  webhook:
    enabled: false
    url_env: WEBHOOK_URL
security:
  max_connections: 500
  max_request_body: 1048576
  enable_uploads: true
  outbound_network: false
`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("write config: %v", err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.Listen.SSH != "0.0.0.0:2222" {
		t.Errorf("ssh listen: %q", cfg.Listen.SSH)
	}
	if cfg.Listen.HTTP != "0.0.0.0:8080" {
		t.Errorf("http listen: %q", cfg.Listen.HTTP)
	}
	if cfg.Listen.Telnet != "0.0.0.0:2323" {
		t.Errorf("telnet listen: %q", cfg.Listen.Telnet)
	}
	if cfg.Storage.Path != "./data/honeypot.db" {
		t.Errorf("storage path: %q", cfg.Storage.Path)
	}
	if cfg.EventBus.BufferSize != 1000 {
		t.Errorf("buffer size: %d", cfg.EventBus.BufferSize)
	}
	if cfg.EventBus.Workers != 4 {
		t.Errorf("workers: %d", cfg.EventBus.Workers)
	}
	if !cfg.Detection.BruteForce.Enabled {
		t.Error("brute force should be enabled")
	}
	if cfg.Detection.BruteForce.MaxAttempts != 20 {
		t.Errorf("max attempts: %d", cfg.Detection.BruteForce.MaxAttempts)
	}
	if cfg.Detection.BruteForce.WindowSeconds != 60 {
		t.Errorf("window seconds: %d", cfg.Detection.BruteForce.WindowSeconds)
	}
	if !cfg.Security.EnableUploads {
		t.Error("uploads should be enabled")
	}
	if cfg.Security.OutboundNetwork {
		t.Error("outbound network should be disabled")
	}
}

func TestLoadExampleConfig(t *testing.T) {
	cfg, err := Load("../../configs/config.example.yaml")
	if err != nil {
		t.Fatalf("load example config: %v", err)
	}
	if cfg.Protocols.HTTP.MaxHeaders != 64 {
		t.Fatalf("HTTP max_headers = %d, want 64", cfg.Protocols.HTTP.MaxHeaders)
	}
	if cfg.Protocols.Telnet.LoginTimeout <= 0 {
		t.Fatal("Telnet login_timeout must be positive")
	}
}

func TestLoadMissingFile(t *testing.T) {
	_, err := Load("/nonexistent/path/config.yaml")
	if err == nil {
		t.Error("expected error for missing config file")
	}
}

func TestLoadMissingRequiredFields(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	// Пустая конфигурация — все обязательные поля отсутствуют.
	if err := os.WriteFile(path, []byte("listen: {}\n"), 0644); err != nil {
		t.Fatalf("write config: %v", err)
	}
	_, err := Load(path)
	if err == nil {
		t.Error("expected error for missing required fields")
	}
}

func TestSecretAccessors(t *testing.T) {
	cfg := &Config{
		Alerts: Alerts{
			Telegram: Telegram{
				Enabled:     true,
				BotTokenEnv: "TEST_BOT_TOKEN",
				ChatIDEnv:   "TEST_CHAT_ID",
			},
			Webhook: Webhook{
				Enabled: true,
				URLEnv:  "TEST_WEBHOOK_URL",
			},
		},
	}
	os.Setenv("TEST_BOT_TOKEN", "secret-token")
	os.Setenv("TEST_CHAT_ID", "secret-chat")
	os.Setenv("TEST_WEBHOOK_URL", "https://example.com/hook")
	defer os.Unsetenv("TEST_BOT_TOKEN")
	defer os.Unsetenv("TEST_CHAT_ID")
	defer os.Unsetenv("TEST_WEBHOOK_URL")

	if got := cfg.TelegramBotToken(); got != "secret-token" {
		t.Errorf("bot token: %q", got)
	}
	if got := cfg.TelegramChatID(); got != "secret-chat" {
		t.Errorf("chat id: %q", got)
	}
	if got := cfg.WebhookURL(); got != "https://example.com/hook" {
		t.Errorf("webhook url: %q", got)
	}
}

func TestSecretAccessorsMissingEnv(t *testing.T) {
	cfg := &Config{
		Alerts: Alerts{
			Telegram: Telegram{
				BotTokenEnv: "MISSING_BOT_TOKEN",
			},
		},
	}
	os.Unsetenv("MISSING_BOT_TOKEN")
	if got := cfg.TelegramBotToken(); got != "" {
		t.Errorf("expected empty string, got %q", got)
	}
}
