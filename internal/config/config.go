package config

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// Listen содержит адреса протокольных слушателей.
type Listen struct {
	SSH     string `yaml:"ssh"`
	HTTP    string `yaml:"http"`
	Telnet  string `yaml:"telnet"`
}

// API содержит настройки REST API.
type API struct {
	Listen         string `yaml:"listen"`
	Authentication bool   `yaml:"authentication"`
}

// Storage содержит настройки хранилища.
type Storage struct {
	Driver        string `yaml:"driver"`
	Path          string `yaml:"path"`
	MaxUploadSize int64  `yaml:"max_upload_size"`
	RetentionDays int    `yaml:"retention_days"`
}

// BruteForce содержит пороги детектора брутфорса.
type BruteForce struct {
	Enabled       bool  `yaml:"enabled"`
	MaxAttempts   int   `yaml:"max_attempts"`
	WindowSeconds int   `yaml:"window_seconds"`
}

// Detection содержит настройки модуля обнаружения.
type Detection struct {
	BruteForce          BruteForce `yaml:"brute_force"`
	SuspiciousCommands  bool       `yaml:"suspicious_commands"`
}

// Telegram содержит настройки оповещений через Telegram.
type Telegram struct {
	Enabled     bool   `yaml:"enabled"`
	BotTokenEnv string `yaml:"bot_token_env"`
	ChatIDEnv   string `yaml:"chat_id_env"`
}

// Webhook содержит настройки оповещений через webhook.
type Webhook struct {
	Enabled bool   `yaml:"enabled"`
	URLEnv  string `yaml:"url_env"`
}

// Alerts содержит настройки оповещений.
type Alerts struct {
	Telegram Telegram `yaml:"telegram"`
	Webhook  Webhook  `yaml:"webhook"`
}

// Security содержит ограничения безопасности.
type Security struct {
	MaxConnections   int   `yaml:"max_connections"`
	MaxRequestBody   int64 `yaml:"max_request_body"`
	EnableUploads    bool  `yaml:"enable_uploads"`
	OutboundNetwork  bool  `yaml:"outbound_network"`
}

// EventBus содержит настройки шины событий.
type EventBus struct {
	BufferSize int `yaml:"buffer_size"`
	Workers    int `yaml:"workers"`
}

// SSHConfig содержит настройки SSH сборщика.
type SSHConfig struct {
	Enabled       bool          `yaml:"enabled"`
	ListenAddress string        `yaml:"listen_address"`
	HostKeyPath   string        `yaml:"host_key_path"`
	MaxConnections int         `yaml:"max_connections"`
	AuthTimeout   time.Duration `yaml:"auth_timeout"`
	Banner        string        `yaml:"banner"`
}

// HTTPConfig содержит настройки HTTP сборщика.
type HTTPConfig struct {
	Enabled        bool          `yaml:"enabled"`
	ListenAddress  string        `yaml:"listen_address"`
	MaxConnections int           `yaml:"max_connections"`
	ReadTimeout    time.Duration `yaml:"read_timeout"`
	WriteTimeout   time.Duration `yaml:"write_timeout"`
	IdleTimeout    time.Duration `yaml:"idle_timeout"`
	MaxBodySize    int64         `yaml:"max_body_size"`
	MaxHeaders     int           `yaml:"max_headers"`
	TLSCertFile    string        `yaml:"tls_cert_file"`
	TLSKeyFile     string        `yaml:"tls_key_file"`
}

// TelnetConfig содержит настройки Telnet сборщика.
type TelnetConfig struct {
	Enabled       bool          `yaml:"enabled"`
	ListenAddress string        `yaml:"listen_address"`
	MaxConnections int         `yaml:"max_connections"`
	ReadTimeout   time.Duration `yaml:"read_timeout"`
	WriteTimeout  time.Duration `yaml:"write_timeout"`
	IdleTimeout   time.Duration `yaml:"idle_timeout"`
	LoginTimeout  time.Duration `yaml:"login_timeout"`
	Banner        string        `yaml:"banner"`
}

// Protocols содержит настройки всех протокольных сборщиков.
type Protocols struct {
	SSH   SSHConfig   `yaml:"ssh"`
	HTTP  HTTPConfig  `yaml:"http"`
	Telnet TelnetConfig `yaml:"telnet"`
}

// Config — корневая конфигурация приложения.
type Config struct {
	Listen    Listen    `yaml:"listen"`
	API       API       `yaml:"api"`
	Storage   Storage   `yaml:"storage"`
	EventBus  EventBus  `yaml:"event_bus"`
	Detection Detection `yaml:"detection"`
	Alerts    Alerts    `yaml:"alerts"`
	Security  Security  `yaml:"security"`
	Protocols Protocols `yaml:"protocols"`
}

// Load загружает конфигурацию из YAML-файла.
// Секретные значения (бот-токен, chat-id, URL вебхука) не хранятся в файле;
// в конфиге указаны только имена переменных окружения, фактические значения
// читаются из os.LookupEnv при вызове соответствующих сервисов.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}

	if err := cfg.validate(); err != nil {
		return nil, fmt.Errorf("validate config: %w", err)
	}

	return &cfg, nil
}

func (c *Config) validate() error {
	if c.Listen.SSH == "" {
		return fmt.Errorf("listen.ssh is required")
	}
	if c.Listen.HTTP == "" {
		return fmt.Errorf("listen.http is required")
	}
	if c.Listen.Telnet == "" {
		return fmt.Errorf("listen.telnet is required")
	}
	if c.Storage.Path == "" {
		return fmt.Errorf("storage.path is required")
	}
	if c.EventBus.BufferSize <= 0 {
		return fmt.Errorf("event_bus.buffer_size must be positive")
	}
	if c.EventBus.Workers <= 0 {
		return fmt.Errorf("event_bus.workers must be positive")
	}
	return nil
}

// TelegramBotToken возвращает значение токена бота из переменной окружения.
func (c *Config) TelegramBotToken() string {
	return os.Getenv(c.Alerts.Telegram.BotTokenEnv)
}

// TelegramChatID возвращает значение chat-id из переменной окружения.
func (c *Config) TelegramChatID() string {
	return os.Getenv(c.Alerts.Telegram.ChatIDEnv)
}

// WebhookURL возвращает URL вебхука из переменной окружения.
func (c *Config) WebhookURL() string {
	return os.Getenv(c.Alerts.Webhook.URLEnv)
}
