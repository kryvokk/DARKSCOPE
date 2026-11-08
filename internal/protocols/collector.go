package protocols

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	"darkscope/honeypot/internal/event"
	"darkscope/honeypot/internal/session"
)

// Collector — общий интерфейс для всех протокольных сборщиков (SSH, HTTP, Telnet).
// Каждый сборщик запускается независимо, принимает подключения, формирует события
// и публикует их через Event Bus, отслеживая сессии через Session Manager.
type Collector interface {
	// Name возвращает имя протокола (например, "ssh", "http", "telnet").
	Name() string
	// ListenAddr возвращает адрес, на котором сборщик слушает подключения.
	ListenAddr() string
	// Start запускает прослушивание подключений.
	Start(ctx context.Context) error
	// Stop инициирует graceful shutdown: прекращает приём новых подключений,
	// даёт активным обработчикам время завершиться.
	Stop(ctx context.Context) error
	// IsRunning возвращает true, если сборщик запущен и принимает подключения.
	IsRunning() bool
}

// CollectorConfig содержит общие настройки для сборщиков протоколов.
type CollectorConfig struct {
	Enabled           bool      `yaml:"enabled"`
	ListenAddress     string    `yaml:"listen_address"`
	MaxConnections    int       `yaml:"max_connections"`
	ReadTimeout       time.Duration `yaml:"read_timeout"`
	WriteTimeout      time.Duration `yaml:"write_timeout"`
	IdleTimeout       time.Duration `yaml:"idle_timeout"`
	MaxConnectionLife time.Duration `yaml:"max_connection_life"`
}

// BaseCollector содержит общие поля для всех сборщиков.
type BaseCollector struct {
	name        string
	listenAddr  string
	eventBus    *event.EventBus
	sessions    *session.Manager
	ctx         context.Context
	cancel      context.CancelFunc
	running     int32
	wg          sync.WaitGroup
	connLimiter chan struct{}
}

func (b *BaseCollector) Name() string {
	return b.name
}

func (b *BaseCollector) ListenAddr() string {
	return b.listenAddr
}

func (b *BaseCollector) IsRunning() bool {
	return atomic.LoadInt32(&b.running) == 1
}

func (b *BaseCollector) acquireConn() bool {
	if b.connLimiter == nil {
		return true
	}
	select {
	case b.connLimiter <- struct{}{}:
		return true
	default:
		return false
	}
}

func (b *BaseCollector) releaseConn() {
	if b.connLimiter == nil {
		return
	}
	select {
	case <-b.connLimiter:
	default:
	}
}

var _ = CollectorConfig{}
var _ = session.Session{}
var _ = event.Event{}
var _ = time.Second
