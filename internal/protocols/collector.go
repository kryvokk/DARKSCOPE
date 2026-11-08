package protocols

import (
	"context"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"darkscope/honeypot/internal/event"
	"darkscope/honeypot/internal/session"
)

// Collector — общий интерфейс для всех протокольных сборщиков (SSH, HTTP, Telnet).
type Collector interface {
	Name() string
	ListenAddr() string
	Start(ctx context.Context) error
	Stop(ctx context.Context) error
	IsRunning() bool
}

// CollectorConfig содержит общие настройки для сборщиков протоколов.
type CollectorConfig struct {
	Enabled           bool          `yaml:"enabled"`
	ListenAddress     string        `yaml:"listen_address"`
	MaxConnections    int           `yaml:"max_connections"`
	ReadTimeout       time.Duration `yaml:"read_timeout"`
	WriteTimeout      time.Duration `yaml:"write_timeout"`
	IdleTimeout       time.Duration `yaml:"idle_timeout"`
	MaxConnectionLife time.Duration `yaml:"max_connection_life"`
}

// BaseCollector содержит общие поля и методы для всех сборщиков.
type BaseCollector struct {
	name        string
	listenAddr  string
	EventBus    *event.EventBus
	Sessions    *session.Manager
	Listener    net.Listener

	ctx    context.Context
	cancel context.CancelFunc
	running int32
	wg      sync.WaitGroup
	connLimiter chan struct{}
}

// Name возвращает имя протокола сборщика.
func (b *BaseCollector) Name() string {
	return b.name
}

// ListenAddr возвращает адрес прослушивания сборщика.
func (b *BaseCollector) ListenAddr() string {
	return b.listenAddr
}

// SetContext устанавливает контекст и функцию отмены.
func (b *BaseCollector) SetContext(ctx context.Context, cancel context.CancelFunc) {
	b.ctx = ctx
	b.cancel = cancel
}

// GetCancel возвращает функцию отмены контекста.
func (b *BaseCollector) GetCancel() context.CancelFunc {
	return b.cancel
}

// GetWG возвращает WaitGroup для отслеживания горутин.
func (b *BaseCollector) GetWG() *sync.WaitGroup {
	return &b.wg
}

// AcquireConn пытается занять слот соединения. Возвращает false при превышении лимита.
func (b *BaseCollector) AcquireConn() bool {
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

// ReleaseConn освобождает слот соединения.
func (b *BaseCollector) ReleaseConn() {
	if b.connLimiter == nil {
		return
	}
	select {
	case <-b.connLimiter:
	default:
	}
}

// SetRunning устанавливает флаг запуска.
func (b *BaseCollector) SetRunning(v bool) {
	if v {
		atomic.StoreInt32(&b.running, 1)
	} else {
		atomic.StoreInt32(&b.running, 0)
	}
}

// IsRunning возвращает true, если сборщик запущен.
func (b *BaseCollector) IsRunning() bool {
	return atomic.LoadInt32(&b.running) == 1
}

// GetRunning возвращает указатель на флаг running для atomar операций.
func (b *BaseCollector) GetRunning() *int32 {
	return &b.running
}

// SetConnLimiter устанавливает канал для ограничения количества соединений.
func (b *BaseCollector) SetConnLimiter(ch chan struct{}) {
	b.connLimiter = ch
}

var _ = CollectorConfig{}
var _ = session.Session{}
var _ = event.Event{}
var _ = time.Second
