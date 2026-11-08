package app

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"darkscope/honeypot/internal/config"
	"darkscope/honeypot/internal/event"
	"darkscope/honeypot/internal/protocols"
	"darkscope/honeypot/internal/protocols/http"
	"darkscope/honeypot/internal/protocols/ssh"
	"darkscope/honeypot/internal/protocols/telnet"
	"darkscope/honeypot/internal/session"
	"darkscope/honeypot/internal/storage"
	"darkscope/honeypot/internal/storage/repositories"
)

type App struct {
	cfg       *config.Config
	store     *storage.Storage
	bus       *event.EventBus
	sessions  *session.Manager
	events    *repositories.EventRepository
	sessRepo  *repositories.SessionRepository
	attackers *repositories.AttackerRepository
	files     *repositories.FileRepository
	alerts    *repositories.AlertRepository
	collectors []protocols.Collector
	log       *slog.Logger
}

// New создает приложение: подключает хранилище, применяет миграции,
// создаёт шину событий, репозитории, менеджер сессий и протокольные сборщики.
func New(cfg *config.Config) (*App, error) {
	log := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	store, err := storage.Open(cfg.Storage.Path)
	if err != nil {
		return nil, fmt.Errorf("open storage: %w", err)
	}
	log.Info("storage opened", "path", cfg.Storage.Path)

	eventRepo := repositories.NewEventRepository(store.DB())
	sessRepo := repositories.NewSessionRepository(store.DB())
	attackerRepo := repositories.NewAttackerRepository(store.DB())
	fileRepo := repositories.NewFileRepository(store.DB())
	alertRepo := repositories.NewAlertRepository(store.DB())

	sessMgr := session.NewManager()
	bus := event.New(cfg.EventBus.BufferSize)
	// Storage-воркер сохраняет события в SQLite. Detection и Alert
	// пока считают события как доставленные (полная логика — в следующих фазах).
	bus.SetProcessors(
		func(e *event.Event) error { return eventRepo.Insert(context.Background(), e) },
		nil,
		nil,
	)

	// Создаём протокольные сборщики.
	var collectors []protocols.Collector

	if cfg.Protocols.SSH.Enabled {
		sshCollector, err := ssh.New(&cfg.Protocols.SSH, bus, sessMgr, log)
		if err != nil {
			store.Close()
			return nil, fmt.Errorf("create ssh collector: %w", err)
		}
		collectors = append(collectors, sshCollector)
		log.Info("ssh collector enabled", "address", cfg.Protocols.SSH.ListenAddress)
	}

	if cfg.Protocols.HTTP.Enabled {
		httpCollector, err := http.New(&cfg.Protocols.HTTP, bus, sessMgr, log)
		if err != nil {
			store.Close()
			return nil, fmt.Errorf("create http collector: %w", err)
		}
		collectors = append(collectors, httpCollector)
		log.Info("http collector enabled", "address", cfg.Protocols.HTTP.ListenAddress)
	}

	if cfg.Protocols.Telnet.Enabled {
		telnetCollector, err := telnet.New(&cfg.Protocols.Telnet, bus, sessMgr, log)
		if err != nil {
			store.Close()
			return nil, fmt.Errorf("create telnet collector: %w", err)
		}
		collectors = append(collectors, telnetCollector)
		log.Info("telnet collector enabled", "address", cfg.Protocols.Telnet.ListenAddress)
	}

	return &App{
		cfg:       cfg,
		store:     store,
		bus:       bus,
		sessions:  sessMgr,
		events:    eventRepo,
		sessRepo:  sessRepo,
		attackers: attackerRepo,
		files:     fileRepo,
		alerts:    alertRepo,
		collectors: collectors,
		log:       log,
	}, nil
}

// Run запускает шину событий, все сборщики протоколов и блокируется до отмены контекста,
// после чего выполняет graceful shutdown.
func (a *App) Run(ctx context.Context) error {
	// Запускаем шину событий.
	if err := a.bus.Start(ctx); err != nil {
		return fmt.Errorf("start event bus: %w", err)
	}
	a.log.Info("event bus started")

	// Запускаем все включённые сборщики протоколов.
	for _, coll := range a.collectors {
		if err := coll.Start(ctx); err != nil {
			a.log.Error("collector start failed", "collector", coll.Name(), "error", err)
			// Останавливаем уже запущенные сборщики.
			for _, stopped := range a.collectors[:len(a.collectors)-1] {
				_ = stopped.Stop(context.Background())
			}
			return fmt.Errorf("start collector %s: %w", coll.Name(), err)
		}
		a.log.Info("collector started", "collector", coll.Name(), "address", coll.ListenAddr())
	}

	// Ждем отмены контекста.
	<-ctx.Done()
	a.log.Info("shutdown signal received", "reason", ctx.Err())
	a.shutdown(ctx)
	return ctx.Err()
}

// shutdown выполняет graceful shutdown всех компонентов.
// Сначала останавливаем сборщики (прекращаем приём новых подключений),
// затем даём активным обработчикам время завершиться, потом останавливаем
// шину событий (с дренажем очередей), и в конце закрываем хранилище.
func (a *App) shutdown(ctx context.Context) {
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// 1. Останавливаем сборщики протоколов (первым делом прекращаем приём).
	for _, coll := range a.collectors {
		if err := coll.Stop(shutdownCtx); err != nil {
			a.log.Error("collector stop", "collector", coll.Name(), "error", err)
		} else {
			a.log.Info("collector stopped", "collector", coll.Name())
		}
	}

	// 2. Останавливаем шину событий (с дренажем очередей).
	if err := a.bus.Stop(shutdownCtx); err != nil {
		a.log.Error("bus stop", "error", err)
	} else {
		a.log.Info("event bus stopped", "metrics", a.bus.Metrics())
	}

	// 3. Закрываем менеджер сессий и хранилище.
	a.sessions.Close()
	if err := a.store.Close(); err != nil {
		a.log.Error("store close", "error", err)
	}
	a.log.Info("application shutdown complete")
}

// Close освобождает ресурсы (вызывается из main через defer).
func (a *App) Close() error {
	return a.store.Close()
}

// RunWithSignals запускает приложение с обработкой SIGINT/SIGTERM.
func RunWithSignals(ctx context.Context, cfg *config.Config) error {
	a, err := New(cfg)
	if err != nil {
		return err
	}
	defer a.Close()
	return a.Run(ctx)
}

// SignalContext возвращает контекст, отменяемый по SIGINT или SIGTERM.
func SignalContext() (context.Context, context.CancelFunc) {
	return signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
}
