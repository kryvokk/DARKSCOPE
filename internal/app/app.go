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
	"darkscope/honeypot/internal/session"
	"darkscope/honeypot/internal/storage"
	"darkscope/honeypot/internal/storage/repositories"
)

type App struct {
	cfg     *config.Config
	store   *storage.Storage
	bus     *event.EventBus
	sessions *session.Manager
	events   *repositories.EventRepository
	sessRepo *repositories.SessionRepository
	attackers *repositories.AttackerRepository
	files    *repositories.FileRepository
	alerts   *repositories.AlertRepository
	log      *slog.Logger
}

// New создает приложение: подключает хранилище, применяет миграции,
// создаёт шину событий, репозитории и менеджер сессий.
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

	return &App{
		cfg: cfg,
		store: store,
		bus: bus,
		sessions: sessMgr,
		events: eventRepo,
		sessRepo: sessRepo,
		attackers: attackerRepo,
		files: fileRepo,
		alerts: alertRepo,
		log: log,
	}, nil
}

// Run запускает шину событий и блокируется до отмены контекста,
// после чего выполняет graceful shutdown.
func (a *App) Run(ctx context.Context) error {
	if err := a.bus.Start(ctx); err != nil {
		return fmt.Errorf("start event bus: %w", err)
	}
	a.log.Info("event bus started")

	<-ctx.Done()
	a.log.Info("shutdown signal received", "reason", ctx.Err())
	a.shutdown(ctx)
	return ctx.Err()
}

// shutdown останавливает шину с дренажем очередей, менеджер сессий и хранилище.
func (a *App) shutdown(ctx context.Context) {
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := a.bus.Stop(shutdownCtx); err != nil {
		a.log.Error("bus stop", "error", err)
	} else {
		a.log.Info("event bus stopped", "metrics", a.bus.Metrics())
	}
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
