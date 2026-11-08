package ssh

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/ssh"

	"darkscope/honeypot/internal/config"
	"darkscope/honeypot/internal/event"
	"darkscope/honeypot/internal/protocols"
	"darkscope/honeypot/internal/session"
)

// authAttempt хранит данные последней попытки аутентификации для соединения.
type authAttempt struct {
	mu     sync.Mutex
	user   string
	pass   string
	result string // "pending" | "success" | "failure"
}

// Collector реализует SSH Honeypot.
type Collector struct {
	protocols.BaseCollector
	cfg       *config.SSHConfig
	serverCfg *ssh.ServerConfig
	log       *slog.Logger
	authMu    sync.Mutex
	authMap   map[string]*authAttempt // ключ — remote address
}

// New создаёт новый SSH Collectор.
func New(cfg *config.SSHConfig, eventBus *event.EventBus, sessMgr *session.Manager, log *slog.Logger) (*Collector, error) {
	var hostKey ssh.Signer
	if cfg.HostKeyPath != "" {
		keyData, err := os.ReadFile(cfg.HostKeyPath)
		if err != nil {
			return nil, fmt.Errorf("read host key: %w", err)
		}
		hostKey, err = ssh.ParsePrivateKey(keyData)
		if err != nil {
			return nil, fmt.Errorf("parse host key: %w", err)
		}
	} else {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, fmt.Errorf("generate host key: %w", err)
		}
		hostKey, err = ssh.NewSignerFromKey(key)
		if err != nil {
			return nil, fmt.Errorf("create host key signer: %w", err)
		}
	}

	serverCfg := &ssh.ServerConfig{
		ServerVersion: "SSH-2.0-DARKSCOPE",
	}
	serverCfg.AddHostKey(hostKey)

	serverCfg.PasswordCallback = func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
		return nil, nil // принимаем любой пароль — имитация успешного входа
	}

	return &Collector{
		cfg:       cfg,
		serverCfg: serverCfg,
		authMap:   make(map[string]*authAttempt),
		log:       log,
	}, nil
}

// Start запускает SSH слушатель.
func (c *Collector) Start(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	c.BaseCollector.SetContext(ctx, cancel)

	listener, err := net.Listen("tcp", c.cfg.ListenAddress)
	if err != nil {
		return fmt.Errorf("listen ssh: %w", err)
	}
	c.BaseCollector.Listener = listener

	c.BaseCollector.SetRunning(true)

	c.BaseCollector.GetWG().Add(1)
	go c.acceptLoop()

	c.log.Info("ssh collector started", "address", c.cfg.ListenAddress)
	return nil
}

// acceptLoop принимает входящие TCP-подключения.
func (c *Collector) acceptLoop() {
	defer c.BaseCollector.GetWG().Done()

	for {
		conn, err := c.BaseCollector.Listener.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			c.log.Error("ssh accept error", "error", err)
			return
		}

		if !c.BaseCollector.AcquireConn() {
			c.log.Warn("ssh connection limit reached, rejecting", "remote", conn.RemoteAddr())
			conn.Close()
			continue
		}

		c.BaseCollector.GetWG().Add(1)
		go c.handleConn(conn)
	}
}

// handleConn обрабатывает одно SSH-подключение.
func (c *Collector) handleConn(conn net.Conn) {
	defer c.BaseCollector.ReleaseConn()
	defer conn.Close()

	remoteAddr := conn.RemoteAddr().String()
	host, port, _ := net.SplitHostPort(remoteAddr)

	// Регистрируем попытку аутентификации для этого адреса.
	c.authMu.Lock()
	c.authMap[remoteAddr] = &authAttempt{result: "pending"}
	c.authMu.Unlock()
	defer func() {
		c.authMu.Lock()
		delete(c.authMap, remoteAddr)
		c.authMu.Unlock()
	}()

	// Сохраняем ссылку на Collector для использования в замыкании.
	collector := c

	// Устанавливаем колбэк, который записывает данные аутентификации.
	collector.serverCfg.PasswordCallback = func(sshConn ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
		ra := sshConn.RemoteAddr().String()
		collector.authMu.Lock()
		if a, ok := collector.authMap[ra]; ok {
			a.mu.Lock()
			a.user = sshConn.User()
			a.pass = string(pass)
			a.mu.Unlock()
		}
		collector.authMu.Unlock()
		return nil, nil
	}

	// Настраиваем таймаут на handshake и аутентификацию.
	conn.SetDeadline(time.Now().Add(c.cfg.AuthTimeout))
	defer conn.SetDeadline(time.Time{})

	// Выполняем SSH handshake (серверная сторона).
	sshConn, chans, reqs, err := ssh.NewServerConn(conn, c.serverCfg)
	if err != nil {
		if !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
			c.log.Warn("ssh handshake failed", "remote", remoteAddr, "error", err)
		}
		return
	}
	defer sshConn.Close()

	c.authMu.Lock()
	if a, ok := c.authMap[remoteAddr]; ok {
		a.mu.Lock()
		a.result = "success"
		a.mu.Unlock()
	}
	c.authMu.Unlock()

	sessionID := fmt.Sprintf("%x", sshConn.SessionID())

	// Создаём сессию в Session Manager.
	_, err = c.BaseCollector.Sessions.CreateSession(
		sessionID, host, "ssh", mustAtoi(port),
	)
	if err != nil {
		c.log.Error("ssh create session failed", "session_id", sessionID, "error", err)
		return
	}

	// Публикуем событие connect.
	c.publishEvent(sessionID, host, port, "ssh", "ssh", event.EventTypeConnect, nil, event.SeverityLow)

	// Публикуем событие login_attempt.
	c.BaseCollector.Sessions.RecordLoginAttempt(sessionID)
	c.publishEvent(sessionID, host, port, "ssh", "ssh", event.EventTypeLoginAttempt, map[string]interface{}{
		"method": "password",
		"result": "accepted",
	}, event.SeverityMedium)

	// Публикуем событие login_success (имитация успешной аутентификации).
	c.publishEvent(sessionID, host, port, "ssh", "ssh", event.EventTypeLoginSuccess, map[string]interface{}{
		"method": "password",
	}, event.SeverityHigh)

	// Обрабатываем глобальные запросы.
	go ssh.DiscardRequests(reqs)

	// Обрабатываем каналы.
	for newChannel := range chans {
		c.BaseCollector.GetWG().Add(1)
		go c.handleChannel(newChannel, sessionID, host, port)
	}

	// Ожидаем закрытия соединения.
	sshConn.Wait()

	// Завершаем сессию.
	c.BaseCollector.Sessions.EndSession(sessionID)
	c.publishEvent(sessionID, host, port, "ssh", "ssh", event.EventTypeDisconnect, nil, event.SeverityLow)
}

// handleChannel обрабатывает SSH-канал (session, exec и т.п.).
func (c *Collector) handleChannel(newChannel ssh.NewChannel, sessionID, host, port string) {
	defer c.BaseCollector.GetWG().Done()

	channelType := newChannel.ChannelType()
	c.log.Debug("ssh channel opened", "session_id", sessionID, "channel_type", channelType)

	// Отклоняем все каналы — не предоставляем реальный shell.
	newChannel.Reject(ssh.Prohibited, "channel not supported")

	// Регистрируем попытку открытия канала как событие.
	c.BaseCollector.Sessions.RecordCommand(sessionID)
	c.publishEvent(sessionID, host, port, "ssh", "ssh", event.EventTypeCommand, map[string]interface{}{
		"channel_type": channelType,
		"action":       "channel_rejected",
	}, event.SeverityLow)
}

// publishEvent публикует событие в Event Bus.
func (c *Collector) publishEvent(sessionID, sourceIP, sourcePort, protocol, service string, et event.EventType, payload interface{}, severity event.Severity) {
	ev := event.NewEvent(sessionID, sourceIP, "127.0.0.1", mustAtoi(sourcePort), 22, protocol, service, et, payload)
	ev.WithSeverity(severity).WithConfidence(0.9)
	if err := c.BaseCollector.EventBus.Publish(ev); err != nil {
		c.log.Warn("ssh publish event failed", "error", err)
	}
}

// Stop инициирует graceful shutdown SSH Collectора.
func (c *Collector) Stop(ctx context.Context) error {
	if !atomic.CompareAndSwapInt32(c.BaseCollector.GetRunning(), 1, 0) {
		return nil // уже остановлен
	}

	if cancel := c.BaseCollector.GetCancel(); cancel != nil {
		cancel()
	}

	if c.BaseCollector.Listener != nil {
		c.BaseCollector.Listener.Close()
	}

	done := make(chan struct{})
	go func() {
		c.BaseCollector.GetWG().Wait()
		close(done)
	}()

	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// mustAtoi конвертирует строку в int, возвращая 0 при ошибке.
func mustAtoi(s string) int {
	var n int
	for _, ch := range s {
		if ch < '0' || ch > '9' {
			return 0
		}
		n = n*10 + int(ch-'0')
	}
	return n
}

var (
	_ = context.Background
	_ = time.Second
)
