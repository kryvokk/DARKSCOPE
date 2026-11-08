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
	"strings"
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
	cfg         *config.SSHConfig
	serverCfg   *ssh.ServerConfig
	log         *slog.Logger
	authMu      sync.Mutex
	authMap     map[string]*authAttempt
	listener    net.Listener
	ctx         context.Context
	cancel      context.CancelFunc
	running     int32
	wg          sync.WaitGroup
	connLimiter chan struct{}
	publisher   protocols.Publisher
	sessions    *session.Manager
}

// New создаёт новый SSH Collectор.
func New(cfg *config.SSHConfig, publisher protocols.Publisher, sessMgr *session.Manager, log *slog.Logger) (*Collector, error) {
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
		ServerVersion: sanitizeServerVersion(cfg.Banner),
		PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			return &ssh.Permissions{}, nil
		},
	}
	serverCfg.AddHostKey(hostKey)

	c := &Collector{
		cfg:         cfg,
		serverCfg:   serverCfg,
		authMap:     make(map[string]*authAttempt),
		log:         log,
		publisher:   publisher,
		sessions:    sessMgr,
	}
	if cfg.MaxConnections > 0 {
		c.connLimiter = make(chan struct{}, cfg.MaxConnections)
	}
	return c, nil
}

// Name возвращает имя протокола.
func (c *Collector) Name() string {
	return "ssh"
}

// ListenAddr возвращает адрес прослушивания.
func (c *Collector) ListenAddr() string {
	if c.listener != nil {
		return c.listener.Addr().String()
	}
	return c.cfg.ListenAddress
}

// Start запускает SSH слушатель.
func (c *Collector) Start(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	c.ctx = ctx
	c.cancel = cancel

	listener, err := net.Listen("tcp", c.cfg.ListenAddress)
	if err != nil {
		return fmt.Errorf("listen ssh: %w", err)
	}
	c.listener = listener

	atomic.StoreInt32(&c.running, 1)

	c.wg.Add(1)
	go c.acceptLoop()

	c.log.Info("ssh collector started", "address", c.cfg.ListenAddress)
	return nil
}

// acceptLoop принимает входящие TCP-подключения.
func (c *Collector) acceptLoop() {
	defer c.wg.Done()

	for {
		conn, err := c.listener.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			c.log.Error("ssh accept error", "error", err)
			return
		}

		if !c.acquireConn() {
			c.log.Warn("ssh connection limit reached, rejecting", "remote", conn.RemoteAddr())
			conn.Close()
			continue
		}

		c.wg.Add(1)
		go c.handleConn(conn)
	}
}

func (c *Collector) acquireConn() bool {
	if c.connLimiter == nil {
		return true
	}
	select {
	case c.connLimiter <- struct{}{}:
		return true
	default:
		return false
	}
}

func (c *Collector) releaseConn() {
	if c.connLimiter == nil {
		return
	}
	select {
	case <-c.connLimiter:
	default:
	}
}

func (c *Collector) handleConn(conn net.Conn) {
	defer c.wg.Done()
	defer c.releaseConn()
	defer conn.Close()

	remoteAddr := conn.RemoteAddr().String()
	host, port, _ := net.SplitHostPort(remoteAddr)

	c.authMu.Lock()
	c.authMap[remoteAddr] = &authAttempt{result: "pending"}
	c.authMu.Unlock()
	defer func() {
		c.authMu.Lock()
		delete(c.authMap, remoteAddr)
		c.authMu.Unlock()
	}()

	conn.SetDeadline(time.Now().Add(c.cfg.AuthTimeout))
	defer conn.SetDeadline(time.Time{})

	sshConn, chans, reqs, err := ssh.NewServerConn(conn, c.serverCfg)
	if err != nil {
		if !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
			c.log.Warn("ssh handshake failed", "remote", remoteAddr, "error", err)
		}
		return
	}
	defer sshConn.Close()

	sessionID := fmt.Sprintf("%x", sshConn.SessionID())

	_, err = c.sessions.CreateSession(
		sessionID, host, "ssh", mustAtoi(port),
	)
	if err != nil {
		c.log.Error("ssh create session failed", "session_id", sessionID, "error", err)
		return
	}

	c.publishEvent(sessionID, host, port, "ssh", "ssh", event.EventTypeConnect, nil, event.SeverityLow)

	c.sessions.RecordLoginAttempt(sessionID)
	c.publishEvent(sessionID, host, port, "ssh", "ssh", event.EventTypeLoginAttempt, map[string]interface{}{
		"method": "password",
		"result": "accepted",
	}, event.SeverityMedium)

	c.publishEvent(sessionID, host, port, "ssh", "ssh", event.EventTypeLoginSuccess, map[string]interface{}{
		"method": "password",
	}, event.SeverityHigh)

	go ssh.DiscardRequests(reqs)

	for newChannel := range chans {
		c.wg.Add(1)
		go c.handleChannel(newChannel, sessionID, host, port)
	}

	sshConn.Wait()

	c.sessions.EndSession(sessionID)
	c.publishEvent(sessionID, host, port, "ssh", "ssh", event.EventTypeDisconnect, nil, event.SeverityLow)
}

func (c *Collector) handleChannel(newChannel ssh.NewChannel, sessionID, host, port string) {
	defer c.wg.Done()

	channelType := newChannel.ChannelType()
	c.log.Debug("ssh channel opened", "session_id", sessionID, "channel_type", channelType)

	newChannel.Reject(ssh.Prohibited, "channel not supported")

	c.sessions.RecordCommand(sessionID)
	c.publishEvent(sessionID, host, port, "ssh", "ssh", event.EventTypeCommand, map[string]interface{}{
		"channel_type": channelType,
		"action":       "channel_rejected",
	}, event.SeverityLow)
}

func (c *Collector) publishEvent(sessionID, sourceIP, sourcePort, protocol, service string, et event.EventType, payload interface{}, severity event.Severity) {
	ev := event.NewEvent(sessionID, sourceIP, "127.0.0.1", mustAtoi(sourcePort), 22, protocol, service, et, payload)
	ev.WithSeverity(severity).WithConfidence(0.9)
	if err := c.publisher.Publish(ev); err != nil {
		c.log.Warn("ssh publish event failed", "error", err)
	}
}

func (c *Collector) IsRunning() bool {
	return atomic.LoadInt32(&c.running) == 1
}

func (c *Collector) Stop(ctx context.Context) error {
	if !atomic.CompareAndSwapInt32(&c.running, 1, 0) {
		return nil
	}

	if c.cancel != nil {
		c.cancel()
	}

	if c.listener != nil {
		c.listener.Close()
	}

	done := make(chan struct{})
	go func() {
		c.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// sanitizeServerVersion валидирует настроенный баннер SSH:
// версия сервера обязана начинаться с "SSH-2.0-" или "SSH-1.99-",
// не содержать CR/LF и не превышать разумную длину; иначе — безопасное значение.
func sanitizeServerVersion(banner string) string {
	const fallback = "SSH-2.0-DARKSCOPE"
	switch {
	case banner == "":
		return fallback
	case !strings.HasPrefix(banner, "SSH-2.0-") && !strings.HasPrefix(banner, "SSH-1.99-"):
		return fallback
	case strings.ContainsAny(banner, "\r\n\x00"):
		return fallback
	case len(banner) > 64:
		return fallback
	}
	return banner
}

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
