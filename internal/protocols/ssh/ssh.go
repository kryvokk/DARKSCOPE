package ssh

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/binary"
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

// authAttempt хранит данные попытки аутентификации для одного соединения.
// Пароль не сохраняется в событиях — фиксируются username и длина пароля.
type authAttempt struct {
	mu        sync.Mutex
	user      string
	passLen   int
	clientVer string
	result    string // "pending" | "accepted"
}

// Collector реализует SSH Honeypot.
type Collector struct {
	cfg         *config.SSHConfig
	serverCfg   *ssh.ServerConfig
	log         *slog.Logger
	authMu      sync.Mutex
	authMap     map[string]*authAttempt
	connsMu     sync.Mutex
	conns       map[net.Conn]struct{} // живые соединения для форс-закрытия на Stop
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

	// Honeypot принимает любую парольную аутентификацию: реальные креды
	// не проверяются, доступа к ОС не существует. Попытка фиксируется для
	// последующего анализа (username, длина пароля, версия клиента).
	c := &Collector{
		cfg:       cfg,
		authMap:   make(map[string]*authAttempt),
		conns:     make(map[net.Conn]struct{}),
		log:       log,
		publisher: publisher,
		sessions:  sessMgr,
	}

	serverCfg := &ssh.ServerConfig{
		ServerVersion: sanitizeServerVersion(cfg.Banner),
	}
	c.serverCfg = serverCfg
	serverCfg.AddHostKey(hostKey)

	serverCfg.PasswordCallback = func(cm ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
		ra := cm.RemoteAddr().String()
		c.authMu.Lock()
		c.authMap[ra] = &authAttempt{
			user:      cm.User(),
			passLen:   len(pass),
			clientVer: string(cm.ClientVersion()),
			result:    "accepted",
		}
		c.authMu.Unlock()
		return &ssh.Permissions{}, nil
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

func (c *Collector) destPort() int {
	if c.listener != nil {
		if addr, ok := c.listener.Addr().(*net.TCPAddr); ok {
			return addr.Port
		}
	}
	_, port, err := net.SplitHostPort(c.cfg.ListenAddress)
	if err != nil {
		return 0
	}
	return mustAtoi(port)
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
// Каждое принятое соединение регистрируется в c.conns до запуска обработчика:
// Stop всегда может их форс-закрыть. Регистрация под mutex с проверкой
// running исключает race: после старта остановки новые соединения не
// попадают в карту, а сразу закрываются.
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

		registered := false
		c.connsMu.Lock()
		if atomic.LoadInt32(&c.running) == 1 {
			c.conns[conn] = struct{}{}
			registered = true
		}
		c.connsMu.Unlock()

		if !registered {
			// Остановка началась между Accept и регистрацией.
			conn.Close()
			c.releaseConn()
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
	defer func() {
		c.connsMu.Lock()
		delete(c.conns, conn)
		c.connsMu.Unlock()
	}()

	remoteAddr := conn.RemoteAddr().String()
	host, port, _ := net.SplitHostPort(remoteAddr)

	// Запись из authMap удаляется при завершении соединения, чтобы карта
	// не росла неограниченно в течение жизни процесса.
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
			// Некорректное поведение клиента на уровне протокола —
			// отдельное событие; обычный EOF сканирования не фиксируем.
			c.publishEvent(ephemeralSessionID("ssh-handshake"), host, port, "ssh", "ssh",
				event.EventTypeProtocolError, map[string]interface{}{
					"stage":          "handshake",
					"reason":         err.Error(),
					"client_version": clientBanner(conn),
				}, event.SeverityLow)
		}
		return
	}
	defer sshConn.Close()

	// После успешного handshake ограничение AuthTimeout снято: сессия имеет
	// право на интерактивное использование; остановка контролируется через
	// Stop (форс-закрытие живых соединений).
	if err := conn.SetDeadline(time.Time{}); err != nil {
		c.log.Debug("ssh deadline reset failed", "remote", remoteAddr, "error", err)
	}

	// Данные последней попытки аутентификации этого соединения,
	// записанные PasswordCallback при handshake.
	var att *authAttempt
	c.authMu.Lock()
	if a, ok := c.authMap[remoteAddr]; ok {
		att = a
	}
	c.authMu.Unlock()

	sessionID := fmt.Sprintf("%x", sshConn.SessionID())

	_, err = c.sessions.CreateSession(
		sessionID, host, "ssh", mustAtoi(port),
	)
	if err != nil {
		c.log.Error("ssh create session failed", "session_id", sessionID, "error", err)
		return
	}

	// Событие подключения; версии клиента и сервера — в метаданных.
	c.publishEvent(sessionID, host, port, "ssh", "ssh", event.EventTypeConnect, nil, event.SeverityLow,
		func(e *event.Event) {
			e.WithMetadata("client_version", string(sshConn.ClientVersion())).
				WithMetadata("server_version", string(sshConn.ServerVersion()))
		})

	// Попытка аутентификации: honeypot принимает любой пароль, реальные
	// креды не проверяются, пароль в событие не пишется (только длина).
	user := ""
	passLen := 0
	if att != nil {
		att.mu.Lock()
		user, passLen = att.user, att.passLen
		att.mu.Unlock()
	}

	c.sessions.RecordLoginAttempt(sessionID)
	c.publishEvent(sessionID, host, port, "ssh", "ssh", event.EventTypeLoginAttempt, map[string]interface{}{
		"method":          "password",
		"user":            user,
		"password":        "***",
		"password_length": passLen,
		"result":          "accepted",
	}, event.SeverityMedium)

	c.publishEvent(sessionID, host, port, "ssh", "ssh", event.EventTypeLoginSuccess, map[string]interface{}{
		"method": "password",
		"user":   user,
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

	// Реальный shell не предоставляется: попытка открытия канала
	// фиксируется и отклоняется. Каналы не выполняют команды хоста.
	newChannel.Reject(ssh.Prohibited, "channel not supported")

	c.sessions.RecordCommand(sessionID)
	c.publishEvent(sessionID, host, port, "ssh", "ssh", event.EventTypeCommand, map[string]interface{}{
		"channel_type": channelType,
		"action":       "channel_rejected",
	}, event.SeverityLow, nil)
}

// publishOption — необязательная донастройка события перед публикацией.
type publishOption func(*event.Event)

// publishEvent формирует нормализованное событие и публикует его через publisher.
func (c *Collector) publishEvent(sessionID, sourceIP, sourcePort, protocol, service string,
	et event.EventType, payload interface{}, severity event.Severity, opts ...publishOption) {
	ev := event.NewEvent(sessionID, sourceIP, "127.0.0.1", mustAtoi(sourcePort), c.destPort(), protocol, service, et, payload)
	ev.WithSeverity(severity).WithConfidence(0.9)
	for _, opt := range opts {
		opt(ev)
	}
	c.publish(ev, string(et))
}

// publish отправляет готовое событие; ошибки публикации не прерывают
// обработку соединения (ошибки шины не должны валить honeypot).
func (c *Collector) publish(ev *event.Event, et string) {
	if err := c.publisher.Publish(ev); err != nil {
		c.log.Warn("ssh publish event failed", "event_type", et, "error", err)
	}
}

// ephemeralSessionID генерирует временный ID для событий вне сессии
// (например, отказ handshake до установления Session).
func ephemeralSessionID(prefix string) string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		n := ephemIDSeq.Add(1)
		binary.BigEndian.PutUint64(b[:], n)
	}
	return fmt.Sprintf("%s-%x", prefix, b)
}

var ephemIDSeq atomic.Uint64

// clientBanner пытается получить версию клиента из необработанного потока
// до handshake (первая строка, ограниченная по длине) — для диагностики.
func clientBanner(conn net.Conn) string {
	conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	buf := make([]byte, 255)
	n, err := conn.Read(buf)
	_ = conn.SetReadDeadline(time.Time{})
	if err != nil && n == 0 {
		return ""
	}
	line := string(buf[:n])
	if i := strings.IndexAny(line, "\r\n"); i >= 0 {
		line = line[:i]
	}
	if len(line) > 128 {
		line = line[:128]
	}
	return line
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

	// Форс-закрытие живых соединений: разблокирует sshConn.Wait()
	// и гарантирует завершение обработчиков за ограниченное время.
	c.connsMu.Lock()
	for conn := range c.conns {
		_ = conn.Close()
	}
	c.connsMu.Unlock()

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
