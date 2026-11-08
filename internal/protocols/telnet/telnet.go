package telnet

import (
	"context"
	"bufio"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"darkscope/honeypot/internal/config"
	"darkscope/honeypot/internal/event"
	"darkscope/honeypot/internal/protocols"
	"darkscope/honeypot/internal/session"
)

// Collector реализует Telnet Honeypot.
type Collector struct {
	protocols.BaseCollector
	cfg     *config.TelnetConfig
	listener net.Listener
	log     *slog.Logger
}

// New создаёт новый Telnet Collectор.
func New(cfg *config.TelnetConfig, eventBus *event.EventBus, sessMgr *session.Manager, log *slog.Logger) (*Collector, error) {
	return &Collector{
		cfg:  cfg,
		log:  log,
	}, nil
}

// Start запускает Telnet слушатель.
func (c *Collector) Start(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	c.BaseCollector.SetContext(ctx, cancel)

	listener, err := net.Listen("tcp", c.cfg.ListenAddress)
	if err != nil {
		return fmt.Errorf("listen telnet: %w", err)
	}
	c.BaseCollector.Listener = listener
	c.listener = listener

	c.BaseCollector.SetRunning(true)

	// Ограничиваем количество одновременных соединений.
	if c.cfg.MaxConnections > 0 {
		c.BaseCollector.SetConnLimiter(make(chan struct{}, c.cfg.MaxConnections))
	}

	c.BaseCollector.GetWG().Add(1)
	go c.acceptLoop()

	c.log.Info("telnet collector started", "address", c.cfg.ListenAddress)
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
			c.log.Error("telnet accept error", "error", err)
			return
		}

		if !c.BaseCollector.AcquireConn() {
			c.log.Warn("telnet connection limit reached, rejecting", "remote", conn.RemoteAddr())
			conn.Close()
			continue
		}

		c.BaseCollector.GetWG().Add(1)
		go c.handleConn(conn)
	}
}

// handleConn обрабатывает одно Telnet-подключение.
func (c *Collector) handleConn(conn net.Conn) {
	defer c.BaseCollector.ReleaseConn()
	defer conn.Close()

	remoteAddr := conn.RemoteAddr().String()
	host, port, _ := net.SplitHostPort(remoteAddr)

	// Генерируем уникальный ID сессии.
	sessionID := fmt.Sprintf("%x", time.Now().UnixNano())

	// Создаём сессию в Session Manager.
	_, err := c.BaseCollector.Sessions.CreateSession(
		sessionID, host, "telnet", mustAtoi(port),
	)
	if err != nil {
		c.log.Error("telnet create session failed", "session_id", sessionID, "error", err)
		return
	}

	// Публикуем событие connect.
	c.publishEvent(sessionID, host, port, "telnet", "telnet", event.EventTypeConnect, nil, event.SeverityLow)

	// Настраиваем таймауты.
	conn.SetDeadline(time.Now().Add(c.cfg.LoginTimeout))
	defer conn.SetDeadline(time.Time{})

	// Отправляем баннер.
	banner := c.cfg.Banner
	if banner == "" {
		banner = "DARKSCOPE Telnet Service"
	}
	fmt.Fprintf(conn, "%s\r\n", banner)

	reader := bufio.NewReader(conn)

	// Эмуляция login prompt.
	fmt.Fprint(conn, "login: ")
	username, err := readLine(reader)
	if err != nil {
		c.log.Warn("telnet read username failed", "session_id", sessionID, "error", err)
		c.BaseCollector.Sessions.EndSession(sessionID)
		c.publishEvent(sessionID, host, port, "telnet", "telnet", event.EventTypeDisconnect, nil, event.SeverityLow)
		return
	}
	username = strings.TrimSpace(username)

	// Регистрируем попытку входа.
	c.BaseCollector.Sessions.RecordLoginAttempt(sessionID)
	c.publishEvent(sessionID, host, port, "telnet", "telnet", event.EventTypeLoginAttempt, map[string]interface{}{
		"username": username,
		"result":   "pending",
	}, event.SeverityMedium)

	// Эмуляция password prompt.
	fmt.Fprint(conn, "Password: ")
	password, err := readLine(reader)
	if err != nil {
		c.log.Warn("telnet read password failed", "session_id", sessionID, "error", err)
		c.BaseCollector.Sessions.EndSession(sessionID)
		c.publishEvent(sessionID, host, port, "telnet", "telnet", event.EventTypeDisconnect, nil, event.SeverityLow)
		return
	}
	password = strings.TrimSpace(password)

	// Обновляем событие login_attempt с результатом.
	c.publishEvent(sessionID, host, port, "telnet", "telnet", event.EventTypeLoginAttempt, map[string]interface{}{
		"username": username,
		"password": "***",
		"result":   "accepted",
	}, event.SeverityMedium)

	// Имитация успешного входа.
	fmt.Fprintf(conn, "\r\nWelcome, %s. Type 'help' for available commands.\r\n", username)
	c.publishEvent(sessionID, host, port, "telnet", "telnet", event.EventTypeLoginSuccess, map[string]interface{}{
		"username": username,
	}, event.SeverityHigh)

	// Основной цикл чтения команд.
	for {
		conn.SetDeadline(time.Now().Add(c.cfg.IdleTimeout))
		fmt.Fprint(conn, "> ")
		line, err := readLine(reader)
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				c.log.Debug("telnet client disconnected", "session_id", sessionID)
			} else {
				c.log.Warn("telnet read error", "session_id", sessionID, "error", err)
			}
			break
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// Регистрируем команду как событие.
		c.BaseCollector.Sessions.RecordCommand(sessionID)
		c.publishEvent(sessionID, host, port, "telnet", "telnet", event.EventTypeCommand, map[string]interface{}{
			"command": line,
		}, event.SeverityLow)

		// Обрабатываем встроенные команды (имитация).
		response := handleTelnetCommand(line)
		fmt.Fprintf(conn, "%s\r\n", response)

		if line == "exit" || line == "quit" || line == "logout" {
			break
		}
	}

	// Завершаем сессию.
	c.BaseCollector.Sessions.EndSession(sessionID)
	c.publishEvent(sessionID, host, port, "telnet", "telnet", event.EventTypeDisconnect, nil, event.SeverityLow)
}

// readLine читает одну строку от клиента.
func readLine(reader *bufio.Reader) (string, error) {
	line, err := reader.ReadString('\n')
	if err != nil {
		return "", err
	}
	return line, nil
}

// handleTelnetCommand обрабатывает встроенные команды telnet (имитация).
func handleTelnetCommand(cmd string) string {
	switch strings.ToLower(cmd) {
	case "help":
		return "Available commands: whoami, id, uname, hostname, pwd, ls, ps, exit"
	case "whoami":
		return "fakeuser"
	case "id":
		return "uid=1000(fakeuser) gid=1000(fakeuser) groups=1000(fakeuser)"
	case "uname":
		return "Linux darkscope 5.10.0-fake #1 SMP x86_64 GNU/Linux"
	case "hostname":
		return "darkscope"
	case "pwd":
		return "/home/fakeuser"
	case "ls":
		return "bin  boot  dev  etc  home  lib  lib64  media  mnt  opt  proc  root  run  sbin  srv  sys  tmp  usr  var"
	case "ps":
		return "  PID TTY          TIME CMD\n    1 ?        00:00:00 init\n    2 ?        00:00:00 kthreadd"
	case "exit", "quit", "logout":
		return "Goodbye."
	default:
		return fmt.Sprintf("%s: command not found", cmd)
	}
}

// Stop инициирует graceful shutdown Telnet Collectора.
func (c *Collector) Stop(ctx context.Context) error {
	if !atomic.CompareAndSwapInt32(c.BaseCollector.GetRunning(), 1, 0) {
		return nil // уже остановлен
	}

	if cancel := c.BaseCollector.GetCancel(); cancel != nil {
		cancel()
	}

	if c.listener != nil {
		c.listener.Close()
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

// mustAtoi конвертирует строку в int.
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

// publishEvent публикует событие в Event Bus.
func (c *Collector) publishEvent(sessionID, sourceIP, sourcePort, protocol, service string, et event.EventType, payload interface{}, severity event.Severity) {
	ev := event.NewEvent(sessionID, sourceIP, "127.0.0.1", mustAtoi(sourcePort), 23, protocol, service, et, payload)
	ev.WithSeverity(severity).WithConfidence(0.9)
	if err := c.BaseCollector.EventBus.Publish(ev); err != nil {
		c.log.Warn("telnet publish event failed", "error", err)
	}
}

var (
	_ = context.Background
	_ = sync.WaitGroup{}
	_ = time.Second
)
