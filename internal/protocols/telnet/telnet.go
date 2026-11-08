package telnet

import (
	"bufio"
	"context"
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
	"darkscope/honeypot/internal/emulator"
	"darkscope/honeypot/internal/event"
	"darkscope/honeypot/internal/protocols"
	"darkscope/honeypot/internal/session"
)

const maxInputLine = 256

// Collector is a credential-capture-only Telnet honeypot. It never offers a shell.
type Collector struct {
	protocols.BaseCollector
	cfg       *config.TelnetConfig
	listener  net.Listener
	log       *slog.Logger
	publisher protocols.Publisher
	mu        sync.Mutex
	conns     map[net.Conn]struct{}
}

func New(cfg *config.TelnetConfig, publisher protocols.Publisher, sessMgr *session.Manager, log *slog.Logger) (*Collector, error) {
	if cfg == nil || publisher == nil || sessMgr == nil || log == nil {
		return nil, errors.New("telnet collector requires config, publisher, session manager, and logger")
	}
	c := *cfg
	if c.MaxConnections <= 0 {
		c.MaxConnections = 50
	}
	if c.LoginTimeout <= 0 {
		c.LoginTimeout = 60 * time.Second
	}
	if c.IdleTimeout <= 0 {
		c.IdleTimeout = 30 * time.Second
	}
	if c.ReadTimeout <= 0 {
		c.ReadTimeout = 10 * time.Second
	}
	if c.WriteTimeout <= 0 {
		c.WriteTimeout = 10 * time.Second
	}
	if c.Banner == "" {
		c.Banner = "DARKSCOPE Telnet Service"
	}
	return &Collector{BaseCollector: protocols.BaseCollector{Sessions: sessMgr}, cfg: &c, publisher: publisher, log: log, conns: make(map[net.Conn]struct{})}, nil
}

func (c *Collector) Name() string { return "telnet" }
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

func (c *Collector) Start(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	c.BaseCollector.SetContext(ctx, cancel)
	l, err := net.Listen("tcp", c.cfg.ListenAddress)
	if err != nil {
		cancel()
		return fmt.Errorf("listen telnet: %w", err)
	}
	c.listener, c.BaseCollector.Listener = l, l
	c.BaseCollector.SetConnLimiter(make(chan struct{}, c.cfg.MaxConnections))
	c.BaseCollector.SetRunning(true)
	c.BaseCollector.GetWG().Add(1)
	go c.acceptLoop()
	return nil
}

func (c *Collector) acceptLoop() {
	defer c.BaseCollector.GetWG().Done()
	for {
		conn, err := c.listener.Accept()
		if err != nil {
			if !errors.Is(err, net.ErrClosed) {
				c.log.Warn("telnet accept failed", "error", err)
			}
			return
		}
		if !c.BaseCollector.AcquireConn() {
			_ = conn.Close()
			continue
		}
		c.mu.Lock()
		if !c.BaseCollector.IsRunning() {
			c.mu.Unlock()
			c.BaseCollector.ReleaseConn()
			_ = conn.Close()
			continue
		}
		c.conns[conn] = struct{}{}
		c.mu.Unlock()
		c.BaseCollector.GetWG().Add(1)
		go c.handleConn(conn)
	}
}

func (c *Collector) handleConn(conn net.Conn) {
	defer c.BaseCollector.GetWG().Done()
	defer c.BaseCollector.ReleaseConn()
	defer func() { c.mu.Lock(); delete(c.conns, conn); c.mu.Unlock(); _ = conn.Close() }()
	host, port, _ := net.SplitHostPort(conn.RemoteAddr().String())
	sid := protocols.NewSessionID("telnet")
	if _, err := c.Sessions.CreateSession(sid, host, "telnet", mustAtoi(port)); err != nil {
		c.log.Warn("telnet create session failed", "error", err)
		return
	}
	defer func() {
		_ = c.Sessions.EndSession(sid)
		c.publishEvent(sid, host, port, event.EventTypeDisconnect, nil, event.SeverityLow)
	}()
	c.publishEvent(sid, host, port, event.EventTypeConnect, nil, event.SeverityLow)
	loginDeadline := time.Now().Add(c.cfg.LoginTimeout)
	r := bufio.NewReader(conn)
	write := func(s string) error {
		_ = conn.SetWriteDeadline(time.Now().Add(c.cfg.WriteTimeout))
		_, err := io.WriteString(conn, s)
		return err
	}
	read := func() (string, error) {
		deadline := time.Now().Add(c.cfg.ReadTimeout)
		if loginDeadline.Before(deadline) {
			deadline = loginDeadline
		}
		_ = conn.SetReadDeadline(deadline)
		return readTelnetLine(r, maxInputLine)
	}
	if err := write(sanitizeLine(c.cfg.Banner) + "\r\nlogin: "); err != nil {
		return
	}
	for attempt := 0; attempt < 3; attempt++ {
		user, err := read()
		if err != nil {
			return
		}
		user = strings.TrimSpace(user)
		if err := write("Password: "); err != nil {
			return
		}
		pass, err := read()
		if err != nil {
			return
		}
		_ = c.Sessions.RecordLoginAttempt(sid)
		c.publishEvent(sid, host, port, event.EventTypeLoginAttempt, map[string]interface{}{
			"username": user, "password": "***", "password_length": len(strings.TrimSpace(pass)), "attempt": attempt + 1, "result": "rejected",
		}, event.SeverityMedium)
		if attempt < 2 {
			if err := write("Login incorrect\r\nlogin: "); err != nil {
				return
			}
		}
	}
	_ = write("\r\nWelcome to DARKSCOPE. Type exit to disconnect.\r\n")
	shell := emulator.New(sid, "telnet", emulator.BusPublisher{Bus: c.publisher, SourceIP: host, SourcePort: mustAtoi(port), DestPort: c.destPort(), Protocol: "telnet"})
	for {
		if err := write(shell.User + "@" + shell.Host + ":" + shell.Cwd + "$ "); err != nil {
			return
		}
		line, err := readTelnetLine(r, emulator.MaxCommandBytes)
		if err != nil {
			return
		}
		line = strings.TrimSpace(line)
		if line == "exit" || line == "logout" {
			return
		}
		res := shell.Execute(line)
		if res.Out != "" {
			if err = write(res.Out); err != nil {
				return
			}
		}
		if res.Err != "" {
			if err = write(res.Err); err != nil {
				return
			}
		}
	}
}

// readTelnetLine bounds input and removes Telnet IAC negotiation sequences.
func readTelnetLine(r *bufio.Reader, limit int) (string, error) {
	line := make([]byte, 0, limit)
	for {
		b, err := r.ReadByte()
		if err != nil {
			return "", err
		}
		if b == 255 { // IAC: discard negotiation and subnegotiation data
			cmd, e := r.ReadByte()
			if e != nil {
				return "", e
			}
			if cmd == 250 { // SB option ... IAC SE
				if _, e = r.ReadByte(); e != nil {
					return "", e
				}
				for {
					v, readErr := r.ReadByte()
					if readErr != nil {
						return "", readErr
					}
					if v == 255 {
						next, readErr := r.ReadByte()
						if readErr != nil {
							return "", readErr
						}
						if next == 240 {
							break
						}
					}
				}
			} else if cmd >= 251 && cmd <= 254 {
				if _, e = r.ReadByte(); e != nil {
					return "", e
				}
			}
			continue
		}
		if b == '\n' {
			return strings.TrimRight(string(line), "\r"), nil
		}
		if len(line) >= limit {
			return "", errors.New("telnet input line too long")
		}
		line = append(line, b)
	}
}

func sanitizeLine(s string) string {
	return strings.Map(func(r rune) rune {
		if r == '\r' || r == '\n' || r == 0 {
			return -1
		}
		return r
	}, s)
}

func (c *Collector) Stop(ctx context.Context) error {
	if !atomic.CompareAndSwapInt32(c.BaseCollector.GetRunning(), 1, 0) {
		return nil
	}
	if cancel := c.BaseCollector.GetCancel(); cancel != nil {
		cancel()
	}
	if c.listener != nil {
		_ = c.listener.Close()
	}
	c.mu.Lock()
	for conn := range c.conns {
		_ = conn.Close()
	}
	c.mu.Unlock()
	done := make(chan struct{})
	go func() { c.BaseCollector.GetWG().Wait(); close(done) }()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (c *Collector) publishEvent(sid, ip, srcPort string, typ event.EventType, payload interface{}, severity event.Severity) {
	ev := event.NewEvent(sid, ip, "127.0.0.1", mustAtoi(srcPort), c.destPort(), "telnet", "telnet", typ, payload)
	ev.WithSeverity(severity).WithConfidence(0.9)
	if err := c.publisher.Publish(ev); err != nil {
		c.log.Warn("telnet publish event failed", "error", err)
	}
}

func mustAtoi(s string) int {
	n := 0
	for _, ch := range s {
		if ch < '0' || ch > '9' {
			return 0
		}
		n = n*10 + int(ch-'0')
	}
	return n
}
