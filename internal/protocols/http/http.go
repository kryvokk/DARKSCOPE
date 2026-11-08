package http

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"darkscope/honeypot/internal/config"
	"darkscope/honeypot/internal/event"
	"darkscope/honeypot/internal/protocols"
	"darkscope/honeypot/internal/session"
)

// honeypotEndpoints — типовые точки сбора данных (ТЗ Phase 2 разд. 3).
var honeypotEndpoints = []string{
	"/",
	"/login",
	"/admin",
	"/wp-login.php",
	"/phpmyadmin",
	"/api/",
	"/robots.txt",
}

// isHoneypotEndpoint проверяет, является ли путь одной из honeypot-точек.
func isHoneypotEndpoint(path string) bool {
	for _, ep := range honeypotEndpoints {
		if path == "/" || (ep != "/" && strings.HasPrefix(path, ep)) {
			return true
		}
	}
	return false
}

// sessionIDKey — ключ контекста запроса, в котором ConnContext кладёт ID сессии.
type sessionIDKey struct{}

// tokenBucketCap — предельные размеры сохраняемых заголовков (анти-DoS).
const (
	maxStoredHeaders = 24
	maxHeaderKeyLen  = 64
	maxHeaderValLen  = 512
)

// Collector реализует HTTP Honeypot.
type Collector struct {
	protocols.BaseCollector
	cfg       *config.HTTPConfig
	server    *http.Server
	listener  net.Listener
	log       *slog.Logger
	publisher protocols.Publisher

	connsMu sync.Mutex
	conns   map[net.Conn]*connState // регистр живых соединений
}

// connState — состояние сессии одного соединения.
type connState struct {
	sessionID  string
	sourceIP   string
	sourcePort int
}

// New создаёт новый HTTP Collector.
func New(cfg *config.HTTPConfig, publisher protocols.Publisher, sessMgr *session.Manager, log *slog.Logger) (*Collector, error) {
	c := &Collector{
		BaseCollector: protocols.BaseCollector{Sessions: sessMgr},
		log:           log,
		publisher:     publisher,
		conns:         make(map[net.Conn]*connState),
	}

	// Безопасные значения по умолчанию: нулевые таймауты в net/http
	// означают «без ограничения», что недопустимо для honeypot.
	c.cfg = &config.HTTPConfig{
		Enabled:        cfg.Enabled,
		ListenAddress:  cfg.ListenAddress,
		MaxConnections: cfg.MaxConnections,
		ReadTimeout:    orDefault(cfg.ReadTimeout, 15*time.Second),
		WriteTimeout:   orDefault(cfg.WriteTimeout, 15*time.Second),
		IdleTimeout:    orDefault(cfg.IdleTimeout, 60*time.Second),
		MaxBodySize:    orDefault64(cfg.MaxBodySize, int64(1)<<20),
		MaxHeaders:     orDefaultInt(cfg.MaxHeaders, maxStoredHeaders),
		TLSCertFile:    cfg.TLSCertFile,
		TLSKeyFile:     cfg.TLSKeyFile,
	}

	server := &http.Server{
		Handler:           &handler{collector: c},
		ReadHeaderTimeout: c.cfg.ReadTimeout,
		ReadTimeout:       c.cfg.ReadTimeout,
		WriteTimeout:      c.cfg.WriteTimeout,
		IdleTimeout:       c.cfg.IdleTimeout,
		MaxHeaderBytes:    1 << 20, // 1 MiB — верхняя граница протокола
		// HTTP/2 отключён: объемлющая мера для детерминированной работы
		// ConnContext/ConnState и постоянных HTTP/1.1-сессий.
		TLSNextProto: map[string]func(*http.Server, *tls.Conn, http.Handler){},
	}
	c.server = server

	return c, nil
}

// Name возвращает имя протокола.
func (c *Collector) Name() string { return "http" }

// ListenAddr возвращает адрес прослушивания.
func (c *Collector) ListenAddr() string { return c.cfg.ListenAddress }

// destPort возвращает фактический порт прослушивания (0 до старта).
func (c *Collector) destPort() int {
	if c.listener == nil {
		return 0
	}
	if addr, ok := c.listener.Addr().(*net.TCPAddr); ok {
		return addr.Port
	}
	return 0
}

// Start запускает HTTP-сервер.
func (c *Collector) Start(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	c.BaseCollector.SetContext(ctx, cancel)

	listener, err := net.Listen("tcp", c.cfg.ListenAddress)
	if err != nil {
		cancel() // не оставляем висеть созданный контекст
		return fmt.Errorf("listen http: %w", err)
	}

	// Ограничение одновременных соединений на уровне слушателя.
	listener = protocols.NewLimitedListener(listener, c.cfg.MaxConnections)

	// Опциональный TLS: включается только при явно настроенных
	// cert/key; безопасность — TLS 1.2+, HTTP/2 выключен.
	switch {
	case c.cfg.TLSCertFile != "" && c.cfg.TLSKeyFile != "":
		cert, certErr := tls.LoadX509KeyPair(c.cfg.TLSCertFile, c.cfg.TLSKeyFile)
		if certErr != nil {
			listener.Close()
			cancel()
			return fmt.Errorf("load tls keypair: %w", certErr)
		}
		listener = tls.NewListener(listener, &tls.Config{
			MinVersion:   tls.VersionTLS12,
			Certificates: []tls.Certificate{cert},
		})
	case c.cfg.TLSCertFile != "" || c.cfg.TLSKeyFile != "":
		listener.Close()
		cancel()
		return fmt.Errorf("tls требует одновременно tls_cert_file и tls_key_file")
	}

	c.listener = listener
	c.BaseCollector.Listener = listener
	c.BaseCollector.SetRunning(true)

	c.server.ConnContext = c.onNewConn
	c.server.ConnState = c.onConnState

	c.BaseCollector.GetWG().Add(1)
	go func() {
		defer c.BaseCollector.GetWG().Done()
		if err := c.server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			c.log.Error("http server error", "error", err)
		}
	}()

	c.log.Info("http collector started", "address", c.cfg.ListenAddress)
	return nil
}

// onNewConn вызывается один раз на каждое соединение до первого запроса:
// создаёт Session «одно подключение = одна сессия» (ТЗ Phase 2 разд. 6),
// публикует connect и кладёт ID сессии в контекст всех запросов соединения.
func (c *Collector) onNewConn(ctx context.Context, conn net.Conn) context.Context {
	remote := conn.RemoteAddr()
	host, port, _ := net.SplitHostPort(remote.String())

	sess := &connState{
		sessionID:  protocols.NewSessionID("http"),
		sourceIP:   host,
		sourcePort: mustAtoi(port),
	}
	if _, err := c.BaseCollector.Sessions.CreateSession(sess.sessionID, sess.sourceIP, "http", sess.sourcePort); err != nil {
		c.log.Warn("http create session failed", "session_id", sess.sessionID, "error", err)
		return ctx // обработчики получат пустой ID и не соберут данные
	}

	c.connsMu.Lock()
	c.conns[conn] = sess
	c.connsMu.Unlock()

	c.publishEvent(sess.sessionID, sess.sourceIP, port, "http", "http", event.EventTypeConnect, nil, event.SeverityLow)
	return context.WithValue(ctx, sessionIDKey{}, sess.sessionID)
}

// onConnState отслеживает закрытие/захват соединения и завершает сессию.
func (c *Collector) onConnState(conn net.Conn, cs http.ConnState) {
	if cs != http.StateClosed && cs != http.StateHijacked {
		return
	}
	c.connsMu.Lock()
	sess, ok := c.conns[conn]
	delete(c.conns, conn)
	c.connsMu.Unlock()
	if !ok {
		return
	}

	if err := c.BaseCollector.Sessions.EndSession(sess.sessionID); err != nil {
		c.log.Debug("http end session failed", "session_id", sess.sessionID, "error", err)
	}
	c.publishEvent(sess.sessionID, sess.sourceIP, fmt.Sprintf("%d", sess.sourcePort), "http", "http",
		event.EventTypeDisconnect, nil, event.SeverityLow)
}

// handler обрабатывает HTTP-запросы.
type handler struct {
	collector *Collector
}

func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	c := h.collector
	if c == nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	sessionID, _ := r.Context().Value(sessionIDKey{}).(string)
	if sessionID == "" {
		// Соединение не прошло регистрацию сессии — не собираем.
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	host, port, _ := net.SplitHostPort(r.RemoteAddr)

	// Заголовки ограничены по числу и длине: собранные данные не
	// должны становиться каналом исчерпания памяти.
	payload := map[string]interface{}{
		"method":               r.Method,
		"path":                 r.URL.Path,
		"query":                r.URL.RawQuery,
		"user_agent":           r.UserAgent(),
		"referer":              r.Referer(),
		"content_type":         r.Header.Get("Content-Type"),
		"content_length":       r.ContentLength,
		"headers":              headersToMap(r.Header, c.cfg.MaxHeaders),
		"is_honeypot_endpoint": isHoneypotEndpoint(r.URL.Path),
	}

	// Тело читается с жёстким лимитом: MaxBytesReader разрывает избыточные
	// данные и даёт серверу основание закрыть соединение.
	r.Body = http.MaxBytesReader(w, r.Body, c.cfg.MaxBodySize)
	bodyData, readErr := io.ReadAll(r.Body)
	switch {
	case readErr == nil:
		if len(bodyData) > 0 {
			sum := sha256.Sum256(bodyData)
			payload["body_sha256"] = hex.EncodeToString(sum[:])
			payload["body_size"] = len(bodyData)
			// Имена файлов multipart фиксируются без сохранения содержимого.
			if ct := r.Header.Get("Content-Type"); strings.HasPrefix(ct, "multipart/form-data") {
				payload["upload_type"] = "multipart"
				if formErr := r.ParseMultipartForm(c.cfg.MaxBodySize); formErr == nil {
					var names []string
					for _, fhs := range r.MultipartForm.File {
						for _, fh := range fhs {
							names = append(names, fh.Filename)
						}
					}
					payload["upload_files"] = names
				}
			}
		}
	case strings.Contains(readErr.Error(), "request body too large"):
		// Превышение лимита тела — аномалия клиента, отдельное событие.
		c.BaseCollector.Sessions.RecordEvent(sessionID)
		c.publishEvent(sessionID, host, port, "http", "http", event.EventTypeProtocolError,
			map[string]interface{}{
				"reason": "request_body_exceeds_limit",
				"limit":  c.cfg.MaxBodySize,
			}, event.SeverityMedium)
		http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
		return
	default:
		c.log.Warn("http read body failed", "session_id", sessionID, "error", readErr)
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	sev := event.SeverityLow
	if isHoneypotEndpoint(r.URL.Path) {
		sev = event.SeverityMedium
	}

	// Счётчик событий сессии и событие запроса.
	_ = c.BaseCollector.Sessions.RecordEvent(sessionID)
	c.publishEvent(sessionID, host, port, "http", "http", event.EventTypeRequest, payload, sev)

	// Ответ honeypot: не выдаёт реальное содержимое и не открывает файлы.
	w.Header().Set("Server", "DARKSCOPE/1.0")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("<html><body><h1>Service Unavailable</h1></body></html>"))
}

// headersToMap конвертирует заголовки с ограничением количества: не более
// limit записей; ключ и значение обрезаются до безопасной длины.
func headersToMap(h http.Header, limit int) map[string]string {
	m := make(map[string]string)
	stored := 0
	for k, v := range h {
		if stored >= limit {
			break
		}
		if len(v) == 0 {
			continue
		}
		key := k
		if len(key) > maxHeaderKeyLen {
			key = key[:maxHeaderKeyLen]
		}
		val := v[0]
		if len(val) > maxHeaderValLen {
			val = val[:maxHeaderValLen]
		}
		m[key] = val
		stored++
	}
	return m
}

// orDefault и вспомогательные функции подставляют безопасные значения
// вместо нулевых настроек (ТЗ Phase 2 разд. 7).
func orDefault(d, def time.Duration) time.Duration {
	if d <= 0 {
		return def
	}
	return d
}

func orDefault64(v, def int64) int64 {
	if v <= 0 {
		return def
	}
	return v
}

func orDefaultInt(v, def int) int {
	if v <= 0 {
		return def
	}
	return v
}

// Stop инициирует graceful shutdown HTTP Collector'а:
// сервер прекращает принимать новые соединения, активным обработчикам
// даётся время завершиться, затем ожидается полный дренаж горутин.
func (c *Collector) Stop(ctx context.Context) error {
	if !atomic.CompareAndSwapInt32(c.BaseCollector.GetRunning(), 1, 0) {
		return nil // уже остановлен
	}

	if cancel := c.BaseCollector.GetCancel(); cancel != nil {
		cancel()
	}

	// Graceful shutdown самого сервера: слушатель закрывается, активным
	// запросам даётся время завершиться (ceiling 10 c).
	shutdownCtx, cancelShutdown := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancelShutdown()
	if err := c.server.Shutdown(shutdownCtx); err != nil {
		c.log.Warn("http server shutdown error", "error", err)
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

// publishEvent формирует нормализованное событие и публикует его;
// ошибки публикации логируются и не влияют на обработку запроса.
func (c *Collector) publishEvent(sessionID, sourceIP, sourcePort, protocol, service string,
	et event.EventType, payload interface{}, severity event.Severity) {
	ev := event.NewEvent(sessionID, sourceIP, "127.0.0.1", mustAtoi(sourcePort), c.destPort(), protocol, service, et, payload)
	ev.WithSeverity(severity).WithConfidence(0.9)
	if err := c.publisher.Publish(ev); err != nil {
		c.log.Warn("http publish event failed", "error", err)
	}
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
