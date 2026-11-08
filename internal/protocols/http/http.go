package http

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"darkscope/honeypot/internal/config"
	"darkscope/honeypot/internal/event"
	"darkscope/honeypot/internal/protocols"
	"darkscope/honeypot/internal/session"
)

// honeypotEndpoints — список эндпоинтов для сбора данных.
var honeypotEndpoints = []string{
	"/",
	"/login",
	"/admin",
	"/wp-login.php",
	"/phpmyadmin",
	"/api/",
	"/robots.txt",
}

// isHoneypotEndpoint проверяет, является ли путь одним из эндпоинтов.
func isHoneypotEndpoint(path string) bool {
	for _, ep := range honeypotEndpoints {
		if strings.HasPrefix(path, ep) || path == ep {
			return true
		}
	}
	return false
}

// Collector реализует HTTP Honeypot.
type Collector struct {
	protocols.BaseCollector
	cfg      *config.HTTPConfig
	server   *http.Server
	listener net.Listener
	log      *slog.Logger
	publisher protocols.Publisher
}

// New создаёт новый HTTP Collectор.
func New(cfg *config.HTTPConfig, publisher protocols.Publisher, sessMgr *session.Manager, log *slog.Logger) (*Collector, error) {
	mux := http.NewServeMux()
	h := &handler{}

	c := &Collector{
		BaseCollector: protocols.BaseCollector{Sessions: sessMgr},
		cfg:           cfg,
		log:           log,
		publisher:     publisher,
	}

	h.collector = c

	// Регистрируем обработчики для типовых honeypot-эндпоинтов.
	// "/" регистрируется отдельно один раз как catch-all: повторная
	// регистрация одного и того же пути вызывает панику ServeMux.
	for _, ep := range honeypotEndpoints {
		if ep == "/" {
			continue
		}
		mux.HandleFunc(ep, h.handleRequest)
	}
	mux.HandleFunc("/", h.handleRequest)

	server := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: cfg.ReadTimeout,
		ReadTimeout:       cfg.ReadTimeout,
		WriteTimeout:      cfg.WriteTimeout,
		IdleTimeout:       cfg.IdleTimeout,
		MaxHeaderBytes:    1 << 20, // 1 MB max headers
	}
	c.server = server

	return c, nil
}

// Name возвращает имя протокола.
func (c *Collector) Name() string { return "http" }

// ListenAddr возвращает адрес прослушивания.
func (c *Collector) ListenAddr() string { return c.cfg.ListenAddress }

// handler обрабатывает HTTP-запросы.
type handler struct {
	collector *Collector
}

func (h *handler) handleRequest(w http.ResponseWriter, r *http.Request) {
	c := h.collector
	if c == nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	remoteAddr := r.RemoteAddr
	host, port, _ := net.SplitHostPort(remoteAddr)

	// Уникальный ID на каждый запрос. В этом коммите гарантируется
	// уникальность, чтобы повторный запрос не конфликтовал с уже
	// существующей сессией; полноценная сессия "на соединение"
	// вводится следующим коммитом.
	sessionID := newSessionID()

	_, err := c.BaseCollector.Sessions.CreateSession(
		sessionID, host, "http", mustAtoi(port),
	)
	if err != nil {
		c.log.Error("http create session failed", "session_id", sessionID, "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	// Собираем метаданные запроса.
	payload := map[string]interface{}{
		"method":             r.Method,
		"url":                r.URL.String(),
		"path":               r.URL.Path,
		"query":              r.URL.RawQuery,
		"user_agent":         r.UserAgent(),
		"referer":            r.Referer(),
		"content_type":       r.Header.Get("Content-Type"),
		"content_length":     r.ContentLength,
		"headers":            headersToMap(r.Header),
		"is_honeypot_endpoint": isHoneypotEndpoint(r.URL.Path),
	}

	// Читаем тело запроса с жёстким ограничением размера.
	// MaxBytesReader гарантирует, что клиент не сможет передать
	// больше лимита и что место под тело не будет выделено заранее.
	r.Body = http.MaxBytesReader(w, r.Body, c.cfg.MaxBodySize)
	bodyData, err := io.ReadAll(r.Body)
	if err != nil {
		c.log.Warn("http read body failed", "session_id", sessionID, "error", err)
		http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
		return
	}

	if len(bodyData) > 0 {
		bodyHash := sha256.Sum256(bodyData)
		payload["body_sha256"] = hex.EncodeToString(bodyHash[:])
		payload["body_size"] = len(bodyData)
		// Проверяем на multipart upload.
		if ct := r.Header.Get("Content-Type"); strings.HasPrefix(ct, "multipart/form-data") {
			payload["upload_type"] = "multipart"
			// Парсим multipart для извлечения имён файлов (без сохранения содержимого).
			if err := r.ParseMultipartForm(c.cfg.MaxBodySize); err == nil {
				var files []string
				for _, fheaders := range r.MultipartForm.File {
					for _, fh := range fheaders {
						files = append(files, fh.Filename)
					}
				}
				payload["upload_files"] = files
			}
		}
	}

	// Публикуем событие connect.
	c.BaseCollector.Sessions.RecordEvent(sessionID)
	c.publishEvent(sessionID, host, port, "http", "http", event.EventTypeConnect, nil, event.SeverityLow)

	// Публикуем событие request.
	c.BaseCollector.Sessions.RecordEvent(sessionID)
	sev := event.SeverityLow
	if isHoneypotEndpoint(r.URL.Path) {
		sev = event.SeverityMedium
	}
	c.publishEvent(sessionID, host, port, "http", "http", event.EventTypeRequest, payload, sev)

	// Отправляем простой ответ.
	w.Header().Set("Server", "DARKSCOPE/1.0")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("<html><body><h1>Service Unavailable</h1></body></html>"))

	// Завершаем сессию.
	c.BaseCollector.Sessions.EndSession(sessionID)
	c.publishEvent(sessionID, host, port, "http", "http", event.EventTypeDisconnect, nil, event.SeverityLow)
}

// headersToMap конвертирует HTTP заголовки в map.
func headersToMap(h http.Header) map[string]string {
	m := make(map[string]string)
	for k, v := range h {
		if len(v) > 0 {
			m[k] = v[0]
		}
	}
	return m
}

// sessionIDSeq — резерв для генерации ID при недоступном crypto/rand.
var sessionIDSeq atomic.Uint64

// newSessionID генерирует уникальный идентификатор сессии/запроса на основе
// crypto/rand; при недоступном rand использует резервный счётчик.
func newSessionID() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		n := sessionIDSeq.Add(1)
		binary.BigEndian.PutUint64(b[:], n)
	}
	return fmt.Sprintf("http-%s", hex.EncodeToString(b[:]))
}

// Start запускает HTTP сервер.
func (c *Collector) Start(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	c.BaseCollector.SetContext(ctx, cancel)

	listener, err := net.Listen("tcp", c.cfg.ListenAddress)
	if err != nil {
		return fmt.Errorf("listen http: %w", err)
	}
	c.BaseCollector.Listener = listener
	c.listener = listener

	c.BaseCollector.SetRunning(true)

	// Ограничиваем количество одновременных соединений.
	if c.cfg.MaxConnections > 0 {
		c.BaseCollector.SetConnLimiter(make(chan struct{}, c.cfg.MaxConnections))
	}

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

// Stop инициирует graceful shutdown HTTP Collectора.
func (c *Collector) Stop(ctx context.Context) error {
	if !atomic.CompareAndSwapInt32(c.BaseCollector.GetRunning(), 1, 0) {
		return nil // уже остановлен
	}

	if cancel := c.BaseCollector.GetCancel(); cancel != nil {
		cancel()
	}

	// Закрываем сервер с таймаутом.
	shutdownCtx, cancelShutdown := context.WithTimeout(context.Background(), 15*time.Second)
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
	ev := event.NewEvent(sessionID, sourceIP, "127.0.0.1", mustAtoi(sourcePort), 80, protocol, service, et, payload)
	ev.WithSeverity(severity).WithConfidence(0.9)
	if err := c.publisher.Publish(ev); err != nil {
		c.log.Warn("http publish event failed", "error", err)
	}
}

var (
	_ = context.Background
	_ = time.Second
)
