package http

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	nethttp "net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"darkscope/honeypot/internal/config"
	"darkscope/honeypot/internal/event"
	"darkscope/honeypot/internal/session"
)

// captureProcessor собирает события для проверок (как в ssh-тестах).
type captureProcessor struct {
	mu     sync.Mutex
	events []*event.Event
}

func (c *captureProcessor) Publish(ev *event.Event) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.events = append(c.events, ev)
	return nil
}

func (c *captureProcessor) Events() []*event.Event {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]*event.Event, len(c.events))
	copy(out, c.events)
	return out
}

// waitForCond опрашивает условие до выполнения или таймаута; возвращает успех.
func waitForCond(t *testing.T, cond func() bool, d time.Duration) bool {
	t.Helper()
	deadline := time.Now().Add(d)
	for {
		if cond() {
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// actualAddr возвращает фактический адрес слушателя ("127.0.0.1:0" → реальный порт).
func actualAddr(c *Collector) string {
	return c.listener.Addr().String()
}

// newTestCollector собирает конфигурацию по умолчанию с безопасными
// короткими таймаутами; mutate корректирует её.
func newTestCollector(t *testing.T, mutate func(*config.HTTPConfig)) (*Collector, *captureProcessor, *session.Manager) {
	t.Helper()
	cfg := &config.HTTPConfig{
		Enabled:        true,
		ListenAddress:  "127.0.0.1:0",
		MaxConnections: 100,
		ReadTimeout:    2 * time.Second,
		WriteTimeout:   2 * time.Second,
		IdleTimeout:    5 * time.Second,
		MaxBodySize:    1 << 10, // 1 KiB: тесты с лимитом тела проходят быстро
		MaxHeaders:     24,
	}
	if mutate != nil {
		mutate(cfg)
	}
	capture := &captureProcessor{}
	sessMgr := session.NewManager()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	coll, err := New(cfg, capture, sessMgr, logger)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return coll, capture, sessMgr
}

// startAndRegister запускает коллектор и останавливает его в t.Cleanup
// за ограниченное время.
func startAndRegister(t *testing.T, coll *Collector) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := coll.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() {
		stopCtx, stopCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer stopCancel()
		_ = coll.Stop(stopCtx)
	})
}

// TestHTTPStartStop проверяет запуск/остановку и идемпотентность Stop.
func TestHTTPStartStop(t *testing.T) {
	coll, _, _ := newTestCollector(t, nil)
	startAndRegister(t, coll)

	if !coll.IsRunning() {
		t.Error("collector must be running after Start")
	}

	stopCtx, stopCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer stopCancel()
	if err := coll.Stop(stopCtx); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if coll.IsRunning() {
		t.Error("collector must not be running after Stop")
	}
	if err := coll.Stop(stopCtx); err != nil {
		t.Fatalf("second Stop: %v", err)
	}
}

// TestHTTPGetEndpoints проверяет события request для honeypot-эндпоинтов,
// user_agent в payload, реальные protocol/service/dest_port.
func TestHTTPGetEndpoints(t *testing.T) {
	coll, capture, _ := newTestCollector(t, nil)
	startAndRegister(t, coll)

	addr := actualAddr(coll)
	paths := []string{"/", "/login", "/wp-login.php", "/robots.txt", "/api/users", "/admin"}
	client := &nethttp.Client{Timeout: 3 * time.Second}

	for _, p := range paths {
		req, err := nethttp.NewRequest("GET", fmt.Sprintf("http://%s%s", addr, p), nil)
		if err != nil {
			t.Fatalf("NewRequest %s: %v", p, err)
		}
		req.Header.Set("User-Agent", "darkscope-test")
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("GET %s: %v", p, err)
		}
		resp.Body.Close()
		if resp.StatusCode != nethttp.StatusOK {
			t.Errorf("GET %s status = %d, want 200", p, resp.StatusCode)
		}
	}

	// Ждём событие запроса на каждый путь.
	var seen map[string]*event.Event
	ok := waitForCond(t, func() bool {
		seen = make(map[string]*event.Event)
		for _, ev := range capture.Events() {
			if ev.EventType != event.EventTypeRequest {
				continue
			}
			pay, okPay := ev.Payload.(map[string]interface{})
			if !okPay {
				t.Errorf("request payload type = %T", ev.Payload)
				return false
			}
			path, _ := pay["path"].(string)
			seen[path] = ev
		}
		for _, p := range paths {
			if _, okPath := seen[p]; !okPath {
				return false
			}
		}
		return true
	}, 3*time.Second)
	if !ok || len(seen) < len(paths) {
		t.Fatalf("no request events for all paths: got %v (total events %d)", mapKeys(seen), len(capture.Events()))
	}

	for _, p := range paths {
		ev := seen[p]
		pay := ev.Payload.(map[string]interface{})

		if ev.Protocol != "http" || ev.Service != "http" {
			t.Errorf("path %s: protocol/service = %s/%s", p, ev.Protocol, ev.Service)
		}
		if ev.DestPort <= 0 {
			t.Errorf("path %s: dest port = %d, want real listener port", p, ev.DestPort)
		}
		if ev.SourceIP == "" {
			t.Errorf("path %s: source ip is empty", p)
		}
		if ua := pay["user_agent"]; ua != "darkscope-test" {
			t.Errorf("path %s: user_agent = %v", p, ua)
		}
		if method := pay["method"]; method != "GET" {
			t.Errorf("path %s: method = %v", p, method)
		}
		wantEndpoint := true // все пути списка — honeypot-эндпоинты
		if got, okIs := pay["is_honeypot_endpoint"].(bool); !okIs || got != wantEndpoint {
			t.Errorf("path %s: is_honeypot_endpoint = %v (%t)", p, pay["is_honeypot_endpoint"], okIs)
		}
	}
}

// mapKeys — множество ключей карты для сообщений об ошибках.
func mapKeys[T any](m map[string]T) []string {
	if m == nil {
		return nil
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

// TestHTTPPostBodyHash проверяет фиксацию body_sha256/body_size у POST.
func TestHTTPPostBodyHash(t *testing.T) {
	coll, capture, _ := newTestCollector(t, nil)
	startAndRegister(t, coll)

	addr := actualAddr(coll)
	payload := []byte("hello darkscope honeypot")
	resp, err := (&nethttp.Client{Timeout: 3 * time.Second}).Post(
		fmt.Sprintf("http://%s/login", addr), "text/plain", strings.NewReader(string(payload)))
	if err != nil {
		t.Fatalf("POST /login: %v", err)
	}
	resp.Body.Close()

	var request *event.Event
	ok := waitForCond(t, func() bool {
		for _, ev := range capture.Events() {
			if ev.EventType != event.EventTypeRequest {
				continue
			}
			pay := ev.Payload.(map[string]interface{})
			if pay["path"] == "/login" {
				request = ev
				return true
			}
		}
		return false
	}, 3*time.Second)
	if !ok {
		t.Fatal("no request event for POST /login")
	}

	pay := request.Payload.(map[string]interface{})
	sum := sha256.Sum256(payload)
	want := hex.EncodeToString(sum[:])
	if got := pay["body_sha256"]; got != want {
		t.Errorf("body_sha256 = %v, want %s", got, want)
	}
	if got, okSize := pay["body_size"].(int); !okSize || got != len(payload) {
		t.Errorf("body_size = %v (%t), want %d", pay["body_size"], okSize, len(payload))
	}
}

// TestHTTPBodyLimit проверяет 413 и protocol_error при превышении лимита тела.
func TestHTTPBodyLimit(t *testing.T) {
	coll, capture, _ := newTestCollector(t, nil) // MaxBodySize = 1 KiB
	startAndRegister(t, coll)

	addr := actualAddr(coll)
	resp, err := (&nethttp.Client{Timeout: 3 * time.Second}).Post(
		fmt.Sprintf("http://%s/login", addr), "text/plain",
		strings.NewReader(strings.Repeat("x", 4096)))
	if err != nil {
		t.Fatalf("POST oversized: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != nethttp.StatusRequestEntityTooLarge {
		t.Errorf("status = %d, want 413", resp.StatusCode)
	}

	ok := waitForCond(t, func() bool {
		for _, ev := range capture.Events() {
			if ev.EventType != event.EventTypeProtocolError {
				continue
			}
			pay, _ := ev.Payload.(map[string]interface{})
			if pay["reason"] == "request_body_exceeds_limit" {
				return true
			}
		}
		return false
	}, 3*time.Second)
	if !ok {
		t.Errorf("expected protocol_error event for oversized body (total %d)", len(capture.Events()))
	}
}

// TestHTTPSessionPerConnection проверяет «одно соединение = одна сессия»:
// два запроса keep-alive → одна сессия; закрытие соединения → сессия
// завершена и публикуется disconnect; новое соединение → новая сессия.
func TestHTTPSessionPerConnection(t *testing.T) {
	coll, capture, sessMgr := newTestCollector(t, nil)
	startAndRegister(t, coll)

	addr := actualAddr(coll)
	client := &nethttp.Client{
		Timeout:   3 * time.Second,
		Transport: &nethttp.Transport{}, // собственный пул соединений
	}

	for i := 0; i < 2; i++ {
		resp, err := client.Get(fmt.Sprintf("http://%s/", addr))
		if err != nil {
			t.Fatalf("GET #%d: %v", i, err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}

	if got := sessMgr.Count(); got != 1 {
		t.Fatalf("sessions count = %d, want 1 for keep-alive connection", got)
	}

	var connectCount int
	var requestSessionID string
	for _, ev := range capture.Events() {
		switch ev.EventType {
		case event.EventTypeConnect:
			connectCount++
		case event.EventTypeRequest:
			if requestSessionID == "" {
				requestSessionID = ev.SessionID
			}
		}
	}
	if connectCount != 1 {
		t.Errorf("connect events = %d, want 1", connectCount)
	}
	if requestSessionID == "" {
		t.Fatal("request event has empty session id")
	}
	if requestSessionID != "" {
		for _, ev := range capture.Events() {
			if ev.EventType == event.EventTypeRequest && ev.SessionID != requestSessionID {
				t.Errorf("request session id %q differs from %q in same connection", ev.SessionID, requestSessionID)
			}
		}
	}

	// Отдельное соединение (собственный транспорт) → вторая сессия.
	client2 := &nethttp.Client{
		Timeout:   3 * time.Second,
		Transport: &nethttp.Transport{},
	}
	resp, err := client2.Get(fmt.Sprintf("http://%s/", addr))
	if err != nil {
		t.Fatalf("GET via new client: %v", err)
	}
	resp.Body.Close()
	client2.CloseIdleConnections()

	if !waitForCond(t, func() bool { return sessMgr.Count() == 2 }, 3*time.Second) {
		t.Fatalf("sessions count = %d, want 2 after new connection", sessMgr.Count())
	}

	// Закрытие keep-alive соединения → EndSession + disconnect.
	client.CloseIdleConnections()
	ok := waitForCond(t, func() bool {
		for _, ev := range capture.Events() {
			if ev.EventType == event.EventTypeDisconnect && ev.SessionID == requestSessionID {
				return true
			}
		}
		return false
	}, 3*time.Second)
	if !ok {
		t.Error("no disconnect event for keep-alive session")
	}

	sess, found := sessMgr.GetSession(requestSessionID)
	if !found {
		t.Fatal("session disappeared from manager")
	}
	if sess.IsActive() {
		t.Error("session must be ended after connection close")
	}
}

// TestHTTPMaxConnections проверяет ограничение соединений: второе
// raw-соединение сбрасывается, после освобождения слота новый клиент работает.
func TestHTTPMaxConnections(t *testing.T) {
	coll, capture, _ := newTestCollector(t, func(cfg *config.HTTPConfig) {
		cfg.MaxConnections = 1
	})
	startAndRegister(t, coll)

	addr := actualAddr(coll)

	// Первое соединение: валидный запрос, затем держим открытым.
	conn1, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial #1: %v", err)
	}
	defer conn1.Close()
	_, _ = conn1.Write([]byte("GET / HTTP/1.1\r\nHost: darkscope\r\nUser-Agent: probe\r\nConnection: keep-alive\r\n\r\n"))
	_ = conn1.SetReadDeadline(time.Now().Add(3 * time.Second))
	line, err := bufio.NewReader(conn1).ReadString('\n')
	if err != nil || !strings.HasPrefix(line, "HTTP/1.1 200") {
		t.Fatalf("first request failed: %q (%v)", line, err)
	}

	// Второе соединение при исчерпании лимита → немедленное закрытие → EOF.
	conn2, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial #2: %v", err)
	}
	_ = conn2.SetReadDeadline(time.Now().Add(3 * time.Second))
	errCh := make(chan error, 1)
	go func() {
		buf := make([]byte, 32)
		_, readErr := conn2.Read(buf)
		conn2.Close()
		errCh <- readErr
	}()
	select {
	case readErr := <-errCh:
		if readErr == nil {
			t.Error("limited connection expected to be closed, got successful read")
		}
	case <-time.After(3 * time.Second):
		t.Error("limited connection was not closed within 3s")
	}

	// Слот освобождается после закрытия первого соединения.
	conn1.Close()
	resp, err := (&nethttp.Client{Timeout: 3 * time.Second}).Get(fmt.Sprintf("http://%s/", addr))
	if err != nil {
		t.Fatalf("GET after slot freed: %v", err)
	}
	resp.Body.Close()

	// События первого и последнего запроса доставлены.
	if !waitForCond(t, func() bool {
		return len(capture.Events()) >= 3 // connect+connect(+request)
	}, 3*time.Second) {
		t.Errorf("expected events from accepted connections, got %d", len(capture.Events()))
	}
}

// TestHTTPReadTimeout проверяет разрыв частичного запроса по ReadTimeout.
func TestHTTPReadTimeout(t *testing.T) {
	coll, _, _ := newTestCollector(t, func(cfg *config.HTTPConfig) {
		cfg.ReadTimeout = 300 * time.Millisecond
	})
	startAndRegister(t, coll)

	addr := actualAddr(coll)
	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	// Неполный запрос: заголовки не завершены.
	_, _ = conn.Write([]byte("GET / HTTP/1.1\r\nHost: darkscope\r\n"))

	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 64)
	if _, err := conn.Read(buf); err == nil {
		t.Error("connection must be closed by ReadTimeout, got data instead")
	}
}

// TestHTTPHeaderCap проверяет ограничение числа сохранённых заголовков.
func TestHTTPHeaderCap(t *testing.T) {
	coll, capture, _ := newTestCollector(t, func(cfg *config.HTTPConfig) {
		cfg.MaxHeaders = 5
	})
	startAndRegister(t, coll)

	addr := actualAddr(coll)
	req, err := nethttp.NewRequest("GET", fmt.Sprintf("http://%s/", addr), nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	for i := 0; i < 12; i++ {
		req.Header.Set(fmt.Sprintf("X-Probe-%02d", i), "value")
	}
	resp, err := (&nethttp.Client{Timeout: 3 * time.Second}).Do(req)
	if err != nil {
		t.Fatalf("GET with 12 headers: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != nethttp.StatusRequestHeaderFieldsTooLarge {
		t.Fatalf("status = %d, want 431", resp.StatusCode)
	}

	ok := waitForCond(t, func() bool {
		for _, ev := range capture.Events() {
			if ev.EventType == event.EventTypeProtocolError {
				p, _ := ev.Payload.(map[string]interface{})
				if p["reason"] == "too_many_headers" {
					return true
				}
			}
		}
		return false
	}, 3*time.Second)
	if !ok {
		t.Fatal("no protocol_error for excessive request headers")
	}
}

// TestHTTPNoBodyNoCrash проверяет отсутствие body_*-полей у запросов без
// тела и ответ honeypot с заголовком Server.
func TestHTTPNoBodyNoCrash(t *testing.T) {
	coll, capture, _ := newTestCollector(t, nil)
	startAndRegister(t, coll)

	addr := actualAddr(coll)
	resp, err := (&nethttp.Client{Timeout: 3 * time.Second}).Get(fmt.Sprintf("http://%s/", addr))
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if got := resp.Header.Get("Server"); got != "DARKSCOPE/1.0" {
		t.Errorf("Server header = %q", got)
	}

	found := false
	ok := waitForCond(t, func() bool {
		for _, ev := range capture.Events() {
			if ev.EventType != event.EventTypeRequest {
				continue
			}
			pay := ev.Payload.(map[string]interface{})
			if _, has := pay["body_sha256"]; has {
				t.Errorf("unexpected body_sha256 for bodyless request: %v", pay["body_sha256"])
			}
			if _, has := pay["body_size"]; has {
				t.Errorf("unexpected body_size for bodyless request: %v", pay["body_size"])
			}
			found = true
			return true
		}
		return false
	}, 3*time.Second)
	if !ok || !found {
		t.Fatal("no request event for bodyless GET")
	}
}

// TestHTTPTLSRequiresPair проверяет, что Start с неполной TLS-парой
// возвращает ошибку.
func TestHTTPTLSRequiresPair(t *testing.T) {
	coll, _, _ := newTestCollector(t, func(cfg *config.HTTPConfig) {
		cfg.TLSCertFile = "/nonexistent/cert.pem"
		cfg.TLSKeyFile = ""
	})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := coll.Start(ctx); err == nil {
		t.Error("Start with single TLS file must fail")
		t.Cleanup(func() { _ = coll.Stop(context.Background()) })
	}
}

// TestHTTPTLS проверяет работу коллектора с самоподписанным сертификатом.
func TestHTTPTLS(t *testing.T) {
	// Самоподписанный сертификат во временной директории.
	dir := t.TempDir()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "darkscope-test"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	certFile := filepath.Join(dir, "cert.pem")
	keyFile := filepath.Join(dir, "key.pem")
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	if err := os.WriteFile(certFile, certPEM, 0o600); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	if err := os.WriteFile(keyFile, keyPEM, 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}

	coll, capture, _ := newTestCollector(t, func(cfg *config.HTTPConfig) {
		cfg.TLSCertFile = certFile
		cfg.TLSKeyFile = keyFile
	})
	startAndRegister(t, coll)
	addr := actualAddr(coll)

	client := &nethttp.Client{
		Timeout: 3 * time.Second,
		Transport: &nethttp.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // только для теста
		},
	}
	resp, err := client.Get(fmt.Sprintf("https://%s/login", addr))
	if err != nil {
		t.Fatalf("https GET: %v", err)
	}
	resp.Body.Close()

	ok := waitForCond(t, func() bool {
		for _, ev := range capture.Events() {
			if ev.EventType == event.EventTypeRequest {
				return true
			}
		}
		return false
	}, 3*time.Second)
	if !ok {
		t.Error("no request event over TLS")
	}
}

// TestHTTPStopWithActiveRequest проверяет ограниченную остановку
// при живом клиентском соединении.
func TestHTTPStopWithActiveRequest(t *testing.T) {
	coll, _, _ := newTestCollector(t, nil)
	startAndRegister(t, coll)

	addr := actualAddr(coll)
	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	_, _ = conn.Write([]byte("GET / HTTP/1.1\r\nHost: darkscope\r\n\r\n"))

	// Читаем начало ответа (может прийти до или после Stop).
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, _ = bufio.NewReader(conn).ReadString('\n')

	stopCtx, stopCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer stopCancel()
	start := time.Now()
	if err := coll.Stop(stopCtx); err != nil {
		t.Fatalf("Stop with client connected: %v (elapsed %s)", err, time.Since(start))
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Errorf("Stop took %s", elapsed)
	}
}
