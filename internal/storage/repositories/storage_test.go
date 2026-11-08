package repositories

import (
	"context"
	"testing"
	"time"

	"darkscope/honeypot/internal/event"
	"darkscope/honeypot/internal/session"
	"darkscope/honeypot/internal/storage"
)

func TestStorageIntegration(t *testing.T) {
	dir := t.TempDir()
	dbPath := dir + "/test.db"

	store, err := storage.Open(dbPath)
	if err != nil {
		t.Fatalf("open storage: %v", err)
	}
	defer store.Close()

	if err := store.Ping(context.Background()); err != nil {
		t.Fatalf("ping: %v", err)
	}

	eventRepo := NewEventRepository(store.DB())
	sessRepo := NewSessionRepository(store.DB())

	// Создаем сессию
	s := &session.Session{
		ID:          "sess-1",
		SourceIP:    "10.0.0.1",
		SourcePort:  12345,
		Protocol:    "ssh",
		StartTime:   time.Now().UTC(),
		Status:      session.StatusActive,
	}
	if err := sessRepo.Insert(context.Background(), s); err != nil {
		t.Fatalf("insert session: %v", err)
	}

	// Создаем событие
	e := &event.Event{
		ID:          "evt-1",
		Timestamp:   time.Now().UTC(),
		SessionID:   "sess-1",
		SourceIP:    "10.0.0.1",
		SourcePort:  12345,
		DestIP:      "10.0.0.2",
		DestPort:    22,
		Protocol:    "ssh",
		Service:     "ssh",
		EventType:   event.EventTypeConnect,
		Payload:     map[string]interface{}{"banner": "SSH-2.0-fake"},
		Severity:    event.SeverityLow,
		Confidence:  0.9,
		MITRE:       []string{},
		Metadata:    map[string]interface{}{"key": "val"},
	}
	if err := eventRepo.Insert(context.Background(), e); err != nil {
		t.Fatalf("insert event: %v", err)
	}

	// Читаем событие обратно
	got, err := eventRepo.Get(context.Background(), "evt-1")
	if err != nil {
		t.Fatalf("get event: %v", err)
	}
	if got.ID != "evt-1" {
		t.Errorf("event id: %q", got.ID)
	}
	if got.SessionID != "sess-1" {
		t.Errorf("session_id: %q", got.SessionID)
	}
	if got.SourceIP != "10.0.0.1" {
		t.Errorf("source_ip: %q", got.SourceIP)
	}
	if got.EventType != event.EventTypeConnect {
		t.Errorf("event_type: %q", got.EventType)
	}
	if got.Severity != event.SeverityLow {
		t.Errorf("severity: %q", got.Severity)
	}
	if got.Confidence != 0.9 {
		t.Errorf("confidence: %f", got.Confidence)
	}

	// Читаем сессию
	gotS, err := sessRepo.Get(context.Background(), "sess-1")
	if err != nil {
		t.Fatalf("get session: %v", err)
	}
	if gotS.ID != "sess-1" {
		t.Errorf("session id: %q", gotS.ID)
	}
	if gotS.Status != session.StatusActive {
		t.Errorf("session status: %q", gotS.Status)
	}

	// Список сессий
	list, err := sessRepo.List(context.Background(), 10, 0)
	if err != nil {
		t.Fatalf("list sessions: %v", err)
	}
	if len(list) != 1 {
		t.Errorf("expected 1 session, got %d", len(list))
	}

	// Несуществующее событие
	if _, err := eventRepo.Get(context.Background(), "nonexistent"); err == nil {
		t.Error("expected error for nonexistent event")
	}
}

func TestStorageMigrationIdempotent(t *testing.T) {
	dir := t.TempDir()
	dbPath := dir + "/test.db"

	store1, err := storage.Open(dbPath)
	if err != nil {
		t.Fatalf("open storage: %v", err)
	}
	store1.Close()

	// Повторное открытие должно применять миграции без ошибок (идемпотентно)
	store2, err := storage.Open(dbPath)
	if err != nil {
		t.Fatalf("reopen storage: %v", err)
	}
	store2.Close()
}

func TestAttackerRepository(t *testing.T) {
	dir := t.TempDir()
	dbPath := dir + "/test.db"
	store, err := storage.Open(dbPath)
	if err != nil {
		t.Fatalf("open storage: %v", err)
	}
	defer store.Close()

	attackerRepo := NewAttackerRepository(store.DB())

	now := time.Now().UTC()
	if err := attackerRepo.Upsert(context.Background(), "10.0.0.1", now, now, 5, 2, 7.5, map[string]interface{}{"proto": "ssh"}); err != nil {
		t.Fatalf("upsert attacker: %v", err)
	}

	got, err := attackerRepo.Get(context.Background(), "10.0.0.1")
	if err != nil {
		t.Fatalf("get attacker: %v", err)
	}
	if got.IP != "10.0.0.1" {
		t.Errorf("attacker ip: %q", got.IP)
	}
	if got.TotalEvents != 5 {
		t.Errorf("total_events: %d (want 5)", got.TotalEvents)
	}
	if got.TotalSessions != 2 {
		t.Errorf("total_sessions: %d (want 2)", got.TotalSessions)
	}

	// Обновляем того же атакующего (перезаписываем значения)
	if err := attackerRepo.Upsert(context.Background(), "10.0.0.1", now, now.Add(time.Hour), 3, 1, 8.0, nil); err != nil {
		t.Fatalf("upsert attacker again: %v", err)
	}

	got, err = attackerRepo.Get(context.Background(), "10.0.0.1")
	if err != nil {
		t.Fatalf("get attacker again: %v", err)
	}
	if got.TotalEvents != 3 {
		t.Errorf("total_events: %d (want 3)", got.TotalEvents)
	}
	if got.TotalSessions != 1 {
		t.Errorf("total_sessions: %d (want 1)", got.TotalSessions)
	}

	// Несуществующий атакующий
	if _, err := attackerRepo.Get(context.Background(), "10.0.0.99"); err == nil {
		t.Error("expected error for nonexistent attacker")
	}

	list, err := attackerRepo.List(context.Background(), 10, 0)
	if err != nil {
		t.Fatalf("list attackers: %v", err)
	}
	if len(list) != 1 {
		t.Errorf("expected 1 attacker, got %d", len(list))
	}
}


func TestFileRepository(t *testing.T) {
	dir := t.TempDir()
	dbPath := dir + "/test.db"
	store, err := storage.Open(dbPath)
	if err != nil {
		t.Fatalf("open storage: %v", err)
	}
	defer store.Close()

	fileRepo := NewFileRepository(store.DB())

	f, err := fileRepo.Insert(context.Background(), "sess-1", "10.0.0.1", "passwords.txt", "/tmp/uploads/abc123", 1024, "sha256hash123")
	if err != nil {
		t.Fatalf("insert file: %v", err)
	}
	if f.Filename != "passwords.txt" {
		t.Errorf("filename: %q", f.Filename)
	}
	if f.SHA256 != "sha256hash123" {
		t.Errorf("sha256: %q", f.SHA256)
	}

	// Поиск по SHA256
	found, err := fileRepo.BySHA256(context.Background(), "sha256hash123")
	if err != nil {
		t.Fatalf("by sha256: %v", err)
	}
	if found.ID != f.ID {
		t.Errorf("file id: %d", found.ID)
	}

	// Список файлов
	list, err := fileRepo.List(context.Background(), 10, 0)
	if err != nil {
		t.Fatalf("list files: %v", err)
	}
	if len(list) != 1 {
		t.Errorf("expected 1 file, got %d", len(list))
	}

	// Несуществующий hash
	if _, err := fileRepo.BySHA256(context.Background(), "nonexistent"); err == nil {
		t.Error("expected error for nonexistent file hash")
	}
}

func TestHoneytokenAndAlertRepository(t *testing.T) {
	dir := t.TempDir()
	dbPath := dir + "/test.db"
	store, err := storage.Open(dbPath)
	if err != nil {
		t.Fatalf("open storage: %v", err)
	}
	defer store.Close()

	htRepo := NewHoneytokenRepository(store.DB())
	alertRepo := NewAlertRepository(store.DB())

	ht, err := htRepo.Insert(context.Background(), "passwords.txt", "credentials")
	if err != nil {
		t.Fatalf("insert honeytoken: %v", err)
	}
	if ht.TokenName != "passwords.txt" {
		t.Errorf("token name: %q", ht.TokenName)
	}

	list, err := htRepo.List(context.Background(), 10, 0)
	if err != nil {
		t.Fatalf("list honeytokens: %v", err)
	}
	if len(list) != 1 {
		t.Errorf("expected 1 honeytoken, got %d", len(list))
	}

	alert, err := alertRepo.Insert(context.Background(), "evt-1", "telegram", "sent")
	if err != nil {
		t.Fatalf("insert alert: %v", err)
	}
	if alert.Channel != "telegram" {
		t.Errorf("channel: %q", alert.Channel)
	}

	alertList, err := alertRepo.List(context.Background(), 10, 0)
	if err != nil {
		t.Fatalf("list alerts: %v", err)
	}
	if len(alertList) != 1 {
		t.Errorf("expected 1 alert, got %d", len(alertList))
	}
}
