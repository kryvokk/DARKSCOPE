package event

import (
	"testing"
	"time"
)

func TestNewEvent(t *testing.T) {
	e := NewEvent("sess-1", "10.0.0.1", "10.0.0.2", 1234, 22, "ssh", "ssh", EventTypeConnect, nil)
	if e.ID == "" {
		t.Error("event ID should not be empty")
	}
	if e.SessionID != "sess-1" {
		t.Errorf("session_id: %q", e.SessionID)
	}
	if e.SourceIP != "10.0.0.1" {
		t.Errorf("source_ip: %q", e.SourceIP)
	}
	if e.SourcePort != 1234 {
		t.Errorf("source_port: %d", e.SourcePort)
	}
	if e.DestIP != "10.0.0.2" {
		t.Errorf("dest_ip: %q", e.DestIP)
	}
	if e.DestPort != 22 {
		t.Errorf("dest_port: %d", e.DestPort)
	}
	if e.Protocol != "ssh" {
		t.Errorf("protocol: %q", e.Protocol)
	}
	if e.Service != "ssh" {
		t.Errorf("service: %q", e.Service)
	}
	if e.EventType != EventTypeConnect {
		t.Errorf("event_type: %q", e.EventType)
	}
	if e.Confidence != 1.0 {
		t.Errorf("confidence: %f", e.Confidence)
	}
	if e.Metadata == nil {
		t.Error("metadata should be initialized")
	}
	if e.Timestamp.IsZero() {
		t.Error("timestamp should be set")
	}
}

func TestEventUniqueIDs(t *testing.T) {
	e1 := NewEvent("s", "1.2.3.4", "1.2.3.5", 1, 2, "ssh", "ssh", EventTypeConnect, nil)
	e2 := NewEvent("s", "1.2.3.4", "1.2.3.5", 1, 2, "ssh", "ssh", EventTypeConnect, nil)
	if e1.ID == e2.ID {
		t.Error("two events should have unique IDs")
	}
}

func TestEventValidation(t *testing.T) {
	// Валидное событие
	e := NewEvent("s", "1.2.3.4", "1.2.3.5", 1, 2, "ssh", "ssh", EventTypeCommand, nil)
	e.Severity = SeverityHigh
	e.Confidence = 0.9
	if err := e.IsValid(); err != nil {
		t.Errorf("valid event should pass validation: %v", err)
	}

	// Пустой ID
	e2 := NewEvent("", "1.2.3.4", "1.2.3.5", 1, 2, "ssh", "ssh", EventTypeConnect, nil)
	if err := e2.IsValid(); err == nil {
		t.Error("expected validation error for empty ID")
	}

	// Неизвестный тип события
	e3 := NewEvent("s", "1.2.3.4", "1.2.3.5", 1, 2, "ssh", "ssh", "unknown_type", nil)
	if err := e3.IsValid(); err == nil {
		t.Error("expected validation error for unknown event type")
	}

	// Confidence вне диапазона
	e4 := NewEvent("s", "1.2.3.4", "1.2.3.5", 1, 2, "ssh", "ssh", EventTypeConnect, nil)
	e4.Confidence = 1.5
	if err := e4.IsValid(); err == nil {
		t.Error("expected validation error for confidence > 1")
	}

	// Неизвестный северити
	e5 := NewEvent("s", "1.2.3.4", "1.2.3.5", 1, 2, "ssh", "ssh", EventTypeConnect, nil)
	e5.Severity = "unknown"
	if err := e5.IsValid(); err == nil {
		t.Error("expected validation error for unknown severity")
	}
}

func TestEventNormalizeSeverity(t *testing.T) {
	e := NewEvent("s", "1.2.3.4", "1.2.3.5", 1, 2, "ssh", "ssh", EventTypeConnect, nil)
	e.NormalizeSeverity()
	if e.Severity != SeverityMedium {
		t.Errorf("default severity should be medium, got %q", e.Severity)
	}

	e2 := NewEvent("s", "1.2.3.4", "1.2.3.5", 1, 2, "ssh", "ssh", EventTypeConnect, nil)
	e2.Severity = SeverityCritical
	e2.NormalizeSeverity()
	if e2.Severity != SeverityCritical {
		t.Errorf("existing severity should not be changed, got %q", e2.Severity)
	}
}

func TestEventWithModifiers(t *testing.T) {
	e := NewEvent("s", "1.2.3.4", "1.2.3.5", 1, 2, "ssh", "ssh", EventTypeCommand, nil).
		WithSeverity(SeverityHigh).
		WithConfidence(0.85).
		WithMITRE("T1110", "T1059").
		WithMetadata("key", "value")

	if e.Severity != SeverityHigh {
		t.Errorf("severity: %q", e.Severity)
	}
	if e.Confidence != 0.85 {
		t.Errorf("confidence: %f", e.Confidence)
	}
	if len(e.MITRE) != 2 || e.MITRE[0] != "T1110" || e.MITRE[1] != "T1059" {
		t.Errorf("mitre: %v", e.MITRE)
	}
	if e.Metadata["key"] != "value" {
		t.Errorf("metadata: %v", e.Metadata)
	}
}

func TestEventTimestampUTC(t *testing.T) {
	e := NewEvent("s", "1.2.3.4", "1.2.3.5", 1, 2, "ssh", "ssh", EventTypeConnect, nil)
	if e.Timestamp.Location().String() != "UTC" {
		t.Errorf("timestamp should be UTC, got %s", e.Timestamp.Location())
	}
}

var _ = time.Second
