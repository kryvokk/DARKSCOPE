package event

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"sync/atomic"
	"time"
)

// EventType — тип события.
type EventType string

const (
	EventTypeConnect             EventType = "connect"
	EventTypeDisconnect          EventType = "disconnect"
	EventTypeLoginAttempt        EventType = "login_attempt"
	EventTypeLoginSuccess        EventType = "login_success"
	EventTypeCommand             EventType = "command"
	EventTypeRequest             EventType = "request"
	EventTypeFileUpload          EventType = "file_upload"
	EventTypeHoneytokenAccess    EventType = "honeytoken_access"
	EventTypeSuspiciousActivity  EventType = "suspicious_activity"
	EventTypeProtocolError       EventType = "protocol_error"
)

// Severity — уровень серьезности события.
type Severity string

const (
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

// Event — универсальная структура события, публикуемая в Event Bus.
type Event struct {
	ID          string                 `json:"id"`
	Timestamp   time.Time              `json:"timestamp"`
	SessionID   string                 `json:"session_id"`
	SourceIP    string                 `json:"source_ip"`
	SourcePort  int                    `json:"source_port"`
	DestIP      string                 `json:"dest_ip"`
	DestPort    int                    `json:"dest_port"`
	Protocol    string                 `json:"protocol"`
	Service     string                 `json:"service"`
	EventType   EventType              `json:"event_type"`
	Payload     interface{}            `json:"payload"`
	Severity    Severity               `json:"severity"`
	Confidence  float64                `json:"confidence"`
	MITRE       []string               `json:"mitre"`
	Metadata    map[string]interface{} `json:"metadata"`
}

var idCounter atomic.Uint64

// newID генерирует уникальный идентификатор события.
func newID() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		// Fallback: счетчик + время, чтобы не упасть при проблемах с rand.
		n := idCounter.Add(1)
		binary.BigEndian.PutUint64(b[:], n)
	}
	return hex.EncodeToString(b[:])
}

// NewEvent создает событие с уникальным ID и текущей меткой времени.
func NewEvent(sessionID, sourceIP, destIP string, sourcePort, destPort int,
	protocol, service string, et EventType, payload interface{}) *Event {
	return &Event{
		ID:         newID(),
		Timestamp:  time.Now().UTC(),
		SessionID:  sessionID,
		SourceIP:   sourceIP,
		SourcePort: sourcePort,
		DestIP:     destIP,
		DestPort:   destPort,
		Protocol:   protocol,
		Service:    service,
		EventType:  et,
		Payload:    payload,
		Confidence: 1.0,
		Metadata:   make(map[string]interface{}),
	}
}

// WithSeverity задает уровень серьезности.
func (e *Event) WithSeverity(s Severity) *Event {
	e.Severity = s
	return e
}

// WithConfidence задает доверительный интервал (0.0–1.0).
func (e *Event) WithConfidence(c float64) *Event {
	e.Confidence = c
	return e
}

// WithMITRE добавляет техники MITRE ATT&CK.
func (e *Event) WithMITRE(techniques ...string) *Event {
	e.MITRE = append(e.MITRE, techniques...)
	return e
}

// WithMetadata добавляет пары ключ-значение в метаданные.
func (e *Event) WithMetadata(key string, value interface{}) *Event {
	e.Metadata[key] = value
	return e
}
