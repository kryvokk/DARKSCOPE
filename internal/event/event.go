package event

import "fmt"

// ValidSeverities — допустимые уровни серьезности.
var ValidSeverities = map[Severity]struct{}{
	SeverityLow:      {},
	SeverityMedium:   {},
	SeverityHigh:     {},
	SeverityCritical: {},
}

// ValidEventTypes — допустимые типы событий.
var ValidEventTypes = map[EventType]struct{}{
	EventTypeConnect:            {},
	EventTypeDisconnect:         {},
	EventTypeLoginAttempt:       {},
	EventTypeLoginSuccess:       {},
	EventTypeCommand:            {},
	EventTypeRequest:            {},
	EventTypeFileUpload:         {},
	EventTypeHoneytokenAccess:   {},
	EventTypeSuspiciousActivity: {},
	EventTypeProtocolError:      {},
}

// IsValid проверяет корректность полей события.
func (e *Event) IsValid() error {
	if e.ID == "" {
		return fmt.Errorf("event id is required")
	}
	if e.SessionID == "" {
		return fmt.Errorf("session_id is required")
	}
	if e.SourceIP == "" {
		return fmt.Errorf("source_ip is required")
	}
	if e.DestIP == "" {
		return fmt.Errorf("dest_ip is required")
	}
	if e.Protocol == "" {
		return fmt.Errorf("protocol is required")
	}
	if e.Service == "" {
		return fmt.Errorf("service is required")
	}
	if _, ok := ValidEventTypes[e.EventType]; !ok {
		return fmt.Errorf("unknown event_type: %q", e.EventType)
	}
	if e.Severity != "" {
		if _, ok := ValidSeverities[e.Severity]; !ok {
			return fmt.Errorf("unknown severity: %q", e.Severity)
		}
	}
	if e.Confidence < 0 || e.Confidence > 1 {
		return fmt.Errorf("confidence must be between 0 and 1, got %f", e.Confidence)
	}
	return nil
}

// NormalizeSeverity устанавливает Severity по умолчанию, если не задан.
func (e *Event) NormalizeSeverity() {
	if e.Severity == "" {
		e.Severity = SeverityMedium
	}
}
