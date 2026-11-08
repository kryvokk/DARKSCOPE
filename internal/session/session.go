package session

import (
	"fmt"
	"time"
)

// Status сессии.
type Status string

const (
	StatusActive   Status = "active"
	StatusEnded    Status = "ended"
	StatusAbandoned Status = "abandoned"
)

// Session — отслеживаемое сетевое подключение.
type Session struct {
	ID          string    `json:"id"`
	SourceIP    string    `json:"source_ip"`
	SourcePort  int       `json:"source_port"`
	Protocol    string    `json:"protocol"`
	StartTime   time.Time `json:"start_time"`
	EndTime     time.Time `json:"end_time"`
	Duration    time.Duration `json:"duration"`
	EventCount  int       `json:"event_count"`
	LoginAttempts int     `json:"login_attempts"`
	CommandCount  int     `json:"command_count"`
	Status      Status    `json:"status"`
}

// NewSession создает активную сессию.
func NewSession(id, sourceIP, protocol string, sourcePort int) *Session {
	now := time.Now().UTC()
	return &Session{
		ID:          id,
		SourceIP:    sourceIP,
		SourcePort:  sourcePort,
		Protocol:    protocol,
		StartTime:   now,
		EndTime:     now,
		Status:      StatusActive,
	}
}

// IsActive возвращает true, если сессия не завершена.
func (s *Session) IsActive() bool {
	return s.Status == StatusActive
}

// UpdateDuration пересчитывает длительность сессии.
func (s *Session) UpdateDuration(now time.Time) {
	s.Duration = now.Sub(s.StartTime)
}

// End завершает сессию.
func (s *Session) End(now time.Time) {
	s.EndTime = now
	s.Duration = now.Sub(s.StartTime)
	s.Status = StatusEnded
}

var validStatuses = map[Status]struct{}{
	StatusActive:   {},
	StatusEnded:    {},
	StatusAbandoned: {},
}

// Validate проверяет корректность полей сессии.
func (s *Session) Validate() error {
	if s.ID == "" {
		return fmt.Errorf("session id is required")
	}
	if s.SourceIP == "" {
		return fmt.Errorf("source_ip is required")
	}
	if s.Protocol == "" {
		return fmt.Errorf("protocol is required")
	}
	if _, ok := validStatuses[s.Status]; !ok {
		return fmt.Errorf("unknown status: %q", s.Status)
	}
	return nil
}
