package session

import (
	"fmt"
	"sync"
	"time"
)

// Manager отслеживает сессии в памяти с безопасным конкурентным доступом.
type Manager struct {
	mu        sync.RWMutex
	sessions  map[string]*Session
	now       func() time.Time
}

// NewManager создает менеджер сессий.
func NewManager() *Manager {
	return &Manager{
		sessions: make(map[string]*Session),
		now:      time.Now,
	}
}

// CreateSession регистрирует новую сессию и возвращает её.
func (m *Manager) CreateSession(id, sourceIP, protocol string, sourcePort int) (*Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.sessions[id]; exists {
		return nil, fmt.Errorf("session %s already exists", id)
	}
	s := NewSession(id, sourceIP, protocol, sourcePort)
	if err := s.Validate(); err != nil {
		return nil, fmt.Errorf("invalid session: %w", err)
	}
	m.sessions[id] = s
	return s, nil
}

// GetSession возвращает сессию по ID.
func (m *Manager) GetSession(id string) (*Session, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	s, ok := m.sessions[id]
	return s, ok
}

// RecordEvent увеличивает счетчик событий сессии.
func (m *Manager) RecordEvent(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.sessions[id]
	if !ok {
		return fmt.Errorf("session %s not found", id)
	}
	s.EventCount++
	return nil
}

// RecordLoginAttempt увеличивает счетчик попыток входа.
func (m *Manager) RecordLoginAttempt(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.sessions[id]
	if !ok {
		return fmt.Errorf("session %s not found", id)
	}
	s.LoginAttempts++
	return nil
}

// RecordCommand увеличивает счетчик выполненных команд.
func (m *Manager) RecordCommand(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.sessions[id]
	if !ok {
		return fmt.Errorf("session %s not found", id)
	}
	s.CommandCount++
	return nil
}

// EndSession завершает сессию.
func (m *Manager) EndSession(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.sessions[id]
	if !ok {
		return fmt.Errorf("session %s not found", id)
	}
	s.End(m.now())
	return nil
}

// ListSessions возвращает все сессии (копия).
func (m *Manager) ListSessions() []*Session {
	m.mu.RLock()
	defer m.mu.RUnlock()
	list := make([]*Session, 0, len(m.sessions))
	for _, s := range m.sessions {
		// Поверхностная копия для безопасного чтения вызывающим кодом.
		cp := *s
		list = append(list, &cp)
	}
	return list
}

// ActiveSessions возвращает только активные сессии.
func (m *Manager) ActiveSessions() []*Session {
	m.mu.RLock()
	defer m.mu.RUnlock()
	list := make([]*Session, 0)
	for _, s := range m.sessions {
		if s.IsActive() {
			cp := *s
			list = append(list, &cp)
		}
	}
	return list
}

// Count возвращает количество отслеживаемых сессий.
func (m *Manager) Count() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.sessions)
}

// Close удаляет все сессии (используется при остановке).
func (m *Manager) Close() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sessions = make(map[string]*Session)
}
