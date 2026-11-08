package session

import (
	"fmt"
	"sync"
	"testing"
)

func TestSessionCreateAndGet(t *testing.T) {
	m := NewManager()
	s, err := m.CreateSession("s1", "10.0.0.1", "ssh", 1234)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if s.ID != "s1" || s.SourceIP != "10.0.0.1" || s.SourcePort != 1234 || s.Protocol != "ssh" {
		t.Errorf("unexpected session fields: %+v", s)
	}
	if !s.IsActive() {
		t.Error("session should be active")
	}
	got, ok := m.GetSession("s1")
	if !ok {
		t.Fatal("session not found")
	}
	if got.ID != "s1" {
		t.Errorf("get returned %+v", got)
	}
}

func TestSessionDuplicateCreateFails(t *testing.T) {
	m := NewManager()
	if _, err := m.CreateSession("s1", "10.0.0.1", "ssh", 1234); err != nil {
		t.Fatalf("first create: %v", err)
	}
	if _, err := m.CreateSession("s1", "10.0.0.2", "ssh", 1235); err == nil {
		t.Error("expected error on duplicate session id")
	}
}

func TestSessionRecordCounters(t *testing.T) {
	m := NewManager()
	s, _ := m.CreateSession("s1", "10.0.0.1", "ssh", 1234)
	if err := m.RecordEvent(s.ID); err != nil {
		t.Fatalf("record event: %v", err)
	}
	if err := m.RecordEvent(s.ID); err != nil {
		t.Fatalf("record event 2: %v", err)
	}
	if err := m.RecordLoginAttempt(s.ID); err != nil {
		t.Fatalf("record login: %v", err)
	}
	if err := m.RecordCommand(s.ID); err != nil {
		t.Fatalf("record command: %v", err)
	}
	got, _ := m.GetSession(s.ID)
	if got.EventCount != 2 {
		t.Errorf("event_count %d, want 2", got.EventCount)
	}
	if got.LoginAttempts != 1 {
		t.Errorf("login_attempts %d, want 1", got.LoginAttempts)
	}
	if got.CommandCount != 1 {
		t.Errorf("command_count %d, want 1", got.CommandCount)
	}
}

func TestSessionEnd(t *testing.T) {
	m := NewManager()
	s, _ := m.CreateSession("s1", "10.0.0.1", "ssh", 1234)
	start := s.StartTime
	if err := m.EndSession(s.ID); err != nil {
		t.Fatalf("end: %v", err)
	}
	got, _ := m.GetSession(s.ID)
	if got.Status != StatusEnded {
		t.Errorf("status %q, want %q", got.Status, StatusEnded)
	}
	if got.EndTime.Before(start) {
		t.Error("end_time before start_time")
	}
	if got.Duration <= 0 {
		t.Errorf("duration %v, want > 0", got.Duration)
	}
}

func TestSessionUnknownIDErrors(t *testing.T) {
	m := NewManager()
	fns := []func(string) error{
		m.RecordEvent,
		m.RecordLoginAttempt,
		m.RecordCommand,
		m.EndSession,
	}
	for _, fn := range fns {
		if err := fn("nope"); err == nil {
			t.Error("expected error for unknown session")
		}
	}
	if _, ok := m.GetSession("nope"); ok {
		t.Error("get unknown session should return not found")
	}
}

func TestSessionConcurrentAccess(t *testing.T) {
	m := NewManager()
	const n = 100
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			id := fmt.Sprintf("sess-%d", i)
			_, err := m.CreateSession(id, "10.0.0.1", "ssh", 1234)
			if err != nil {
				t.Errorf("create %d: %v", i, err)
			}
			_ = m.RecordEvent(id)
		}(i)
	}
	wg.Wait()
	if m.Count() != n {
		t.Errorf("count %d, want %d", m.Count(), n)
	}
}

func TestSessionValidate(t *testing.T) {
	s := &Session{}
	if err := s.Validate(); err == nil {
		t.Error("expected validation error for empty session")
	}
	s.ID = "x"
	s.SourceIP = "1.2.3.4"
	s.Protocol = "ssh"
	s.Status = StatusActive
	if err := s.Validate(); err != nil {
		t.Errorf("unexpected validation error: %v", err)
	}
}
