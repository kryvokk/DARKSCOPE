package repositories

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"darkscope/honeypot/internal/session"
)

type SessionRepository struct {
	db *sql.DB
}

func NewSessionRepository(db *sql.DB) *SessionRepository {
	return &SessionRepository{db: db}
}

const insertSessionSQL = `INSERT INTO sessions (id, source_ip, source_port, protocol, started_at, ended_at, event_count, status) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`

func (r *SessionRepository) Insert(ctx context.Context, s *session.Session) error {
	if s == nil {
		return fmt.Errorf("session is nil")
	}
	stmt, err := r.db.PrepareContext(ctx, insertSessionSQL)
	if err != nil {
		return fmt.Errorf("prepare insert session: %w", err)
	}
	defer stmt.Close()
	var endedAt interface{}
	if !s.EndTime.IsZero() {
		endedAt = s.EndTime.Format(time.RFC3339Nano)
	}
	_, err = stmt.ExecContext(ctx, s.ID, s.SourceIP, s.SourcePort, s.Protocol, s.StartTime.Format(time.RFC3339Nano), endedAt, s.EventCount, string(s.Status))
	if err != nil {
		return fmt.Errorf("insert session: %w", err)
	}
	return nil
}

const updateSessionSQL = `UPDATE sessions SET ended_at = ?, event_count = ?, status = ? WHERE id = ?`

func (r *SessionRepository) Update(ctx context.Context, s *session.Session) error {
	stmt, err := r.db.PrepareContext(ctx, updateSessionSQL)
	if err != nil {
		return fmt.Errorf("prepare update session: %w", err)
	}
	defer stmt.Close()
	var endedAt interface{}
	if !s.EndTime.IsZero() {
		endedAt = s.EndTime.Format(time.RFC3339Nano)
	}
	_, err = stmt.ExecContext(ctx, endedAt, s.EventCount, string(s.Status), s.ID)
	if err != nil {
		return fmt.Errorf("update session: %w", err)
	}
	return nil
}

const getSessionSQL = `SELECT id, source_ip, source_port, protocol, started_at, ended_at, event_count, status FROM sessions WHERE id = ?`

func (r *SessionRepository) Get(ctx context.Context, id string) (*session.Session, error) {
	stmt, err := r.db.PrepareContext(ctx, getSessionSQL)
	if err != nil {
		return nil, fmt.Errorf("prepare get session: %w", err)
	}
	defer stmt.Close()
	var s session.Session
	var startedAt, endedAt, status string
	err = stmt.QueryRowContext(ctx, id).Scan(&s.ID, &s.SourceIP, &s.SourcePort, &s.Protocol, &startedAt, &endedAt, &s.EventCount, &status)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("session %s not found: %w", id, err)
		}
		return nil, fmt.Errorf("scan session: %w", err)
	}
	s.StartTime, _ = time.Parse(time.RFC3339Nano, startedAt)
	if endedAt != "" {
		s.EndTime, _ = time.Parse(time.RFC3339Nano, endedAt)
	}
	s.Duration = s.EndTime.Sub(s.StartTime)
	s.Status = session.Status(status)
	return &s, nil
}

const listSessionsSQL = `SELECT id, source_ip, source_port, protocol, started_at, ended_at, event_count, status FROM sessions ORDER BY started_at DESC LIMIT ? OFFSET ?`

func (r *SessionRepository) List(ctx context.Context, limit, offset int) ([]*session.Session, error) {
	stmt, err := r.db.PrepareContext(ctx, listSessionsSQL)
	if err != nil {
		return nil, fmt.Errorf("prepare list sessions: %w", err)
	}
	defer stmt.Close()
	rows, err := stmt.QueryContext(ctx, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("query sessions: %w", err)
	}
	defer rows.Close()
	var out []*session.Session
	for rows.Next() {
		var s session.Session
		var startedAt, endedAt, status string
		if err := rows.Scan(&s.ID, &s.SourceIP, &s.SourcePort, &s.Protocol, &startedAt, &endedAt, &s.EventCount, &status); err != nil {
			return nil, fmt.Errorf("scan session: %w", err)
		}
		s.StartTime, _ = time.Parse(time.RFC3339Nano, startedAt)
		if endedAt != "" {
			s.EndTime, _ = time.Parse(time.RFC3339Nano, endedAt)
		}
		s.Duration = s.EndTime.Sub(s.StartTime)
		s.Status = session.Status(status)
		out = append(out, &s)
	}
	return out, rows.Err()
}
