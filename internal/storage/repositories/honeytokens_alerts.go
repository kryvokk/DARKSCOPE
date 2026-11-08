package repositories

import (
	"context"
	"database/sql"
	"fmt"
	"time"

)

type Honeytoken struct {
	ID int64
	TokenName string
	TokenType string
	CreatedAt time.Time
}

type HoneytokenRepository struct {
	db *sql.DB
}

func NewHoneytokenRepository(db *sql.DB) *HoneytokenRepository {
	return &HoneytokenRepository{db: db}
}

const insertHoneytokenSQL = `INSERT INTO honeytokens (token_name, token_type, created_at) VALUES (?, ?, ?)`

func (r *HoneytokenRepository) Insert(ctx context.Context, tokenName, tokenType string) (*Honeytoken, error) {
	stmt, err := r.db.PrepareContext(ctx, insertHoneytokenSQL)
	if err != nil {
		return nil, fmt.Errorf("prepare insert honeytoken: %w", err)
	}
	defer stmt.Close()
	res, err := stmt.ExecContext(ctx, tokenName, tokenType, time.Now().UTC().Format(time.RFC3339Nano))
	if err != nil {
		return nil, fmt.Errorf("insert honeytoken: %w", err)
	}
	id, _ := res.LastInsertId()
	return &Honeytoken{ID: id, TokenName: tokenName, TokenType: tokenType, CreatedAt: time.Now().UTC()}, nil
}

const listHoneytokensSQL = `SELECT id, token_name, token_type, created_at FROM honeytokens ORDER BY created_at DESC LIMIT ? OFFSET ?`

func (r *HoneytokenRepository) List(ctx context.Context, limit, offset int) ([]*Honeytoken, error) {
	stmt, err := r.db.PrepareContext(ctx, listHoneytokensSQL)
	if err != nil {
		return nil, fmt.Errorf("prepare list honeytokens: %w", err)
	}
	defer stmt.Close()
	rows, err := stmt.QueryContext(ctx, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("query honeytokens: %w", err)
	}
	defer rows.Close()
	var out []*Honeytoken
	for rows.Next() {
		var h Honeytoken
		var createdAt string
		if err := rows.Scan(&h.ID, &h.TokenName, &h.TokenType, &createdAt); err != nil {
			return nil, fmt.Errorf("scan honeytoken: %w", err)
		}
		h.CreatedAt, _ = time.Parse(time.RFC3339Nano, createdAt)
		out = append(out, &h)
	}
	return out, rows.Err()
}

type AlertRecord struct {
	ID int64
	EventID *string
	Channel string
	Status string
	CreatedAt time.Time
}

type AlertRepository struct {
	db *sql.DB
}

func NewAlertRepository(db *sql.DB) *AlertRepository {
	return &AlertRepository{db: db}
}

const insertAlertSQL = `INSERT INTO alerts (event_id, channel, status, created_at) VALUES (?, ?, ?, ?)`

func (r *AlertRepository) Insert(ctx context.Context, eventID, channel, status string) (*AlertRecord, error) {
	stmt, err := r.db.PrepareContext(ctx, insertAlertSQL)
	if err != nil {
		return nil, fmt.Errorf("prepare insert alert: %w", err)
	}
	defer stmt.Close()
	var eventIDI interface{} = eventID
	res, err := stmt.ExecContext(ctx, eventIDI, channel, status, time.Now().UTC().Format(time.RFC3339Nano))
	if err != nil {
		return nil, fmt.Errorf("insert alert: %w", err)
	}
	id, _ := res.LastInsertId()
	return &AlertRecord{ID: id, EventID: &eventID, Channel: channel, Status: status, CreatedAt: time.Now().UTC()}, nil
}

const listAlertsSQL = `SELECT id, event_id, channel, status, created_at FROM alerts ORDER BY created_at DESC LIMIT ? OFFSET ?`

func (r *AlertRepository) List(ctx context.Context, limit, offset int) ([]*AlertRecord, error) {
	stmt, err := r.db.PrepareContext(ctx, listAlertsSQL)
	if err != nil {
		return nil, fmt.Errorf("prepare list alerts: %w", err)
	}
	defer stmt.Close()
	rows, err := stmt.QueryContext(ctx, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("query alerts: %w", err)
	}
	defer rows.Close()
	var out []*AlertRecord
	for rows.Next() {
		var a AlertRecord
		var eventID, createdAt string
		if err := rows.Scan(&a.ID, &eventID, &a.Channel, &a.Status, &createdAt); err != nil {
			return nil, fmt.Errorf("scan alert: %w", err)
		}
		if eventID != "" {
			a.EventID = &eventID
		}
		a.CreatedAt, _ = time.Parse(time.RFC3339Nano, createdAt)
		out = append(out, &a)
	}
	return out, rows.Err()
}
