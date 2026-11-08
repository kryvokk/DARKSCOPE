package repositories

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"darkscope/honeypot/internal/event"
)

// EventRepository управляет таблицей events.
type EventRepository struct {
	db *sql.DB
}

func NewEventRepository(db *sql.DB) *EventRepository {
	return &EventRepository{db: db}
}

const insertEventSQL = `INSERT INTO events (id, timestamp, session_id, source_ip, source_port, dest_ip, dest_port, protocol, service, event_type, payload, severity, confidence, mitre_json, metadata_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

func (r *EventRepository) Insert(ctx context.Context, e *event.Event) error {
	if e == nil {
		return fmt.Errorf("event is nil")
	}
	payload, err := json.Marshal(e.Payload)
	if err != nil {
		return fmt.Errorf("marshal payload: %w", err)
	}
	mitre, err := json.Marshal(e.MITRE)
	if err != nil {
		return fmt.Errorf("marshal mitre: %w", err)
	}
	metadata, err := json.Marshal(e.Metadata)
	if err != nil {
		return fmt.Errorf("marshal metadata: %w", err)
	}
	stmt, err := r.db.PrepareContext(ctx, insertEventSQL)
	if err != nil {
		return fmt.Errorf("prepare insert event: %w", err)
	}
	defer stmt.Close()
	_, err = stmt.ExecContext(ctx, e.ID, e.Timestamp.Format(time.RFC3339Nano), e.SessionID, e.SourceIP, e.SourcePort, e.DestIP, e.DestPort, e.Protocol, e.Service, string(e.EventType), string(payload), string(e.Severity), e.Confidence, string(mitre), string(metadata))
	if err != nil {
		return fmt.Errorf("insert event: %w", err)
	}
	return nil
}

const getEventSQL = `SELECT id, timestamp, session_id, source_ip, source_port, dest_ip, dest_port, protocol, service, event_type, payload, severity, confidence, mitre_json, metadata_json FROM events WHERE id = ?`

func (r *EventRepository) Get(ctx context.Context, id string) (*event.Event, error) {
	stmt, err := r.db.PrepareContext(ctx, getEventSQL)
	if err != nil {
		return nil, fmt.Errorf("prepare get event: %w", err)
	}
	defer stmt.Close()
	var e event.Event
	var ts, payload, severity, mitre, metadata string
	var eventType string
	err = stmt.QueryRowContext(ctx, id).Scan(&e.ID, &ts, &e.SessionID, &e.SourceIP, &e.SourcePort, &e.DestIP, &e.DestPort, &e.Protocol, &e.Service, &eventType, &payload, &severity, &e.Confidence, &mitre, &metadata)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("event %s not found: %w", id, err)
		}
		return nil, fmt.Errorf("scan event: %w", err)
	}
	e.Timestamp, err = time.Parse(time.RFC3339Nano, ts)
	if err != nil {
		return nil, fmt.Errorf("parse timestamp: %w", err)
	}
	e.EventType = event.EventType(eventType)
	e.Severity = event.Severity(severity)
	e.Payload = json.RawMessage(payload)
	e.MITRE = []string{}
	json.Unmarshal([]byte(mitre), &e.MITRE)
	e.Metadata = map[string]interface{}{}
	json.Unmarshal([]byte(metadata), &e.Metadata)
	return &e, nil
}
