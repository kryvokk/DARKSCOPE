package repositories

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

)

type DetectionRepository struct {
	db *sql.DB
}

func NewDetectionRepository(db *sql.DB) *DetectionRepository {
	return &DetectionRepository{db: db}
}

const insertDetectionSQL = `INSERT INTO detections (rule_id, session_id, source_ip, severity, confidence, description, mitre_json, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`

type Detection struct {
	ID int64
	RuleID string
	SessionID *string
	SourceIP string
	Severity string
	Confidence float64
	Description string
	MITRE []string
	CreatedAt time.Time
}

func (r *DetectionRepository) Insert(ctx context.Context, ruleID, sessionID, sourceIP, severity, description string, confidence float64, mitre []string) (*Detection, error) {
	stmt, err := r.db.PrepareContext(ctx, insertDetectionSQL)
	if err != nil {
		return nil, fmt.Errorf("prepare insert detection: %w", err)
	}
	defer stmt.Close()
	mitreJSON, _ := json.Marshal(mitre)
	var sessionIDI interface{} = sessionID
	res, err := stmt.ExecContext(ctx, ruleID, sessionIDI, sourceIP, severity, confidence, description, string(mitreJSON), time.Now().UTC().Format(time.RFC3339Nano))
	if err != nil {
		return nil, fmt.Errorf("insert detection: %w", err)
	}
	id, _ := res.LastInsertId()
	return &Detection{ID: id, RuleID: ruleID, SessionID: &sessionID, SourceIP: sourceIP, Severity: severity, Confidence: confidence, Description: description, MITRE: mitre, CreatedAt: time.Now().UTC()}, nil
}

const listDetectionsSQL = `SELECT id, rule_id, session_id, source_ip, severity, confidence, description, mitre_json, created_at FROM detections ORDER BY created_at DESC LIMIT ? OFFSET ?`

func (r *DetectionRepository) List(ctx context.Context, limit, offset int) ([]*Detection, error) {
	stmt, err := r.db.PrepareContext(ctx, listDetectionsSQL)
	if err != nil {
		return nil, fmt.Errorf("prepare list detections: %w", err)
	}
	defer stmt.Close()
	rows, err := stmt.QueryContext(ctx, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("query detections: %w", err)
	}
	defer rows.Close()
	var out []*Detection
	for rows.Next() {
		var d Detection
		var sessionID, mitreJSON, createdAt string
		if err := rows.Scan(&d.ID, &d.RuleID, &sessionID, &d.SourceIP, &d.Severity, &d.Confidence, &d.Description, &mitreJSON, &createdAt); err != nil {
			return nil, fmt.Errorf("scan detection: %w", err)
		}
		if sessionID != "" {
			d.SessionID = &sessionID
		}
		json.Unmarshal([]byte(mitreJSON), &d.MITRE)
		d.CreatedAt, _ = time.Parse(time.RFC3339Nano, createdAt)
		out = append(out, &d)
	}
	return out, rows.Err()
}
