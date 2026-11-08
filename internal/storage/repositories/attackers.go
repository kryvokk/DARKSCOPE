package repositories

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"
)

type AttackerRepository struct {
	db *sql.DB
}

func NewAttackerRepository(db *sql.DB) *AttackerRepository {
	return &AttackerRepository{db: db}
}

// Attacker — профиль источника активности.
type Attacker struct {
	ID           int64
	IP           string
	FirstSeen    time.Time
	LastSeen     time.Time
	TotalEvents  int
	TotalSessions int
	RiskScore    float64
	Metadata     map[string]interface{}
}

const insertAttackerSQL = `INSERT INTO attackers (ip, first_seen, last_seen, total_events, total_sessions, risk_score, metadata_json) VALUES (?, ?, ?, ?, ?, ?, ?)`

const updateAttackerSQL = `UPDATE attackers SET last_seen = ?, total_events = ?, total_sessions = ?, risk_score = ?, metadata_json = ? WHERE ip = ?`

// Upsert вставляет новую запись атакующего или обновляет существующую по IP.
func (r *AttackerRepository) Upsert(ctx context.Context, ip string, firstSeen, lastSeen time.Time, totalEvents, totalSessions int, riskScore float64, metadata map[string]interface{}) error {
	metadataJSON, _ := json.Marshal(metadata)

	stmt, err := r.db.PrepareContext(ctx, insertAttackerSQL)
	if err != nil {
		return fmt.Errorf("prepare insert attacker: %w", err)
	}
	_, err = stmt.ExecContext(ctx, ip, firstSeen.Format(time.RFC3339Nano), lastSeen.Format(time.RFC3339Nano), totalEvents, totalSessions, riskScore, string(metadataJSON))
	stmt.Close()
	if err == nil {
		return nil
	}

	updStmt, err := r.db.PrepareContext(ctx, updateAttackerSQL)
	if err != nil {
		return fmt.Errorf("prepare update attacker: %w", err)
	}
	defer updStmt.Close()
	_, err = updStmt.ExecContext(ctx, lastSeen.Format(time.RFC3339Nano), totalEvents, totalSessions, riskScore, string(metadataJSON), ip)
	if err != nil {
		return fmt.Errorf("update attacker: %w", err)
	}
	return nil
}

const getAttackerSQL = `SELECT id, ip, first_seen, last_seen, total_events, total_sessions, risk_score, metadata_json FROM attackers WHERE ip = ?`

func (r *AttackerRepository) Get(ctx context.Context, ip string) (*Attacker, error) {
	stmt, err := r.db.PrepareContext(ctx, getAttackerSQL)
	if err != nil {
		return nil, fmt.Errorf("prepare get attacker: %w", err)
	}
	defer stmt.Close()
	var a Attacker
	var metadataJSON string
	var firstSeen, lastSeen string
	err = stmt.QueryRowContext(ctx, ip).Scan(&a.ID, &a.IP, &firstSeen, &lastSeen, &a.TotalEvents, &a.TotalSessions, &a.RiskScore, &metadataJSON)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("attacker %s not found: %w", ip, err)
		}
		return nil, fmt.Errorf("scan attacker: %w", err)
	}
	a.FirstSeen, _ = time.Parse(time.RFC3339Nano, firstSeen)
	a.LastSeen, _ = time.Parse(time.RFC3339Nano, lastSeen)
	if metadataJSON != "" {
		json.Unmarshal([]byte(metadataJSON), &a.Metadata)
	}
	return &a, nil
}

const listAttackersSQL = `SELECT ip, first_seen, last_seen, total_events, total_sessions, risk_score FROM attackers ORDER BY risk_score DESC, last_seen DESC LIMIT ? OFFSET ?`

func (r *AttackerRepository) List(ctx context.Context, limit, offset int) ([]*Attacker, error) {
	stmt, err := r.db.PrepareContext(ctx, listAttackersSQL)
	if err != nil {
		return nil, fmt.Errorf("prepare list attackers: %w", err)
	}
	defer stmt.Close()
	rows, err := stmt.QueryContext(ctx, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("query attackers: %w", err)
	}
	defer rows.Close()
	var out []*Attacker
	for rows.Next() {
		var a Attacker
		var firstSeen, lastSeen string
		if err := rows.Scan(&a.IP, &firstSeen, &lastSeen, &a.TotalEvents, &a.TotalSessions, &a.RiskScore); err != nil {
			return nil, fmt.Errorf("scan attacker: %w", err)
		}
		a.FirstSeen, _ = time.Parse(time.RFC3339Nano, firstSeen)
		a.LastSeen, _ = time.Parse(time.RFC3339Nano, lastSeen)
		out = append(out, &a)
	}
	return out, rows.Err()
}
