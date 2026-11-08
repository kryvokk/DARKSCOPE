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

const upsertAttackerSQL = `INSERT INTO attackers (ip, first_seen, last_seen, total_events, total_sessions, risk_score, metadata_json) VALUES (?, ?, ?, ?, ?, ?, ?) ON CONFLICT(ip) DO UPDATE SET last_seen = excluded.last_seen, total_events = total_events + excluded.total_events, total_sessions = total_sessions + excluded.total_sessions, risk_score = excluded.risk_score, metadata_json = excluded.metadata_json`

func (r *AttackerRepository) Upsert(ctx context.Context, ip string, firstSeen, lastSeen time.Time, totalEvents, totalSessions int, riskScore float64, metadata map[string]interface{}) error {
	stmt, err := r.db.PrepareContext(ctx, upsertAttackerSQL)
	if err != nil {
		return fmt.Errorf("prepare upsert attacker: %w", err)
	}
	defer stmt.Close()
	metadataJSON, _ := json.Marshal(metadata)
	_, err = stmt.ExecContext(ctx, ip, firstSeen.Format(time.RFC3339Nano), lastSeen.Format(time.RFC3339Nano), totalEvents, totalSessions, riskScore, string(metadataJSON))
	if err != nil {
		return fmt.Errorf("upsert attacker: %w", err)
	}
	return nil
}

const getAttackerSQL = `SELECT id, ip, first_seen, last_seen, total_events, total_sessions, risk_score, metadata_json FROM attackers WHERE ip = ?`

func (r *AttackerRepository) Get(ctx context.Context, ip string) (map[string]interface{}, error) {
	stmt, err := r.db.PrepareContext(ctx, getAttackerSQL)
	if err != nil {
		return nil, fmt.Errorf("prepare get attacker: %w", err)
	}
	defer stmt.Close()
	var id, ipCol, firstSeen, lastSeen, metadataJSON string
	var totalEvents, totalSessions int
	var riskScore float64
	err = stmt.QueryRowContext(ctx, ip).Scan(&id, &ipCol, &firstSeen, &lastSeen, &totalEvents, &totalSessions, &riskScore, &metadataJSON)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("attacker %s not found: %w", ip, err)
		}
		return nil, fmt.Errorf("scan attacker: %w", err)
	}
	m := map[string]interface{}{}
	m["id"] = id
	m["ip"] = ipCol
	m["first_seen"] = firstSeen
	m["last_seen"] = lastSeen
	m["total_events"] = totalEvents
	m["total_sessions"] = totalSessions
	m["risk_score"] = riskScore
	json.Unmarshal([]byte(metadataJSON), &m)
	return m, nil
}

const listAttackersSQL = `SELECT ip, first_seen, last_seen, total_events, total_sessions, risk_score FROM attackers ORDER BY risk_score DESC, last_seen DESC LIMIT ? OFFSET ?`

func (r *AttackerRepository) List(ctx context.Context, limit, offset int) ([]map[string]interface{}, error) {
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
	var out []map[string]interface{}
	for rows.Next() {
		var ip, firstSeen, lastSeen string
		var totalEvents, totalSessions int
		var riskScore float64
		if err := rows.Scan(&ip, &firstSeen, &lastSeen, &totalEvents, &totalSessions, &riskScore); err != nil {
			return nil, fmt.Errorf("scan attacker: %w", err)
		}
		out = append(out, map[string]interface{}{
			"ip": ip, "first_seen": firstSeen, "last_seen": lastSeen,
			"total_events": totalEvents, "total_sessions": totalSessions,
			"risk_score": riskScore,
		})
	}
	return out, rows.Err()
}
