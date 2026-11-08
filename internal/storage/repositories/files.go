package repositories

import (
	"context"
	"database/sql"
	"fmt"
	"time"

)

type FileRecord struct {
	ID int64
	SessionID *string
	SourceIP string
	Filename string
	Size int64
	SHA256 string
	StoredPath string
	CreatedAt time.Time
}

type FileRepository struct {
	db *sql.DB
}

func NewFileRepository(db *sql.DB) *FileRepository {
	return &FileRepository{db: db}
}

const insertFileSQL = `INSERT INTO files (session_id, source_ip, filename, size, sha256, stored_path, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)`

func (r *FileRepository) Insert(ctx context.Context, sessionID, sourceIP, filename, storedPath string, size int64, sha256 string) (*FileRecord, error) {
	stmt, err := r.db.PrepareContext(ctx, insertFileSQL)
	if err != nil {
		return nil, fmt.Errorf("prepare insert file: %w", err)
	}
	defer stmt.Close()
	var sessionIDI interface{} = sessionID
	res, err := stmt.ExecContext(ctx, sessionIDI, sourceIP, filename, size, sha256, storedPath, time.Now().UTC().Format(time.RFC3339Nano))
	if err != nil {
		return nil, fmt.Errorf("insert file: %w", err)
	}
	id, _ := res.LastInsertId()
	return &FileRecord{ID: id, SessionID: &sessionID, SourceIP: sourceIP, Filename: filename, Size: size, SHA256: sha256, StoredPath: storedPath, CreatedAt: time.Now().UTC()}, nil
}

const listFilesSQL = `SELECT id, session_id, source_ip, filename, size, sha256, stored_path, created_at FROM files ORDER BY created_at DESC LIMIT ? OFFSET ?`

func (r *FileRepository) List(ctx context.Context, limit, offset int) ([]*FileRecord, error) {
	stmt, err := r.db.PrepareContext(ctx, listFilesSQL)
	if err != nil {
		return nil, fmt.Errorf("prepare list files: %w", err)
	}
	defer stmt.Close()
	rows, err := stmt.QueryContext(ctx, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("query files: %w", err)
	}
	defer rows.Close()
	var out []*FileRecord
	for rows.Next() {
		var f FileRecord
		var sessionID, createdAt string
		if err := rows.Scan(&f.ID, &sessionID, &f.SourceIP, &f.Filename, &f.Size, &f.SHA256, &f.StoredPath, &createdAt); err != nil {
			return nil, fmt.Errorf("scan file: %w", err)
		}
		if sessionID != "" {
			f.SessionID = &sessionID
		}
		f.CreatedAt, _ = time.Parse(time.RFC3339Nano, createdAt)
		out = append(out, &f)
	}
	return out, rows.Err()
}

const getFileBySHA256SQL = `SELECT id, session_id, source_ip, filename, size, sha256, stored_path, created_at FROM files WHERE sha256 = ? LIMIT 1`

func (r *FileRepository) BySHA256(ctx context.Context, sha256 string) (*FileRecord, error) {
	stmt, err := r.db.PrepareContext(ctx, getFileBySHA256SQL)
	if err != nil {
		return nil, fmt.Errorf("prepare file by sha256: %w", err)
	}
	defer stmt.Close()
	var f FileRecord
	var sessionID, createdAt string
	if err := stmt.QueryRowContext(ctx, sha256).Scan(&f.ID, &sessionID, &f.SourceIP, &f.Filename, &f.Size, &f.SHA256, &f.StoredPath, &createdAt); err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("file %s not found: %w", sha256, err)
		}
		return nil, fmt.Errorf("scan file: %w", err)
	}
	if sessionID != "" {
		f.SessionID = &sessionID
	}
	f.CreatedAt, _ = time.Parse(time.RFC3339Nano, createdAt)
	return &f, nil
}
