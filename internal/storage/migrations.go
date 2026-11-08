package storage

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

// migrationSQLPath возвращает абсолютный путь к файлу SQL-миграции,
// расположенного рядом с этим исходником.
func migrationSQLPath() string {
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		return "migrations/001_initial.sql"
	}
	return filepath.Join(filepath.Dir(filename), "migrations", "001_initial.sql")
}

// readMigrationSQL читает SQL инициализационной миграции.
func readMigrationSQL() (string, error) {
	data, err := os.ReadFile(migrationSQLPath())
	if err != nil {
		return "", fmt.Errorf("read migration sql: %w", err)
	}
	return string(data), nil
}

// Migrate применяет инициализационную миграцию в транзакции.
// Повторный запуск безопасен (проверка schema_migrations).
func (s *Storage) Migrate() error {
	sql, err := readMigrationSQL()
	if err != nil {
		return err
	}

	if _, err := s.db.ExecContext(context.Background(), "CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY)"); err != nil {
		return fmt.Errorf("ensure schema_migrations: %w", err)
	}

	var applied int
	err = s.db.QueryRowContext(context.Background(), "SELECT COUNT(*) FROM schema_migrations WHERE version = ?", 1).Scan(&applied)
	if err != nil {
		return fmt.Errorf("check migration: %w", err)
	}
	if applied > 0 {
		return nil
	}

	tx, err := s.db.BeginTx(context.Background(), nil)
	if err != nil {
		return fmt.Errorf("begin migration: %w", err)
	}
	if _, err := tx.ExecContext(context.Background(), sql); err != nil {
		tx.Rollback()
		return fmt.Errorf("apply migration: %w", err)
	}
	if _, err := tx.ExecContext(context.Background(), "INSERT INTO schema_migrations (version) VALUES (?)", 1); err != nil {
		tx.Rollback()
		return fmt.Errorf("record migration: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit migration: %w", err)
	}
	return nil
}
