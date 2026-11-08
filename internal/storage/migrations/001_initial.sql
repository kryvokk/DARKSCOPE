-- DARKSCOPE — схема базы данных (версия 1)

-- Таблица событий
CREATE TABLE IF NOT EXISTS events (
    id TEXT PRIMARY KEY,
    timestamp TEXT NOT NULL,
    session_id TEXT NOT NULL,
    source_ip TEXT NOT NULL,
    source_port INTEGER NOT NULL,
    dest_ip TEXT NOT NULL,
    dest_port INTEGER NOT NULL,
    protocol TEXT NOT NULL,
    service TEXT NOT NULL,
    event_type TEXT NOT NULL,
    payload TEXT,
    severity TEXT,
    confidence REAL,
    mitre_json TEXT,
    metadata_json TEXT
);

-- Таблица сессий
CREATE TABLE IF NOT EXISTS sessions (
    id TEXT PRIMARY KEY,
    source_ip TEXT NOT NULL,
    source_port INTEGER NOT NULL,
    protocol TEXT NOT NULL,
    started_at TEXT NOT NULL,
    ended_at TEXT,
    event_count INTEGER DEFAULT 0,
    status TEXT NOT NULL
);

-- Таблица профилей атакующих
CREATE TABLE IF NOT EXISTS attackers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip TEXT UNIQUE NOT NULL,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    total_events INTEGER DEFAULT 0,
    total_sessions INTEGER DEFAULT 0,
    risk_score REAL DEFAULT 0,
    metadata_json TEXT
);

-- Таблица срабатываний детектора
CREATE TABLE IF NOT EXISTS detections (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_id TEXT NOT NULL,
    session_id TEXT,
    source_ip TEXT NOT NULL,
    severity TEXT NOT NULL,
    confidence REAL NOT NULL,
    description TEXT NOT NULL,
    mitre_json TEXT,
    created_at TEXT NOT NULL
);

-- Таблица захваченных файлов
CREATE TABLE IF NOT EXISTS files (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT,
    source_ip TEXT NOT NULL,
    filename TEXT NOT NULL,
    size INTEGER NOT NULL,
    sha256 TEXT NOT NULL,
    stored_path TEXT NOT NULL,
    created_at TEXT NOT NULL
);

-- Таблица honeytokens
CREATE TABLE IF NOT EXISTS honeytokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    token_name TEXT NOT NULL,
    token_type TEXT NOT NULL,
    created_at TEXT NOT NULL
);

-- Таблица алертов
CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id TEXT,
    channel TEXT NOT NULL,
    status TEXT NOT NULL,
    created_at TEXT NOT NULL
);

-- Индексы (по ТЗ раздел 5)
CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);
CREATE INDEX IF NOT EXISTS idx_events_source_ip ON events(source_ip);
CREATE INDEX IF NOT EXISTS idx_events_session_id ON events(session_id);
CREATE INDEX IF NOT EXISTS idx_sessions_source_ip ON sessions(source_ip);
CREATE INDEX IF NOT EXISTS idx_detections_created_at ON detections(created_at);
CREATE INDEX IF NOT EXISTS idx_files_sha256 ON files(sha256);

-- Версия схемы для миграций
CREATE TABLE IF NOT EXISTS schema_migrations (
    version INTEGER PRIMARY KEY
);
