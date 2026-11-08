# DARKSCOPE — Modular Go Honeypot & Threat Intelligence Platform

Defensive security research tool на Go. Имитирует популярные сетевые сервисы
(SSH, HTTP, Telnet), собирает и анализирует поведение источников атак,
но никогда не предоставляет реальный доступ к операционной системе.

## Архитектура (Clean Architecture)

```
honeypot/
├── cmd/honeypot/          # точка входа (main.go)
├── internal/
│   ├── app/               # сборка приложения, graceful shutdown
│   ├── config/            # загрузка YAML + переменные окружения для секретов
│   ├── event/             # Event модель, Event Bus (отдельные очереди на подписчика)
│   ├── session/           # менеджер сессий (конкурентно-безопасный)
│   ├── storage/           # SQLite (WAL, foreign keys, миграции, репозитории)
│   └── storage/repositories/  # репозитории: events, sessions, attackers, detections, files, honeytokens, alerts
├── web/dashboard/         # React + TypeScript + Vite + Tailwind (планируется)
├── configs/config.example.yaml
├── deployments/           # Dockerfile, docker-compose.yml (планируется)
├── tests/
├── go.mod
└── README.md
```

## Стек

- **Go 1.24+** (тестировано на 1.27.3)
- `log/slog` — структурированное логирование
- `gopkg.in/yaml.v3` — парсинг конфигурации
- `modernc.org/sqlite` — чистый Go SQLite (без CGO)
- `crypto/rand` — генерация уникальных ID событий

## Быстрый старт

```bash
# Клонирование
git clone <repository>
cd DARKSCOPE

# Запуск с примером конфигурации
go run ./cmd/honeypot/ -config configs/config.example.yaml

# Сборка бинарника
go build -o honeypot ./cmd/honeypot/
./honeypot -config configs/config.example.yaml
```

## Конфигурация

Пример: `configs/config.example.yaml`. Все секретные значения (бот-токен Telegram,
chat-id, URL вебхука) загружаются **только** из переменных окружения — они не
хранятся в конфигурационном файле и не попадают в Git.

```yaml
listen:
  ssh: "0.0.0.0:2222"
  http: "0.0.0.0:8080"
  telnet: "0.0.0.0:2323"

storage:
  driver: sqlite
  path: "./data/honeypot.db"

event_bus:
  buffer_size: 1000
  workers: 4

detection:
  brute_force:
    enabled: true
    max_attempts: 20
    window_seconds: 60

alerts:
  telegram:
    enabled: false
    bot_token_env: TELEGRAM_BOT_TOKEN
    chat_id_env: TELEGRAM_CHAT_ID
  webhook:
    enabled: false
    url_env: WEBHOOK_URL

security:
  max_connections: 500
  max_request_body: 1048576
  enable_uploads: true
  outbound_network: false
```

## Event Bus

Все протоколы отправляют события в единую шину. Каждое событие доставляется
**независимо** всем трём подписчикам через отдельные буферизированные каналы:
Storage, Detection, Alert. Медленный подписчик не блокирует остальные.

- Буферизация с ограничением очереди
- Обработка переполнения (событие отбрасывается, не блокируя издателя)
- Метрики потерянных событий (`DroppedTotal`)
- Graceful shutdown: остановка приёма → дренаж очередей → ожидание обработчиков с таймаутом

## SQLite Storage

- **WAL mode** для конкурентного чтения/записи
- **Foreign keys** включены
- **Busy timeout** 5 секунд
- Пул соединений: `SetMaxOpenConns(1)`, `SetMaxIdleConns(1)`
- Все запросы через **prepared statements**
- Транзакционные, версионируемые и идемпотентные миграции (таблица `schema_migrations`)

Таблицы: `events`, `sessions`, `attackers`, `detections`, `files`, `honeytokens`, `alerts`.

Индексы: `events.timestamp`, `events.source_ip`, `events.session_id`, `sessions.source_ip`, `detections.created_at`, `files.sha256`.

## Session Tracking

Менеджер сессий отслеживает подключения в памяти с конкурентно-безопасным
доступом (sync.RWMutex). Хранит: ID, IP, порт, протокол, время начала/окончания,
длительность, количество событий, попыток входа, команд, статус.

## Protocol Collectors (Phase 2)

Все сборщики работают через общий Event Bus и Session Manager. Стандартные
порты: SSH `2222`, HTTP `8080`, Telnet `2323`; адреса и лимиты настраиваются в
`protocols` (пример — `configs/config.example.yaml`). События обработки
поступают в SQLite через Storage worker.

- **SSH:** принимает парольную аутентификацию как honeypot, сохраняет имя
  пользователя, длину пароля и версию клиента; пароль маскируется. Host key
  генерируется при создании сборщика либо читается по `host_key_path`.
  Для SSH доступен только виртуальный session channel; PTY и shell host отсутствуют.
- **HTTP:** обслуживает GET/POST без чтения файлов. События содержат путь,
  query, User-Agent, ограниченный набор заголовков и размер/SHA-256 тела.
  При превышении `max_body_size` возвращается 413, при превышении
  `max_headers` — 431. Размер заголовочного блока ограничен сервером. TLS
  включается только при задании обеих настроек `tls_cert_file` и
  `tls_key_file`.
- **Telnet:** показывает login/password prompts и записывает до трёх
  неуспешных попыток. Пароль маскируется, длина строки ограничена 256 байт,
  Telnet IAC negotiation удаляется. После credential prompts доступна только
  виртуальная оболочка.

Таймауты и `max_connections` ограничивают ресурсы. `X-Forwarded-For` не
используется для определения источника: адрес берётся из TCP-соединения.
Завершение останавливает сборщики и активные соединения до дренажа Event Bus.
Ограничение реализации: данные аутентификации SSH/Telnet предназначены для
анализа попыток; настоящая проверка учётных данных не выполняется.

## Виртуальная оболочка (Phase 3)

После honeypot-аутентификации SSH и Telnet предоставляют изолированную
виртуальную среду с отдельной файловой системой на сеанс. Команды проходят
через собственный parser и registry. Реализованы `pwd`, `cd`, `ls`, `tree`,
`cat`, `head`, `tail`, `touch`, `mkdir`, `rm`, `cp`, `mv`, `find`, `file`,
`stat`, `whoami`, `id`, `hostname`, `uname`, `date`, `env`, `history`, `ps`,
`top`, `df`, `free`, `mount`, `ip`, `ifconfig`, `ping`, `netstat`, `ss`,
`curl`, `wget`, `ssh`, `scp`, `help`, `man`, `echo`, `printf`, `grep`, `wc`,
`sort`, `uniq`, `which`. Сетевые команды возвращают симулированный результат.
Parser запрещает shell-операторы и command substitution; команды не запускают
процессы хоста.

Honeytoken-файлы содержат фиктивные значения. Их чтение создаёт
`honeytoken_access` event с session ID, путём и командой; Event Bus передаёт
событие в SQLite. Лимиты на сессию: команда 4 KiB, вывод 64 KiB, история 1000
строк, VFS 4096 узлов и 16 MiB данных.

## Безопасность

- Нет реального shell, нет `os/exec`, нет доступа к файловой системы
- Секреты только в переменных окружения
- SQLite хранилище с ограниченным пулом соединений
- Ограничение размера буфера шей событий (защита от роста памяти)

## Тестирование

```bash
# Все тесты
go test ./...

# Тесты с детектором гонок данных
go test -race ./...

# Ветеринарная проверка кода
go vet ./...

# Сборка всех пакетов
go build ./...
```

## Roadmap (квалификация по фазам)

- **Phase 1 (завершена):** Core Engine — конфигурация, Event модель, Event Bus,
  SQLite Storage, миграции, Session Manager, приложение с graceful shutdown.
- **Phase 2:** Protocol Collectors — SSH, HTTP, Telnet honeypots.
- **Phase 3:** Linux Emulation — виртуальная файловая система, shell эмулятор.
- **Phase 4:** Detection Engine — брутфорс, spraying, MITRE ATT&CK.
- **Phase 5:** Alerts & Intelligence — Telegram, webhook, AbuseIPDB.
- **Phase 6:** REST API & Dashboard — API v1, React панель.
- **Phase 7:** Production Hardening — Docker, non-root, лимиты ресурсов.

## Лицензия

Internal tool для defensive security research.
