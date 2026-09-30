# VYRA - Backend Services & API Engine

> Production-oriented Flask REST API for IoT device management, telemetry ingestion, authentication, and application data services.

[![Python](https://img.shields.io/badge/Python-3.8%2B-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![Flask](https://img.shields.io/badge/Flask-2.x-000000?logo=flask&logoColor=white)](https://flask.palletsprojects.com/)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-14%2B-4169E1?logo=postgresql&logoColor=white)](https://www.postgresql.org/)
[![SQLAlchemy](https://img.shields.io/badge/SQLAlchemy-ORM-D71F00)](https://www.sqlalchemy.org/)
[![Build](https://img.shields.io/github/actions/workflow/status/Aathisivansk/Vyra/ci.yml?label=build&logo=github)](https://github.com/Aathisivansk/Vyra/actions)
[![Tests](https://img.shields.io/badge/tests-pytest-0A9EDC?logo=pytest)](https://docs.pytest.org/)
[![License](https://img.shields.io/badge/license-MIT-yellow.svg)](LICENSE)

## System Overview

VYRA is the backend service layer for an IoT-enabled system. It provides a versioned REST API through which edge devices, operators, and client applications can authenticate, register devices, submit telemetry, query historical data, and manage application resources.

The service is designed around Flask's **Application Factory** pattern with Flask-SQLAlchemy for relational persistence and Flask-Migrate/Alembic for controlled schema evolution.

### Core capabilities

- Concurrent telemetry ingestion from IoT edge nodes and client applications.
- Device registration, ownership, status, and lifecycle management.
- Relational mapping between users, devices, telemetry records, and audit events.
- Password hashing with Werkzeug and token/session-based authentication.
- Role-aware API access for administrative and standard users.
- Versioned API routes under `/api/v1`.
- Transactional PostgreSQL persistence with indexes for time-series access patterns.
- Repeatable database migrations using Flask-Migrate and Alembic.
- Environment-isolated configuration for development, testing, and production.

## Architecture and Data Flow

```mermaid
flowchart LR
    D[IoT Edge Nodes / Devices]
    C[Web and Mobile Clients]
    G[Reverse Proxy / Load Balancer]
    A[Flask REST API\nApplication Factory]
    W[Gunicorn Workers]
    DB[(PostgreSQL)]
    M[Flask-Migrate / Alembic]
    O[Observability and Audit Logs]

    D -->|Telemetry and device events| G
    C -->|HTTPS REST requests| G
    G --> W
    W --> A
    A -->|SQLAlchemy transactions| DB
    M -->|Versioned schema changes| DB
    A --> O
```

At a high level:

1. Devices and client applications send HTTPS requests to the API.
2. A reverse proxy terminates TLS and forwards traffic to Gunicorn.
3. Gunicorn runs multiple Flask workers created by `create_app()`.
4. Route handlers validate authentication and request data before invoking service/model logic.
5. SQLAlchemy persists application data and telemetry in PostgreSQL.
6. Alembic migrations update the schema independently of application startup.
7. Audit and operational events are retained for traceability and troubleshooting.

### Application layout

- **Routes / blueprints**: HTTP methods, URL registration, authentication guards, and response formatting.
- **Schemas / validators**: Request validation, serialization, and response contracts.
- **Services**: Business rules, telemetry ingestion workflows, authorization decisions, and transactions.
- **Models**: SQLAlchemy entities and relationships.
- **Configuration**: Environment-specific settings and secret loading.
- **Migrations**: Alembic revision history for PostgreSQL schema changes.
- **Tests**: Unit, integration, API, and migration coverage.

## Data Model

The following entities represent the expected core domain model. Keep model names and fields aligned with the implementation when adding or changing endpoints.

| Entity | Purpose | Typical relationships |
|---|---|---|
| `User` | Authenticated human or service account. | Owns devices; creates audit events; has one or more roles. |
| `Role` | Authorization grouping for administrator, operator, or read-only access. | Many-to-many or one-to-many relationship with users, depending on implementation. |
| `Device` | Registered IoT edge node and its metadata. | Belongs to a user/tenant; produces telemetry and device events. |
| `Telemetry` / `SensorLog` | Timestamped sensor readings and ingestion metadata. | Belongs to a device; indexed by device and event timestamp. |
| `AuditLog` | Security and administrative activity record. | References a user, device, request, or affected resource. |
| `RefreshToken` or session record | Optional persistent token/session state. | Belongs to a user and supports revocation and expiry. |

### Persistence and indexing guidance

Telemetry tables should use indexes appropriate to the query workload, especially:

- `(device_id, recorded_at)` for recent-device queries.
- `recorded_at` for time-window analytics and retention jobs.
- A unique device identifier such as `device_uid`.
- Foreign-key indexes for user/device ownership and audit lookups.

For high-volume deployments, consider PostgreSQL partitioning, retention policies, batch inserts, connection pooling, and asynchronous ingestion. These changes should be introduced through reviewed migrations and load-tested before production rollout.

### Migration management

Flask-Migrate wraps Alembic and records schema changes as versioned revisions. Migrations are source-controlled and must be applied in every environment before the corresponding application code is deployed.

```bash
# First-time setup only
flask db init

# Generate a revision after changing SQLAlchemy models
flask db migrate -m "describe schema change"

# Review the generated revision, then apply it
flask db upgrade

# Inspect current migration state
flask db current
flask db history
```

Do not edit an already-applied migration in place. Create a new revision for corrective changes.

## API Reference

The API is versioned under `/api/v1`. JSON requests should use `Content-Type: application/json`; protected endpoints require the configured authentication mechanism, normally a bearer JWT or authenticated session.

> The tables below define the intended public contract. Confirm exact field names and response envelopes against the route and schema implementation before publishing a client SDK.

### Authentication: `/api/v1/auth`

| Method | Route | Auth required | Request payload | Description | Response codes |
|---|---|---:|---|---|---|
| `POST` | `/api/v1/auth/register` | No | `{ "email": "user@example.com", "password": "...", "name": "..." }` | Create a user account. | `201`, `400`, `409` |
| `POST` | `/api/v1/auth/login` | No | `{ "email": "user@example.com", "password": "..." }` | Authenticate a user and issue a JWT or session. | `200`, `400`, `401` |
| `POST` | `/api/v1/auth/refresh` | Yes | `{ "refresh_token": "..." }` or refresh cookie | Issue a new access token. | `200`, `401` |
| `POST` | `/api/v1/auth/logout` | Yes | None or token revocation payload | End the current session or revoke a token. | `200`, `204`, `401` |
| `GET` | `/api/v1/auth/me` | Yes | None | Return the authenticated user's profile and roles. | `200`, `401` |
| `PATCH` | `/api/v1/auth/me` | Yes | `{ "name": "Updated name" }` | Update the authenticated user's profile. | `200`, `400`, `401` |

### Devices and telemetry ingestion: `/api/v1/devices`

| Method | Route | Auth required | Request payload | Description | Response codes |
|---|---|---:|---|---|---|
| `GET` | `/api/v1/devices` | Yes | Query: `page`, `limit`, `status` | List devices visible to the authenticated principal. | `200`, `401`, `403` |
| `POST` | `/api/v1/devices` | Yes | `{ "device_uid": "edge-001", "name": "Boiler sensor", "metadata": {} }` | Register a device. | `201`, `400`, `401`, `409` |
| `GET` | `/api/v1/devices/{device_id}` | Yes | None | Retrieve device metadata and current status. | `200`, `401`, `403`, `404` |
| `PATCH` | `/api/v1/devices/{device_id}` | Yes | `{ "name": "Updated name", "status": "active" }` | Update device metadata or lifecycle state. | `200`, `400`, `401`, `403`, `404` |
| `DELETE` | `/api/v1/devices/{device_id}` | Yes | None | Remove or deactivate a device according to retention policy. | `204`, `401`, `403`, `404` |
| `POST` | `/api/v1/devices/{device_id}/telemetry` | Yes | `{ "recorded_at": "2026-09-30T12:00:00Z", "readings": { "temperature": 21.4, "humidity": 47.2 } }` | Ingest one telemetry event. | `201`, `400`, `401`, `403`, `404`, `409` |
| `POST` | `/api/v1/devices/{device_id}/telemetry/batch` | Yes | `{ "events": [{ "recorded_at": "...", "readings": {} }] }` | Ingest multiple telemetry events atomically or with per-item results. | `201`, `207`, `400`, `401`, `403`, `404` |

### Analytics and telemetry queries: `/api/v1/telemetry`

| Method | Route | Auth required | Request payload | Description | Response codes |
|---|---|---:|---|---|---|
| `GET` | `/api/v1/telemetry` | Yes | Query: `device_id`, `from`, `to`, `metric`, `page`, `limit` | Query telemetry for authorized devices within a time range. | `200`, `400`, `401`, `403` |
| `GET` | `/api/v1/telemetry/{telemetry_id}` | Yes | None | Retrieve one telemetry record. | `200`, `401`, `403`, `404` |
| `GET` | `/api/v1/telemetry/summary` | Yes | Query: `device_id`, `from`, `to`, `interval` | Return aggregate statistics for a time window. | `200`, `400`, `401`, `403` |
| `GET` | `/api/v1/telemetry/latest/{device_id}` | Yes | None | Return the latest known reading for a device. | `200`, `401`, `403`, `404` |

### Authentication and response conventions

- Send access tokens with `Authorization: Bearer <token>` when JWT authentication is enabled.
- Use UTC timestamps in ISO 8601 format, for example `2026-09-30T12:00:00Z`.
- Never return password hashes, secret keys, refresh-token material, or database credentials.
- Use consistent JSON errors, for example:

```json
{
  "error": {
    "code": "validation_error",
    "message": "The request payload is invalid.",
    "details": {
      "device_uid": "This field is required."
    },
    "request_id": "4c5d..."
  }
}
```

## Environment Configuration

Create a local `.env` file for development. Do not commit it. Production secrets should be injected by the deployment platform or a dedicated secret manager.

| Variable | Type | Default / example | Description |
|---|---|---|---|
| `FLASK_APP` | string | `app:create_app()` | Flask application import path used by the CLI. |
| `FLASK_ENV` | string | `development` | Runtime environment. Use `production` outside local development. |
| `FLASK_DEBUG` | boolean | `0` | Enables Flask debug behavior. Must be disabled in production. |
| `DATABASE_URL` | URL | `postgresql://postgres:password@localhost:5432/vyra` | PostgreSQL connection string. Use a TLS-enabled URL in production where required. |
| `DB_POOL_SIZE` | integer | `5` | SQLAlchemy connection-pool size. Tune for worker count and PostgreSQL limits. |
| `DB_MAX_OVERFLOW` | integer | `10` | Additional temporary connections allowed above the pool size. |
| `SECRET_KEY` | string | generated 64-character hex value | Flask session signing and application cryptographic secret. |
| `JWT_SECRET_KEY` | string | separate generated 64-character hex value | JWT signing secret. Do not reuse public or database credentials. |
| `JWT_ACCESS_TOKEN_EXPIRES` | integer/string | `3600` | Access-token lifetime in seconds or the format supported by the JWT extension. |
| `JWT_REFRESH_TOKEN_EXPIRES` | integer/string | `2592000` | Refresh-token lifetime in seconds or supported duration format. |
| `CORS_ORIGINS` | comma-separated string | `http://localhost:3000` | Explicitly allowed browser origins. Avoid `*` when credentials are enabled. |
| `SESSION_COOKIE_SECURE` | boolean | `0` locally, `1` in production | Sends session cookies only over HTTPS. |
| `SESSION_COOKIE_HTTPONLY` | boolean | `1` | Prevents browser JavaScript from reading session cookies. |
| `SESSION_COOKIE_SAMESITE` | string | `Lax` | SameSite policy for session cookies. |
| `LOG_LEVEL` | string | `INFO` | Application log level. |
| `JSON_SORT_KEYS` | boolean | `0` | Controls JSON key ordering if supported by the Flask configuration. |
| `RATELIMIT_DEFAULT` | string | `200 per day;50 per hour` | Default request rate limit when Flask-Limiter is enabled. |
| `SENTRY_DSN` | URL | empty | Optional error-monitoring DSN. |
| `TEST_DATABASE_URL` | URL | `postgresql://.../vyra_test` | Isolated database used by integration tests. |

### Generate permanent secrets

The current development pattern may generate a session key at startup. That invalidates sessions whenever the process restarts and is not suitable for production. Generate stable secrets once and store them in a secret manager or protected environment configuration:

```bash
python -c "import secrets; print(secrets.token_hex(32))"
```

Run the command separately for `SECRET_KEY` and `JWT_SECRET_KEY`, then add the resulting values to the deployment environment. Never place real secrets in source control, issue comments, logs, Docker images, or client-side code.

Example local `.env` file:

```dotenv
FLASK_APP=app:create_app()
FLASK_ENV=development
FLASK_DEBUG=1
DATABASE_URL=postgresql://postgres:your_password@localhost:5432/vyra
SECRET_KEY=replace_with_a_generated_value
JWT_SECRET_KEY=replace_with_a_different_generated_value
CORS_ORIGINS=http://localhost:3000
```

## Local Development Runbook

### Prerequisites

- Python 3.8 or newer.
- PostgreSQL 14 or newer.
- Git.
- Optional: Docker and Docker Compose for containerized dependencies.

### Clone and create a virtual environment

#### Linux / macOS

```bash
git clone https://github.com/Aathisivansk/Vyra.git
cd Vyra
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
```

#### Windows PowerShell

```powershell
git clone https://github.com/Aathisivansk/Vyra.git
Set-Location Vyra
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
```

If PowerShell blocks activation, adjust the execution policy for the current user according to your workstation security policy, or invoke the environment's Python executable directly.

### Provision PostgreSQL

Create a dedicated database and role rather than using a superuser in shared or production environments.

```sql
CREATE USER vyra_app WITH PASSWORD 'replace_this_password';
CREATE DATABASE vyra OWNER vyra_app;
```

Set the connection string in `.env`:

```dotenv
DATABASE_URL=postgresql://vyra_app:replace_this_password@localhost:5432/vyra
```

### Initialize and apply migrations

Run these commands from the repository root with the virtual environment active:

```bash
flask db init                    # First project setup only, if migrations/ is absent
flask db migrate -m "initial schema"  # Generate a revision from model metadata
flask db upgrade                 # Apply revisions to the configured database
```

On Windows PowerShell, the same commands are used:

```powershell
flask db init
flask db migrate -m "initial schema"
flask db upgrade
```

Review generated migration files before applying them. Do not use `db.create_all()` as a substitute for migrations in deployed environments.

### Run locally

```bash
flask run --host 127.0.0.1 --port 5000
```

```powershell
flask run --host 127.0.0.1 --port 5000
```

The API is then available at `http://127.0.0.1:5000`. Bind to `0.0.0.0` only when access from another container or host is required.

## Production Deployment

Use a process manager and a production WSGI server. A representative Gunicorn command is:

```bash
gunicorn -w 4 -b 0.0.0.0:5000 "app:create_app()"
```

Recommended production controls:

- Terminate TLS at a reverse proxy or load balancer.
- Set `FLASK_ENV=production` and disable debug mode.
- Inject `SECRET_KEY`, `JWT_SECRET_KEY`, and `DATABASE_URL` from a secret manager.
- Run `flask db upgrade` as an explicit release step before starting new workers.
- Configure PostgreSQL backups, monitoring, connection limits, and least-privilege credentials.
- Use structured logs and propagate a request/correlation ID.
- Configure health and readiness endpoints without exposing secrets or database details.
- Apply rate limits and payload-size limits to authentication and telemetry endpoints.
- Scale Gunicorn workers based on CPU, memory, database capacity, and observed latency; four workers are only a starting point.

### Docker / Docker Compose option

A containerized deployment commonly includes:

- An API container built from a pinned Python base image.
- A PostgreSQL service using a named volume for local development.
- An environment file or secret store for connection credentials.
- A startup/release command that runs migrations before the API becomes ready.
- A health check that verifies application readiness without leaking internal errors.

Do not use the development Flask server as the production container process. Pin image and Python dependency versions, run as a non-root user, and keep PostgreSQL data outside the disposable API container filesystem.

## Repository Structure

A production-oriented layout is:

```text
Vyra/
├── app/
│   ├── __init__.py          # create_app(), extension initialization
│   ├── extensions.py        # db, migrate, jwt, session, and other extensions
│   ├── models/              # SQLAlchemy models and relationships
│   ├── routes/              # Flask blueprints and HTTP handlers
│   ├── schemas/             # Request validation and response serialization
│   ├── services/             # Business logic and transaction workflows
│   ├── errors.py             # API exception and error response handlers
│   └── utils/                # Shared helpers and security utilities
├── migrations/               # Flask-Migrate/Alembic revisions
├── tests/
│   ├── unit/
│   ├── integration/
│   └── conftest.py
├── config.py                 # Development, testing, and production config
├── run.py                    # Optional direct application entry point
├── requirements.txt          # Runtime and development dependencies
├── .env.example              # Safe configuration template; no secrets
├── .gitignore
└── README.md
```

The exact structure may differ in the current implementation. Preserve the application-factory boundary and keep route handlers thin as the codebase grows.

## Testing and Code Quality

Run the test suite against an isolated test database:

```bash
pytest
pytest -q
pytest --cov=app --cov-report=term-missing
```

```powershell
pytest
pytest -q
pytest --cov=app --cov-report=term-missing
```

Recommended formatting and static checks:

```bash
black .
flake8 .
```

```powershell
black .
flake8 .
```

Before opening a pull request:

1. Add or update tests for changed routes, models, authorization, and migrations.
2. Run the complete test suite against PostgreSQL, not only an in-memory substitute.
3. Review generated migration SQL and test upgrade behavior from the previous revision.
4. Run formatting and lint checks.
5. Confirm no `.env`, credentials, tokens, or production data are included in the diff.

## Security and Operations Checklist

- Use HTTPS for all non-local traffic.
- Hash passwords with Werkzeug's current password-hashing helpers; never store plaintext passwords.
- Use separate, high-entropy `SECRET_KEY` and `JWT_SECRET_KEY` values.
- Validate and limit telemetry payload size and timestamp ranges.
- Enforce authorization at the resource level, not only at the route level.
- Use parameterized SQL through SQLAlchemy; never concatenate user input into SQL.
- Protect login and ingestion endpoints with rate limits appropriate to the deployment.
- Redact authorization headers, passwords, tokens, and connection strings from logs.
- Rotate credentials through the deployment platform and revoke compromised tokens.
- Monitor database saturation, migration failures, request latency, error rates, and ingestion lag.

## Contributing and Maintenance

Changes to public routes, request payloads, response formats, models, or environment variables are API changes. Document them in this README, add regression tests, and include a migration when the database schema changes.

Pull requests should include:

- A concise problem statement and implementation summary.
- Test and migration results.
- Security impact, if applicable.
- Any deployment or environment-variable changes.

## License

VYRA is distributed under the MIT License. See [LICENSE](LICENSE) for the full license text.

Copyright belongs to the project contributors and the repository owner as applicable.
