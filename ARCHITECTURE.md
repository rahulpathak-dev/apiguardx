# APIGuardX Architecture

APIGuardX is an enterprise API security scanner and reporting platform for authorized, low-risk assessment of REST APIs. The system is designed as a modular full-stack application with a Next.js frontend, FastAPI backend, PostgreSQL persistence layer, scanner service, PDF reporting pipeline, Docker deployment, and CI/CD scan support.

## Architecture Goals

- Keep scanning passive or low-risk and authorization-gated.
- Separate UI, API, scanner, persistence, and reporting concerns.
- Make scanner checks independently testable and extensible.
- Support multi-user scan history with strong ownership checks.
- Use production-oriented security defaults: JWT auth, validation, CORS restrictions, password hashing, least-privilege APIs, environment-based config, and structured logging.
- Provide a clean resume-level project structure that can grow into background jobs, queues, and team/organization features.

## High-Level System

```text
User Browser
   |
   | HTTPS
   v
Next.js Frontend
   |
   | JWT Bearer API calls
   v
FastAPI Backend
   |
   | SQLAlchemy ORM
   v
PostgreSQL

FastAPI Backend
   |
   | low-risk HTTPX requests
   v
Authorized Target APIs

FastAPI Backend
   |
   | ReportLab
   v
PDF Security Reports

GitHub Actions
   |
   | APIGuardX CLI scan
   v
Authorized CI Target API
```

## Frontend Architecture: Next.js

The frontend is a dashboard-first Next.js application using TypeScript, Tailwind CSS, Recharts, and reusable UI components.

### Responsibilities

- User registration and login.
- JWT token storage and authenticated API calls.
- Protected dashboard access.
- API target creation with explicit authorization acknowledgment.
- Endpoint management.
- Scan execution and status display.
- Scan history and finding visualization.
- Risk analytics using Recharts.
- PDF report download.

### Recommended Structure

```text
frontend/
  src/
    app/
      layout.tsx                  Root layout and global metadata
      page.tsx                    Redirects to dashboard
      globals.css                 Tailwind and global styles
      login/
        page.tsx                  Login form
      register/
        page.tsx                  Registration form
      dashboard/
        page.tsx                  Main protected scanner dashboard
    components/
      Button.tsx                  Reusable button variants
      Input.tsx                   Reusable validated input wrapper
      Shell.tsx                   Authenticated app shell
      MetricCard.tsx              Dashboard metrics
      SeverityBadge.tsx           Finding severity UI
      ScanHistory.tsx             Scan list and report links
      EndpointTable.tsx           Endpoint selection and management
    lib/
      api.ts                      Typed API client and token helpers
      auth.ts                     Auth route guards and logout helpers
      formatting.ts               Date, score, and severity formatting
      validators.ts               Client-side validation helpers
```

### Frontend Security

- Store only the access token client-side; never store passwords or secrets.
- Use HTTPS in production.
- Keep privileged decisions on the backend.
- Treat all backend responses as untrusted and render text safely.
- Require explicit authorization acknowledgment before target creation.
- Avoid exposing scanner internals that would enable harmful testing.

## Backend Architecture: FastAPI

The backend owns authentication, authorization, validation, scan orchestration, persistence, analytics, and report generation.

### API Layers

```text
FastAPI Routers
   |
   v
Dependencies and Auth Guards
   |
   v
Service Layer
   |
   v
Scanner / Reports / Database Repositories
   |
   v
SQLAlchemy + PostgreSQL
```

### Responsibilities

- Register and authenticate users.
- Hash passwords using a dedicated password hashing context.
- Issue and validate JWTs.
- Enforce ownership checks on targets, endpoints, scans, and reports.
- Validate all request payloads with Pydantic schemas.
- Run low-risk scanner checks.
- Calculate severity and total risk score.
- Persist scan history and findings.
- Generate analytics.
- Generate PDF reports.
- Provide a CLI entry point for CI/CD scans.

### Recommended Structure

```text
backend/
  app/
    main.py                       FastAPI app factory, middleware, routers
    cli.py                        CI/CD scanner CLI
    models.py                     SQLAlchemy database models
    schemas.py                    Pydantic request/response schemas
    api/
      deps.py                     Auth and database dependencies
      routes/
        auth.py                   Register, login, current user
        targets.py                API target management
        endpoints.py              Endpoint management
        scans.py                  Scan execution, history, analytics
        reports.py                PDF report download
    core/
      config.py                   Environment-based settings
      security.py                 JWT and password hashing
      logging.py                  Logging setup
      errors.py                   Shared exception mapping
    db/
      session.py                  Engine, session, base model
      migrations/                 Alembic migrations for production growth
    scanner/
      checks.py                   Individual security checks
      service.py                  Scan orchestration
      http_client.py              HTTPX client configuration
      scoring.py                  Severity and risk scoring
      types.py                    Scanner DTOs
    reports/
      pdf.py                      PDF rendering
      templates/                  Future report templates
    repositories/
      targets.py                  Optional data-access isolation
      scans.py
      findings.py
  tests/
    test_auth.py
    test_scanner_checks.py
    test_targets.py
    test_reports.py
```

## PostgreSQL Database Design

The database stores users, authorized targets, endpoints, scans, and findings. Every user-owned object is reachable through ownership checks.

### Tables

```text
users
  id                 primary key
  email              unique, indexed
  full_name
  password_hash
  is_active
  created_at

api_targets
  id                 primary key
  owner_id           foreign key -> users.id, indexed
  name
  base_url
  authorization_ack
  created_at

endpoints
  id                 primary key
  target_id          foreign key -> api_targets.id, indexed
  method             GET, HEAD, OPTIONS
  path
  description
  created_at

scans
  id                 primary key
  target_id          foreign key -> api_targets.id, indexed
  status             pending, running, completed, failed
  total_risk_score   0-100
  summary
  created_at
  completed_at

findings
  id                 primary key
  scan_id            foreign key -> scans.id, indexed
  endpoint_path
  check_name
  severity           Low, Medium, High, Critical
  title
  evidence
  recommendation
```

### Future Production Extensions

```text
organizations
  id
  name
  created_at

memberships
  user_id
  organization_id
  role               owner, admin, analyst, viewer

scan_jobs
  id
  scan_id
  queue_status
  worker_id
  retry_count

audit_events
  id
  actor_user_id
  action
  entity_type
  entity_id
  ip_address
  created_at
```

## Scanner Service Architecture

The scanner is intentionally conservative. It sends low-volume, non-destructive requests to user-authorized APIs.

### Scanner Pipeline

```text
Target + Selected Endpoints
   |
   v
Authorization Acknowledgment Check
   |
   v
Safe HTTP Client
   |
   v
Response Snapshot
   |
   v
Independent Checks
   |
   v
Finding Drafts
   |
   v
Severity + Risk Score
   |
   v
Persist Scan + Findings
```

### Checks

- Missing authentication: unauthenticated safe request returns success.
- Unsafe CORS: wildcard origin and credentialed wildcard detection.
- Missing security headers: HSTS, CSP, frame options, content type options, referrer policy.
- Exposed stack traces: common framework, runtime, and database error signatures.
- Possible exposed secrets: high-confidence secret-like response patterns.
- Weak or missing rate limiting: no rate-limit headers or throttling signals during low-volume checks.

### Scanner Safety Controls

- Only safe methods: `GET`, `HEAD`, `OPTIONS`.
- No brute force, credential attacks, bypass payloads, destructive requests, exploit chaining, or data modification.
- Bounded timeout and response size.
- Low request volume.
- User-agent identifies APIGuardX.
- Scan requires explicit authorization acknowledgment.

### Scalable Scanner Evolution

For larger deployments, move scanning into workers:

```text
FastAPI
   |
   | enqueue scan job
   v
Redis / RabbitMQ
   |
   v
Scanner Worker Pool
   |
   v
Target APIs
   |
   v
PostgreSQL findings
```

Recommended worker options:

- Celery with Redis or RabbitMQ.
- RQ for simpler Redis-backed jobs.
- Dramatiq for lightweight worker processing.

## Authentication Flow

### Registration

```text
User submits email, name, password
   |
   v
FastAPI validates payload
   |
   v
Backend checks duplicate email
   |
   v
Password is hashed
   |
   v
User row is created
```

### Login

```text
User submits email and password
   |
   v
Backend loads user by email
   |
   v
Password hash is verified
   |
   v
JWT access token is issued
   |
   v
Frontend stores token and sends Authorization: Bearer <token>
```

### Protected Request

```text
Frontend sends JWT
   |
   v
FastAPI dependency decodes and validates JWT
   |
   v
Current user is loaded
   |
   v
Route enforces ownership check
   |
   v
Resource is returned or rejected
```

## Report Generation Flow

```text
User selects PDF report
   |
   v
GET /reports/{scan_id}.pdf with JWT
   |
   v
Backend validates JWT
   |
   v
Backend verifies scan ownership
   |
   v
Scan, target, and findings are loaded
   |
   v
ReportLab generates PDF in memory
   |
   v
PDF is returned as attachment
```

### Report Contents

- Product and report title.
- Target name and base URL.
- Scan ID, status, date, and risk score.
- Safety note confirming low-risk authorized scan.
- Finding table by severity.
- Evidence summary.
- Remediation recommendations.

## CI/CD Scan Flow

The CI/CD scanner supports authorized checks in deployment pipelines.

```text
GitHub Actions
   |
   v
Install backend dependencies
   |
   v
python -m app.cli scan --base-url $AUTHORIZED_API_BASE_URL --path /health
   |
   v
Low-risk HTTP request
   |
   v
Run scanner checks
   |
   v
Print risk score and findings
   |
   v
Fail pipeline on High or Critical findings
```

### CI/CD Use Cases

- Check staging API headers before release.
- Detect accidental debug error exposure.
- Detect unsafe CORS configuration drift.
- Prevent deployment when critical secret-like exposure is detected.

## Docker Deployment Architecture

```text
docker-compose.yml
   |
   |-- db
   |     image: postgres:16-alpine
   |     volume: postgres_data
   |     healthcheck: pg_isready
   |
   |-- backend
   |     build: backend/Dockerfile
   |     command: uvicorn app.main:app
   |     env: DATABASE_URL, JWT_SECRET_KEY, CORS origins
   |     depends_on: db healthy
   |
   |-- frontend
         build: frontend/Dockerfile
         command: node server.js
         env: NEXT_PUBLIC_API_URL
         depends_on: backend
```

### Production Deployment Pattern

```text
Internet
   |
   v
Load Balancer / Reverse Proxy with TLS
   |
   |-- Next.js frontend container
   |
   |-- FastAPI backend container
           |
           v
      Managed PostgreSQL
```

Recommended production improvements:

- Use managed PostgreSQL with backups.
- Store secrets in a secret manager.
- Add Alembic migrations.
- Add rate limiting to backend APIs.
- Add audit logging.
- Add worker queue for long scans.
- Restrict scanner egress to approved networks.
- Send application logs to a central logging system.

## Complete Folder Structure

```text
APIGuardX/
  README.md
  ARCHITECTURE.md
  DEPLOYMENT.md
  .env.example
  .gitignore
  docker-compose.yml
  pytest.ini

  .github/
    workflows/
      ci.yml

  backend/
    Dockerfile
    .dockerignore
    requirements.txt
    app/
      __init__.py
      main.py
      cli.py
      models.py
      schemas.py
      api/
        __init__.py
        deps.py
        routes/
          __init__.py
          auth.py
          targets.py
          endpoints.py
          scans.py
          reports.py
      core/
        config.py
        logging.py
        security.py
      db/
        session.py
      scanner/
        __init__.py
        checks.py
        service.py
      reports/
        __init__.py
        pdf.py
    tests/
      test_scanner_checks.py

  frontend/
    Dockerfile
    .dockerignore
    package.json
    next.config.mjs
    tsconfig.json
    tailwind.config.ts
    postcss.config.mjs
    .eslintrc.json
    public/
      .gitkeep
    src/
      app/
        layout.tsx
        page.tsx
        globals.css
        login/
          page.tsx
        register/
          page.tsx
        dashboard/
          page.tsx
      components/
        Button.tsx
        Input.tsx
        Shell.tsx
      lib/
        api.ts
```

## Resume-Level Highlights

- Full-stack TypeScript and Python architecture.
- Secure JWT authentication and protected resource ownership.
- PostgreSQL relational design with scan history and findings.
- Modular scanner engine with isolated checks and scoring.
- PDF security report generation.
- CI/CD scan command for release gates.
- Dockerized deployment with frontend, backend, and database.
- Professional dashboard with analytics and report export.
- Clear ethical boundary: authorized, passive, low-risk API security testing only.

