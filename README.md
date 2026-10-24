# APIGuardX

Enterprise API Security Scanner and Risk Reporting Platform.

APIGuardX helps authorized teams run passive and low-risk checks against REST APIs they own or have written permission to assess. It stores scan history, calculates risk, renders dashboard analytics, and exports professional PDF reports.

## Safety Boundary

Use APIGuardX only on APIs you own or where you have written authorization. The scanner intentionally avoids destructive attacks, credential theft, brute force, bypass techniques, exploit chaining, and harmful payloads. Checks are limited to low-risk HTTP requests such as `GET` and `OPTIONS`.

## Stack

- Frontend: Next.js, TypeScript, Tailwind CSS, Recharts
- Backend: FastAPI, Python, SQLAlchemy, JWT auth
- Database: PostgreSQL
- Scanner: HTTPX
- Reports: ReportLab PDF generation
- Deployment: Docker, Docker Compose
- CI/CD: GitHub Actions

## Quick Start

1. Copy environment variables:

```bash
cp .env.example .env
```

2. Start the stack:

```bash
docker compose up --build
```

3. Open:

- Frontend: http://localhost:3000
- Backend API docs: http://localhost:8000/docs

## CI Scan

APIGuardX includes a CLI for authorized CI checks:

```bash
cd backend
python -m app.cli scan --base-url https://api.example.com --path /health
```

The CLI exits non-zero when high or critical findings are detected.
For hosted pipeline integration, generate a project-scoped CI/CD token and call the JSON scan endpoint:

- Endpoint: `POST /ci/scan`
- Token header: `X-APIGUARDX-TOKEN`
- Workflow example: `.github/workflows/apiguardx-ci-scan.yml`
- Usage guide: `docs/CI_CD_USAGE.md`


## Security Hardening

Application hardening controls are documented in `docs/SECURITY_HARDENING.md`, including SSRF protection, rate limiting, JWT handling, audit logging, safe errors, environment guardrails, and Docker runtime settings.
## Development

Local login and signup work without Docker or Postgres. The backend stores data in SQLite (`backend/apiguardx.db`). The frontend proxies `/api` to `http://127.0.0.1:8000`.

Backend:

```bash
cd backend
python -m venv .venv
. .venv/Scripts/activate
pip install -r requirements.txt
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

Frontend (in a second terminal):

```bash
cd frontend
npm install
npm run dev
```

Open http://localhost:3000 and create an account. Use a password with at least 12 characters, including uppercase, lowercase, a number, and a symbol (for example `TestAccount123!`).

## Testing

Latest stabilization report: `docs/TEST_REPORT.md`

```bash
cd backend
pytest
```

```bash
cd frontend
npm run lint
```

## Project Structure

```text
backend/               FastAPI application
  app/api/routes/      HTTP routes
  app/core/            config, security, logging
  app/db/              database session
  app/scanner/         low-risk scanner engine
  app/reports/         PDF report generation
frontend/              Next.js application
.github/workflows/    CI pipeline
docker-compose.yml     local production-like stack
DEPLOYMENT.md          deployment guide
```




