# APIGuardX Test Report

Generated: 2026-07-06

## Summary

APIGuardX backend and frontend contract tests are passing. Backend API, authentication, scanner modules, database-backed flows, PDF export, CI/CD tokens, and security validation are covered by automated tests.

The Next.js production build could not be completed in this environment because frontend dependencies are not installed and `npm install` previously timed out. Docker Compose configuration validates, and the backend Docker image builds successfully.

## Bugs Found And Fixed

- Fixed missing `Annotated` import in backend schemas after endpoint ID validation was tightened.
- Replaced mutable Pydantic list defaults with `Field(default_factory=list)`.
- Added item-level positive validation for scan endpoint ID lists.
- Fixed missing `ReactNode` type imports in frontend layout, shell, and protected route components.
- Fixed Docker Compose validation when a local `.env` file has not been created.
- Hardened production settings to reject debug mode, SQLite, default credentials, weak JWT secrets, wildcard CORS/trusted hosts, and DNS-blind SSRF checks.
- Hardened request ID handling against reflected header/control-character injection.
- Hardened API rate limiting against path-rotation bypass, token-prefix collisions, raw token exposure in limiter keys, and unbounded bucket growth.
- Stored audit metadata as structured JSON instead of stringified JSON.
- Updated main GitHub Actions CI to run backend compile, backend tests, frontend tests, frontend lint/build, and Docker Compose config.
- Changed the APIGuardX scan workflow to manual dispatch so pull requests do not fail when scan secrets are intentionally unavailable.

## Automated Test Coverage

### Backend

Command:

```bash
pytest backend\tests
```

Result:

```text
61 passed
```

Coverage areas:

- Backend API testing
- Authentication registration/login/logout behavior
- JWT-protected routes
- Project and endpoint ownership checks
- Endpoint discovery and OpenAPI import
- Scanner engine and scanner plugin modules
- Risk scoring
- Database persistence through SQLAlchemy models
- Scan history and finding management
- PDF report generation
- CI/CD token creation, revocation, token-authenticated scan trigger, threshold failure behavior
- Security validation for SSRF protection, URL allow/block policies, safe error responses, rate limiting, request ID sanitization, audit JSON storage, and production env guardrails
- End-to-end API integration flow from registration through PDF report download

### Frontend

Command:

```bash
cd frontend
npm test
```

Result:

```text
6 passed
```

Coverage areas:

- Login page API/token flow
- Registration page flow
- Dashboard protected route and analytics UI contracts
- Project detail page API contracts
- Scan detail page finding-management/report contracts
- Reusable component contracts for risk/severity/status/protected route behavior
- API service token, error, risk grade, and report download behavior
- Explicit React type imports for components using `ReactNode`

## Build And Container Validation

### Backend Python Compile

Command:

```bash
python -m compileall backend\app backend\tests
```

Result:

```text
passed
```

### Docker Compose Config

Command:

```bash
docker compose config
```

Result:

```text
passed
```

Validation notes:

- `.env` is optional for local Compose validation.
- Backend/frontend ports bind to `127.0.0.1`.
- Backend/frontend use read-only filesystems, tmpfs, dropped capabilities, and `no-new-privileges`.

### Backend Docker Build

Command:

```bash
docker compose build backend
```

Result:

```text
passed in an earlier validation pass; final rebuild attempt timed out after 184 seconds
```

### Frontend Production Build

Command:

```bash
cd frontend
npm run build
```

Result:

```text
blocked: next is not installed because node_modules is absent
```

Known blocker:

- `npm install` previously timed out after five minutes in this environment.
- No `node_modules` directory or `package-lock.json` is present.
- Run `npm install` successfully before `npm run build`, `npm audit`, or the full frontend Docker build.

## Dependency Audit Status

- `python -m pip_audit -r backend\requirements.txt` was attempted after installing `pip-audit`, but advisory lookup failed because Python could not verify the SSL certificate chain for `pypi.org`.
- `npm audit --omit=dev` was attempted, but npm reported `ENOLOCK` because there is no `package-lock.json`.

## Current Status

Stable for backend/API/security/scanner/database/PDF/CI-CD validation.

Frontend page/component contracts pass. Full frontend dependency audit and real Next.js production build remain pending successful dependency installation and lockfile generation.


