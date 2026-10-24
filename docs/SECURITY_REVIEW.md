# APIGuardX Security Review

Generated: 2026-07-06

## Scope

Authorized review of APIGuardX itself across authentication, JWT handling, backend APIs, frontend contracts, database persistence, Docker deployment, scanner abuse prevention, SSRF controls, CORS, rate limiting, secret exposure, error handling, and dependency-audit readiness.

## Issues Found And Fixed

- Tightened production configuration guardrails in `backend/app/core/config.py`: production now rejects debug mode, SQLite database URLs, default database credentials containing `change-me`, wildcard CORS, wildcard/empty trusted hosts, weak/default JWT secrets, and DNS-blind SSRF checks unless private-network scanning is explicitly enabled.
- Increased the default public API rate-limit ceiling from 30 to 120 requests per window so normal auth/project workflows are not throttled under global client limits. The value remains bounded and environment-configurable.
- Hardened rate-limit keying in `backend/app/core/middleware.py`: buckets are now keyed by client plus a SHA-256 token fingerprint instead of raw token prefixes and raw request paths. This prevents path-rotation bypasses, avoids grouping unrelated JWTs that share a common header prefix, and avoids storing token material in memory keys.
- Added request ID sanitization to prevent reflected header/control-character injection through `X-Request-ID`.
- Added rate-limit bucket pruning and an upper bucket cap to reduce memory-exhaustion risk.
- Stored audit metadata as structured JSON instead of stringified JSON, improving database integrity and future queryability.
- Tightened scan schema validation for endpoint ID lists, including item-level positive integer validation and bounded list sizes.
- Replaced mutable schema defaults with `Field(default_factory=list)`.
- Fixed missing backend `Annotated` import required by the tightened schemas.
- Fixed frontend `ReactNode` imports in layout/protected-route components so TypeScript has explicit type inputs.
- Updated CI to run backend compile/tests, frontend tests/lint/build, and Docker Compose config validation.
- Changed the APIGuardX CI scan workflow to manual dispatch so pull requests do not fail when scan secrets are intentionally absent.

## Controls Reviewed

- Authentication and JWT: bcrypt password hashing, JWT issuer/audience/type/jti/nbf/exp claims, protected route dependency, logout revocation, safe auth errors.
- Backend API security: input validation, ownership checks, safe exception shape, sanitized validation errors, security headers, audit logging.
- Frontend security: protected-route contracts, token storage/service-layer behavior, error/loading states, no hardcoded API secrets found in frontend tests/static checks.
- Database security: ownership-linked models, foreign keys, indexes, audit metadata JSON field, timestamps.
- Scanner abuse prevention: safe HTTP methods, request timeouts, response-size bounds, limited rate-limit probes, authorization acknowledgement, SSRF URL validation.
- SSRF protection: blocked localhost/private/link-local/reserved/metadata addresses, host allowlist/blocklist, optional DNS resolution checks, production guardrail requiring DNS SSRF verification unless private network scanning is explicitly enabled.
- CORS: production rejects wildcard CORS; Compose/development uses explicit localhost origin.
- Docker: local ports bound to 127.0.0.1, non-root runtime images, read-only frontend/backend containers, tmpfs, dropped capabilities, no-new-privileges, database health check.

## Verification

- `python -m compileall backend\app backend\tests`: passed.
- `pytest backend\tests`: 61 passed.
- `cd frontend && npm test`: 6 passed.
- `docker compose config`: passed.
- `docker compose build backend`: passed in an earlier validation pass; the final rebuild attempt after backend hardening timed out after 184 seconds without a completed result.

## Dependency Audit Status

- Python: `pip-audit` is installed, but advisory lookup failed because Python could not verify the local SSL trust chain for `pypi.org` (`CERTIFICATE_VERIFY_FAILED`). No dependency vulnerability result could be trusted from this environment until the host CA store/Python certificate configuration is fixed.
- Frontend: `npm audit --omit=dev` cannot run because the project has no `package-lock.json`. `npm install` previously timed out in this environment, so a lockfile and full Next.js production build are still pending dependency installation.

## Production Release Gates

Before deploying externally:

- Create a real `.env` with a unique 32+ character `JWT_SECRET_KEY`, PostgreSQL credentials without defaults, explicit `BACKEND_CORS_ORIGINS`, explicit `TRUSTED_HOSTS`, and `ENVIRONMENT=production`.
- Set `SCANNER_RESOLVE_DNS_FOR_SSRF=true` in production unless running a deliberately authorized private-network lab with `SCANNER_ALLOW_PRIVATE_NETWORKS=true`.
- Generate and commit/package a frontend lockfile after `npm install` succeeds, then run `npm audit --omit=dev`, `npm run lint`, and `npm run build`.
- Fix the host Python certificate trust issue, then run `python -m pip_audit -r backend\requirements.txt` successfully.
- Replace all Compose sample passwords before any non-local deployment.

