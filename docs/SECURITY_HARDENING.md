# APIGuardX Security Hardening

APIGuardX is designed for authorized, low-risk API scanning. These controls harden the application itself while preserving that safety boundary.

## Backend Controls

- Input validation uses Pydantic field bounds and service-layer ownership checks.
- Validation errors omit raw input values to avoid reflecting passwords, tokens, or scanned response snippets.
- Security headers include `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, `Permissions-Policy`, `Cross-Origin-Opener-Policy`, `Cross-Origin-Resource-Policy: cross-origin` (so the frontend on another localhost port can call the API), and sensitive-route `Cache-Control: no-store`.
- API rate limiting uses a fixed-window in-memory limiter with separate public and authenticated thresholds.
- Audit logs are written for registration, login, logout, project changes, endpoint changes, scans, reports, and CI/CD token operations.

## Scanner SSRF Controls

- API base URLs must be absolute HTTP(S) URLs without credentials or fragments.
- Localhost, local/internal hostnames, private IPs, loopback IPs, link-local IPs, reserved IPs, and cloud metadata IPs are blocked by default.
- `SCANNER_ALLOWED_HOSTS` can restrict scanning to approved host patterns such as `*.example.com`.
- `SCANNER_BLOCKED_HOSTS` can deny specific hosts or wildcard patterns.
- `SCANNER_RESOLVE_DNS_FOR_SSRF=true` enables DNS resolution checks before scanning hosts. Enable this in production when outbound DNS is available.
- `SCANNER_ALLOW_PRIVATE_NETWORKS=true` should only be used in an explicitly authorized internal lab.

## Authentication

- Passwords are hashed with bcrypt.
- Access tokens include `iss`, `aud`, `jti`, `type`, `iat`, `nbf`, and `exp` claims.
- JWT decoding validates issuer and audience.
- Logout records token revocation by `jti`.

## Environment Security

Production mode rejects:

- default or short JWT secrets
- wildcard CORS origins
- wildcard or empty trusted hosts
- default database credentials containing `change-me`
- SQLite database URLs
- debug mode
- DNS-blind SSRF checks unless private-network scanning is explicitly enabled

Keep real secrets out of source control and store them in a secret manager.

## Docker Runtime

- Backend and frontend images run as non-root users.
- Compose binds exposed ports to `127.0.0.1` for local use.
- Backend/frontend containers use `read_only`, `tmpfs`, `cap_drop: ALL`, and `no-new-privileges`.
- Health checks are defined for application containers.

