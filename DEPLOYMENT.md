# Deployment Guide

## Production Checklist

- Set a strong `JWT_SECRET_KEY`.
- Use managed PostgreSQL with encrypted storage and backups.
- Terminate TLS at a trusted load balancer or reverse proxy.
- Restrict backend CORS to the production frontend origin.
- Run scans only from approved egress networks.
- Set `SCANNER_RESOLVE_DNS_FOR_SSRF=true` in production so scanner targets are checked after DNS resolution.
- Store written authorization records outside APIGuardX according to company policy.
- Enable log aggregation and alerting for authentication failures and scan errors.

## Vercel + Hosted Backend

Vercel should host the Next.js frontend. The FastAPI backend should run on a
long-running Python container host (for example Render, Railway, Fly.io, or a
VM) with managed PostgreSQL. This is required because scans and PDF generation
can outlive a serverless request, and Vercel's filesystem is not persistent.
Do not deploy the SQLite database or the scanner as a Vercel function.

### 1. Deploy the backend

Create a PostgreSQL database and deploy the [`backend/`](backend) directory as
a Docker service using [`backend/Dockerfile`](backend/Dockerfile). Configure
these production variables on the backend host:

```text
ENVIRONMENT=production
APP_DEBUG=false
DATABASE_URL=postgresql+psycopg://USER:PASSWORD@HOST:5432/DATABASE
JWT_SECRET_KEY=<unique random value of at least 32 characters>
BACKEND_CORS_ORIGINS=https://<your-vercel-domain>
TRUSTED_HOSTS=<your-backend-host>,<your-vercel-domain>
SCANNER_RESOLVE_DNS_FOR_SSRF=true
SCANNER_ALLOW_PRIVATE_NETWORKS=false
```

Use the public HTTPS URL assigned to the backend as `https://<backend-host>`.
Verify it before deploying the frontend:

```text
GET https://<backend-host>/health
```

The response should report `"status": "ok"` and `"database": "ok"`.

### 2. Deploy the frontend to Vercel

1. Import the repository into Vercel.
2. Set **Root Directory** to `frontend`.
3. Keep the detected framework as **Next.js**. Vercel will use `npm run build`.
4. Add the following Vercel environment variable for **Production**:

   ```text
   API_PROXY_TARGET=https://<backend-host>
   ```

   Leave `NEXT_PUBLIC_API_URL` unset (or set it to `/api`). The existing
   rewrite in [`frontend/next.config.mjs`](frontend/next.config.mjs) proxies
   browser requests through the Vercel domain, so JWTs are not sent directly
   to a separately configured API origin.
5. Deploy, then add the final Vercel URL to the backend's
   `BACKEND_CORS_ORIGINS` and redeploy the backend if the URL changed.

If a custom domain is used, set `BACKEND_CORS_ORIGINS` to that exact HTTPS
origin, without a trailing slash. `API_PROXY_TARGET` is a server-side Vercel
variable and must not be prefixed with `NEXT_PUBLIC_`.

### 3. Verify the deployment

- Open the Vercel URL and register a test account.
- Create a target with written authorization and run a low-risk scan.
- Download a generated PDF report.
- Check the browser network panel: `/api/*` requests should return responses
  from the backend, not 404s from Vercel.
- Confirm the backend logs show the Vercel request and no CORS or trusted-host
  errors.

## Docker Compose

```bash
cp .env.example .env
docker compose up --build -d
```

The backend creates database tables on startup for this scaffold. For a larger deployment, add Alembic migrations and run them during release.

## Environment Variables

See `.env.example` for all required values.

## GitHub Actions

The workflow runs backend tests and frontend lint/build checks. Add deployment steps after the `build` job once your target registry and hosting platform are selected.

## CI/CD Security Scan

Use the backend CLI in a controlled pipeline against environments you own:

```bash
python -m app.cli scan --base-url "$AUTHORIZED_API_BASE_URL" --path /health
```

The scan is intentionally conservative and low-risk.

