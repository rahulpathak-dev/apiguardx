-- APIGuardX PostgreSQL schema
-- Migration-ready baseline DDL for authorized, low-risk API security scanning.

BEGIN;

CREATE TABLE IF NOT EXISTS users (
    id BIGSERIAL PRIMARY KEY,
    email VARCHAR(320) NOT NULL UNIQUE,
    full_name VARCHAR(120) NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_users_email ON users (email);
CREATE INDEX IF NOT EXISTS idx_users_active ON users (is_active);

CREATE TABLE IF NOT EXISTS api_projects (
    id BIGSERIAL PRIMARY KEY,
    owner_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name VARCHAR(120) NOT NULL,
    base_url VARCHAR(2048) NOT NULL,
    authorization_ack BOOLEAN NOT NULL DEFAULT FALSE,
    risk_score INTEGER NOT NULL DEFAULT 0 CHECK (risk_score >= 0 AND risk_score <= 100),
    last_scan_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_api_projects_owner_base_url UNIQUE (owner_id, base_url)
);

CREATE INDEX IF NOT EXISTS idx_api_projects_owner_id ON api_projects (owner_id);
CREATE INDEX IF NOT EXISTS idx_api_projects_risk_score ON api_projects (risk_score);
CREATE INDEX IF NOT EXISTS idx_api_projects_last_scan_at ON api_projects (last_scan_at);
CREATE INDEX IF NOT EXISTS idx_api_projects_owner_project ON api_projects (owner_id, id);

CREATE TABLE IF NOT EXISTS endpoints (
    id BIGSERIAL PRIMARY KEY,
    project_id BIGINT NOT NULL REFERENCES api_projects(id) ON DELETE CASCADE,
    method VARCHAR(12) NOT NULL DEFAULT 'GET',
    path VARCHAR(1024) NOT NULL,
    description VARCHAR(255),
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    last_status_code INTEGER,
    last_risk_score INTEGER NOT NULL DEFAULT 0 CHECK (last_risk_score >= 0 AND last_risk_score <= 100),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT ck_endpoints_safe_method CHECK (method IN ('GET', 'HEAD', 'OPTIONS')),
    CONSTRAINT uq_endpoints_project_method_path UNIQUE (project_id, method, path)
);

CREATE INDEX IF NOT EXISTS idx_endpoints_project_id ON endpoints (project_id);
CREATE INDEX IF NOT EXISTS idx_endpoints_active ON endpoints (is_active);
CREATE INDEX IF NOT EXISTS idx_endpoints_project_path ON endpoints (project_id, path);

CREATE TABLE IF NOT EXISTS scans (
    id BIGSERIAL PRIMARY KEY,
    project_id BIGINT NOT NULL REFERENCES api_projects(id) ON DELETE CASCADE,
    requested_by_user_id BIGINT REFERENCES users(id) ON DELETE SET NULL,
    status VARCHAR(24) NOT NULL DEFAULT 'pending',
    total_risk_score INTEGER NOT NULL DEFAULT 0 CHECK (total_risk_score >= 0 AND total_risk_score <= 100),
    max_severity VARCHAR(16),
    critical_count INTEGER NOT NULL DEFAULT 0 CHECK (critical_count >= 0),
    high_count INTEGER NOT NULL DEFAULT 0 CHECK (high_count >= 0),
    medium_count INTEGER NOT NULL DEFAULT 0 CHECK (medium_count >= 0),
    low_count INTEGER NOT NULL DEFAULT 0 CHECK (low_count >= 0),
    summary TEXT,
    started_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at TIMESTAMPTZ,
    CONSTRAINT ck_scans_status CHECK (status IN ('pending', 'running', 'completed', 'failed')),
    CONSTRAINT ck_scans_max_severity CHECK (max_severity IS NULL OR max_severity IN ('Low', 'Medium', 'High', 'Critical'))
);

CREATE INDEX IF NOT EXISTS idx_scans_project_id ON scans (project_id);
CREATE INDEX IF NOT EXISTS idx_scans_requested_by_user_id ON scans (requested_by_user_id);
CREATE INDEX IF NOT EXISTS idx_scans_status ON scans (status);
CREATE INDEX IF NOT EXISTS idx_scans_created_at ON scans (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_scans_total_risk_score ON scans (total_risk_score);
CREATE INDEX IF NOT EXISTS idx_scans_project_created ON scans (project_id, created_at DESC);

CREATE TABLE IF NOT EXISTS scan_findings (
    id BIGSERIAL PRIMARY KEY,
    scan_id BIGINT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    endpoint_id BIGINT REFERENCES endpoints(id) ON DELETE SET NULL,
    endpoint_path VARCHAR(1024) NOT NULL,
    check_name VARCHAR(120) NOT NULL,
    severity VARCHAR(16) NOT NULL,
    risk_score INTEGER NOT NULL DEFAULT 0 CHECK (risk_score >= 0 AND risk_score <= 100),
    title VARCHAR(180) NOT NULL,
    evidence TEXT NOT NULL,
    recommendation TEXT NOT NULL,
    is_reviewed BOOLEAN NOT NULL DEFAULT FALSE,
    review_notes TEXT,
    reviewed_at TIMESTAMPTZ,
    reviewed_by_user_id BIGINT REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT ck_scan_findings_severity CHECK (severity IN ('Low', 'Medium', 'High', 'Critical'))
);

CREATE INDEX IF NOT EXISTS idx_scan_findings_scan_id ON scan_findings (scan_id);
CREATE INDEX IF NOT EXISTS idx_scan_findings_endpoint_id ON scan_findings (endpoint_id);
CREATE INDEX IF NOT EXISTS idx_scan_findings_severity ON scan_findings (severity);
CREATE INDEX IF NOT EXISTS idx_scan_findings_check_name ON scan_findings (check_name);
CREATE INDEX IF NOT EXISTS idx_scan_findings_risk_score ON scan_findings (risk_score);
CREATE INDEX IF NOT EXISTS idx_scan_findings_reviewed ON scan_findings (is_reviewed);
CREATE INDEX IF NOT EXISTS idx_scan_findings_reviewed_by ON scan_findings (reviewed_by_user_id);

CREATE TABLE IF NOT EXISTS reports (
    id BIGSERIAL PRIMARY KEY,
    project_id BIGINT NOT NULL REFERENCES api_projects(id) ON DELETE CASCADE,
    scan_id BIGINT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    generated_by_user_id BIGINT REFERENCES users(id) ON DELETE SET NULL,
    status VARCHAR(24) NOT NULL DEFAULT 'pending',
    report_type VARCHAR(24) NOT NULL DEFAULT 'pdf',
    file_name VARCHAR(255) NOT NULL,
    storage_path VARCHAR(1024),
    risk_score_snapshot INTEGER NOT NULL DEFAULT 0 CHECK (risk_score_snapshot >= 0 AND risk_score_snapshot <= 100),
    generated_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT ck_reports_status CHECK (status IN ('pending', 'generated', 'failed')),
    CONSTRAINT ck_reports_type CHECK (report_type IN ('pdf'))
);

CREATE INDEX IF NOT EXISTS idx_reports_project_id ON reports (project_id);
CREATE INDEX IF NOT EXISTS idx_reports_scan_id ON reports (scan_id);
CREATE INDEX IF NOT EXISTS idx_reports_generated_by_user_id ON reports (generated_by_user_id);
CREATE INDEX IF NOT EXISTS idx_reports_created_at ON reports (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_reports_project_created ON reports (project_id, created_at DESC);

CREATE TABLE IF NOT EXISTS ci_cd_tokens (
    id BIGSERIAL PRIMARY KEY,
    owner_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    project_id BIGINT NOT NULL REFERENCES api_projects(id) ON DELETE CASCADE,
    name VARCHAR(120) NOT NULL,
    token_prefix VARCHAR(16) NOT NULL UNIQUE,
    token_hash VARCHAR(255) NOT NULL,
    scopes VARCHAR(255) NOT NULL DEFAULT 'scan:run,scan:read',
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    last_used_at TIMESTAMPTZ,
    expires_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    revoked_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_ci_cd_tokens_owner_id ON ci_cd_tokens (owner_id);
CREATE INDEX IF NOT EXISTS idx_ci_cd_tokens_project_id ON ci_cd_tokens (project_id);
CREATE INDEX IF NOT EXISTS idx_ci_cd_tokens_active ON ci_cd_tokens (is_active);
CREATE INDEX IF NOT EXISTS idx_ci_cd_tokens_expires_at ON ci_cd_tokens (expires_at);

CREATE TABLE IF NOT EXISTS audit_logs (
    id BIGSERIAL PRIMARY KEY,
    actor_user_id BIGINT REFERENCES users(id) ON DELETE SET NULL,
    project_id BIGINT REFERENCES api_projects(id) ON DELETE SET NULL,
    action VARCHAR(80) NOT NULL,
    entity_type VARCHAR(80) NOT NULL,
    entity_id BIGINT,
    ip_address INET,
    user_agent VARCHAR(512),
    metadata_json JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_audit_logs_actor_user_id ON audit_logs (actor_user_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_project_id ON audit_logs (project_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_action ON audit_logs (action);
CREATE INDEX IF NOT EXISTS idx_audit_logs_entity ON audit_logs (entity_type, entity_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_created_at ON audit_logs (created_at DESC);


CREATE TABLE IF NOT EXISTS auth_token_revocations (
    id BIGSERIAL PRIMARY KEY,
    token_id VARCHAR(64) NOT NULL UNIQUE,
    user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_auth_token_revocations_token_id ON auth_token_revocations (token_id);
CREATE INDEX IF NOT EXISTS idx_auth_token_revocations_user_id ON auth_token_revocations (user_id);
CREATE INDEX IF NOT EXISTS idx_auth_token_revocations_expires_at ON auth_token_revocations (expires_at);
COMMIT;


