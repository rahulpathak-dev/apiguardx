from datetime import UTC, datetime
from enum import Enum

from sqlalchemy import Boolean, CheckConstraint, DateTime, ForeignKey, Integer, JSON, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship, synonym

from app.db.session import Base
from app.scanner.risk_scoring import explain_score, grade_for_score


class Severity(str, Enum):
    low = "Low"
    medium = "Medium"
    high = "High"
    critical = "Critical"


class ScanStatus(str, Enum):
    pending = "pending"
    running = "running"
    completed = "completed"
    failed = "failed"


class ReportStatus(str, Enum):
    pending = "pending"
    generated = "generated"
    failed = "failed"


class AuditAction(str, Enum):
    register = "register"
    login = "login"
    create_project = "create_project"
    create_endpoint = "create_endpoint"
    run_scan = "run_scan"
    generate_report = "generate_report"
    create_ci_token = "create_ci_token"
    revoke_ci_token = "revoke_ci_token"


def now_utc() -> datetime:
    return datetime.now(UTC)


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    email: Mapped[str] = mapped_column(String(320), unique=True, index=True)
    full_name: Mapped[str] = mapped_column(String(120))
    password_hash: Mapped[str] = mapped_column(String(255))
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc, onupdate=now_utc)

    projects: Mapped[list["ApiProject"]] = relationship(back_populates="owner", cascade="all, delete-orphan")
    ci_cd_tokens: Mapped[list["CiCdToken"]] = relationship(back_populates="owner", cascade="all, delete-orphan")
    audit_logs: Mapped[list["AuditLog"]] = relationship(back_populates="actor")


class ApiProject(Base):
    __tablename__ = "api_projects"
    __table_args__ = (UniqueConstraint("owner_id", "base_url", name="uq_api_projects_owner_base_url"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    owner_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    name: Mapped[str] = mapped_column(String(120))
    base_url: Mapped[str] = mapped_column(String(2048))
    authorization_ack: Mapped[bool] = mapped_column(Boolean, default=False)
    risk_score: Mapped[int] = mapped_column(Integer, default=0)
    last_scan_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc, onupdate=now_utc)

    owner: Mapped[User] = relationship(back_populates="projects")
    endpoints: Mapped[list["Endpoint"]] = relationship(back_populates="project", cascade="all, delete-orphan")
    scans: Mapped[list["Scan"]] = relationship(back_populates="project", cascade="all, delete-orphan")
    reports: Mapped[list["Report"]] = relationship(back_populates="project", cascade="all, delete-orphan")
    ci_cd_tokens: Mapped[list["CiCdToken"]] = relationship(back_populates="project", cascade="all, delete-orphan")


class Endpoint(Base):
    __tablename__ = "endpoints"
    __table_args__ = (
        UniqueConstraint("project_id", "method", "path", name="uq_endpoints_project_method_path"),
        CheckConstraint("method in ('GET', 'HEAD', 'OPTIONS')", name="ck_endpoints_safe_method"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    project_id: Mapped[int] = mapped_column(ForeignKey("api_projects.id", ondelete="CASCADE"), index=True)
    method: Mapped[str] = mapped_column(String(12), default="GET")
    path: Mapped[str] = mapped_column(String(1024))
    description: Mapped[str | None] = mapped_column(String(255), nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    last_status_code: Mapped[int | None] = mapped_column(Integer, nullable=True)
    last_risk_score: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc, onupdate=now_utc)

    project: Mapped[ApiProject] = relationship(back_populates="endpoints")
    scan_findings: Mapped[list["ScanFinding"]] = relationship(back_populates="endpoint")

    target_id = synonym("project_id")
    target = synonym("project")



class Scan(Base):
    __tablename__ = "scans"
    __table_args__ = (
        CheckConstraint("total_risk_score >= 0 and total_risk_score <= 100", name="ck_scans_total_risk_score"),
        CheckConstraint("critical_count >= 0 and high_count >= 0 and medium_count >= 0 and low_count >= 0", name="ck_scans_severity_counts"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    project_id: Mapped[int] = mapped_column(ForeignKey("api_projects.id", ondelete="CASCADE"), index=True)
    requested_by_user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)
    status: Mapped[str] = mapped_column(String(24), default=ScanStatus.pending.value)
    total_risk_score: Mapped[int] = mapped_column(Integer, default=0)
    max_severity: Mapped[str | None] = mapped_column(String(16), nullable=True)
    critical_count: Mapped[int] = mapped_column(Integer, default=0)
    high_count: Mapped[int] = mapped_column(Integer, default=0)
    medium_count: Mapped[int] = mapped_column(Integer, default=0)
    low_count: Mapped[int] = mapped_column(Integer, default=0)
    summary: Mapped[str | None] = mapped_column(Text, nullable=True)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    project: Mapped[ApiProject] = relationship(back_populates="scans")
    requested_by: Mapped[User | None] = relationship()
    findings: Mapped[list["ScanFinding"]] = relationship(back_populates="scan", cascade="all, delete-orphan")
    reports: Mapped[list["Report"]] = relationship(back_populates="scan", cascade="all, delete-orphan")

    @property
    def risk_grade(self) -> str:
        return grade_for_score(self.total_risk_score)

    @property
    def risk_explanation(self) -> str:
        summary = self.summary or ""
        marker_index = summary.find("Grade ")
        if marker_index >= 0:
            return summary[marker_index:]
        return explain_score(
            total_score=self.total_risk_score,
            grade=self.risk_grade,
            finding_count=self.critical_count + self.high_count + self.medium_count + self.low_count,
            severity_score=self.total_risk_score,
            count_score=0,
            criticality_score=0,
            auth_exposure_score=0,
            secret_exposure_score=0,
        )

    target_id = synonym("project_id")
    target = synonym("project")



class ScanFinding(Base):
    __tablename__ = "scan_findings"
    __table_args__ = (CheckConstraint("risk_score >= 0 and risk_score <= 100", name="ck_scan_findings_risk_score"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), index=True)
    endpoint_id: Mapped[int | None] = mapped_column(ForeignKey("endpoints.id", ondelete="SET NULL"), nullable=True, index=True)
    endpoint_path: Mapped[str] = mapped_column(String(1024))
    check_name: Mapped[str] = mapped_column(String(120), index=True)
    severity: Mapped[str] = mapped_column(String(16), index=True)
    risk_score: Mapped[int] = mapped_column(Integer, default=0)
    title: Mapped[str] = mapped_column(String(180))
    evidence: Mapped[str] = mapped_column(Text)
    recommendation: Mapped[str] = mapped_column(Text)
    is_reviewed: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    review_notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    reviewed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    reviewed_by_user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc)

    scan: Mapped[Scan] = relationship(back_populates="findings")
    endpoint: Mapped[Endpoint | None] = relationship(back_populates="scan_findings")
    reviewed_by: Mapped[User | None] = relationship()


class Report(Base):
    __tablename__ = "reports"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    project_id: Mapped[int] = mapped_column(ForeignKey("api_projects.id", ondelete="CASCADE"), index=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), index=True)
    generated_by_user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)
    status: Mapped[str] = mapped_column(String(24), default=ReportStatus.pending.value)
    report_type: Mapped[str] = mapped_column(String(24), default="pdf")
    file_name: Mapped[str] = mapped_column(String(255))
    storage_path: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    risk_score_snapshot: Mapped[int] = mapped_column(Integer, default=0)
    generated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc)

    project: Mapped[ApiProject] = relationship(back_populates="reports")
    scan: Mapped[Scan] = relationship(back_populates="reports")
    generated_by: Mapped[User | None] = relationship()


class CiCdToken(Base):
    __tablename__ = "ci_cd_tokens"
    __table_args__ = (UniqueConstraint("token_prefix", name="uq_ci_cd_tokens_token_prefix"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    owner_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    project_id: Mapped[int] = mapped_column(ForeignKey("api_projects.id", ondelete="CASCADE"), index=True)
    name: Mapped[str] = mapped_column(String(120))
    token_prefix: Mapped[str] = mapped_column(String(16))
    token_hash: Mapped[str] = mapped_column(String(255))
    scopes: Mapped[str] = mapped_column(String(255), default="scan:run,scan:read")
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    owner: Mapped[User] = relationship(back_populates="ci_cd_tokens")
    project: Mapped[ApiProject] = relationship(back_populates="ci_cd_tokens")


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    actor_user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)
    project_id: Mapped[int | None] = mapped_column(ForeignKey("api_projects.id", ondelete="SET NULL"), nullable=True, index=True)
    action: Mapped[str] = mapped_column(String(80), index=True)
    entity_type: Mapped[str] = mapped_column(String(80))
    entity_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    ip_address: Mapped[str | None] = mapped_column(String(64), nullable=True)
    user_agent: Mapped[str | None] = mapped_column(String(512), nullable=True)
    metadata_json: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc, index=True)

    actor: Mapped[User | None] = relationship(back_populates="audit_logs")
    project: Mapped[ApiProject | None] = relationship()



class AuthTokenRevocation(Base):
    __tablename__ = "auth_token_revocations"
    __table_args__ = (UniqueConstraint("token_id", name="uq_auth_token_revocations_token_id"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    token_id: Mapped[str] = mapped_column(String(64), index=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    revoked_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc)

    user: Mapped[User] = relationship()

ApiTarget = ApiProject
Finding = ScanFinding








