from datetime import UTC, datetime
from typing import Annotated
import re

from pydantic import BaseModel, EmailStr, Field, HttpUrl, field_validator, model_validator


class UserCreate(BaseModel):
    email: EmailStr
    full_name: str = Field(min_length=2, max_length=120)
    password: str = Field(min_length=12, max_length=72)

    @field_validator("password")
    @classmethod
    def validate_password_strength(cls, value: str) -> str:
        checks = [
            (r"[a-z]", "one lowercase letter"),
            (r"[A-Z]", "one uppercase letter"),
            (r"\d", "one number"),
            (r"[^A-Za-z0-9]", "one special character"),
        ]
        missing = [label for pattern, label in checks if not re.search(pattern, value)]
        if missing:
            raise ValueError(f"Password must include at least {', '.join(missing)}")
        if value.strip() != value:
            raise ValueError("Password must not start or end with whitespace")
        if len(value.encode("utf-8")) > 72:
            raise ValueError("Password must be 72 bytes or fewer for bcrypt compatibility")
        return value


class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1, max_length=128)


class UserRead(BaseModel):
    id: int
    email: EmailStr
    full_name: str

    model_config = {"from_attributes": True}


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    expires_at: datetime
    user: UserRead


class LogoutResponse(BaseModel):
    message: str = "Logged out successfully"


class ProtectedRouteRead(BaseModel):
    authenticated: bool = True
    user: UserRead


class TargetCreate(BaseModel):
    name: str = Field(min_length=2, max_length=120)
    base_url: HttpUrl
    authorization_ack: bool


class TargetUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=2, max_length=120)
    base_url: HttpUrl | None = None
    authorization_ack: bool | None = None


class TargetRead(BaseModel):
    id: int
    name: str
    base_url: str
    authorization_ack: bool
    risk_score: int = 0
    last_scan_at: datetime | None = None
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class EndpointCreate(BaseModel):
    target_id: int = Field(ge=1)
    method: str = Field(default="GET", pattern="^(GET|OPTIONS|HEAD)$")
    path: str = Field(min_length=1, max_length=1024)
    description: str | None = Field(default=None, max_length=255)

    @field_validator("path")
    @classmethod
    def normalize_path(cls, value: str) -> str:
        return value if value.startswith("/") else f"/{value}"


class EndpointRead(BaseModel):
    id: int
    target_id: int
    method: str
    path: str
    description: str | None
    created_at: datetime

    model_config = {"from_attributes": True}



class EndpointImportOpenAPI(BaseModel):
    target_id: int = Field(ge=1)
    spec: dict = Field(description="OpenAPI or Swagger JSON object")

    @model_validator(mode="after")
    def validate_openapi_spec(self) -> "EndpointImportOpenAPI":
        if not isinstance(self.spec.get("paths"), dict):
            raise ValueError("OpenAPI/Swagger document must include a paths object")
        return self


class EndpointImportResult(BaseModel):
    imported_count: int
    skipped_count: int
    endpoints: list[EndpointRead]

class ScanCreate(BaseModel):
    target_id: int = Field(ge=1)
    endpoint_ids: list[Annotated[int, Field(ge=1)]] = Field(default_factory=list, max_length=250)


class FindingRead(BaseModel):
    id: int
    endpoint_path: str
    check_name: str
    severity: str
    title: str
    evidence: str
    recommendation: str
    is_reviewed: bool = False
    review_notes: str | None = None
    reviewed_at: datetime | None = None
    reviewed_by_user_id: int | None = None

    model_config = {"from_attributes": True}


class FindingUpdate(BaseModel):
    is_reviewed: bool | None = None
    review_notes: str | None = Field(default=None, max_length=4000)


class ScanFindingCompareRead(BaseModel):
    endpoint_path: str
    check_name: str
    severity: str
    title: str


class ScanCompareRead(BaseModel):
    target_id: int
    latest_scan_id: int | None
    previous_scan_id: int | None
    new_findings: list[ScanFindingCompareRead]
    resolved_findings: list[ScanFindingCompareRead]
    persistent_findings: list[ScanFindingCompareRead]


class ScanRead(BaseModel):
    id: int
    target_id: int
    status: str
    total_risk_score: int
    risk_grade: str
    risk_explanation: str
    summary: str | None
    created_at: datetime
    completed_at: datetime | None
    findings: list[FindingRead] = Field(default_factory=list)

    model_config = {"from_attributes": True}


class AnalyticsRead(BaseModel):
    scan_count: int
    finding_count: int
    average_risk_score: float
    severity_counts: dict[str, int]

class CiCdTokenCreate(BaseModel):
    project_id: int = Field(ge=1)
    name: str = Field(min_length=2, max_length=120)
    expires_at: datetime | None = None

    @field_validator("expires_at")
    @classmethod
    def validate_future_expiry(cls, value: datetime | None) -> datetime | None:
        if value is None:
            return value
        expiry = value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)
        if expiry <= datetime.now(UTC):
            raise ValueError("Expiration must be in the future")
        return value


class CiCdTokenRead(BaseModel):
    id: int
    project_id: int
    name: str
    token_prefix: str
    scopes: str
    is_active: bool
    last_used_at: datetime | None = None
    expires_at: datetime | None = None
    created_at: datetime
    revoked_at: datetime | None = None

    model_config = {"from_attributes": True}


class CiCdTokenCreateResponse(CiCdTokenRead):
    token: str = Field(description="Shown once. Store it in your CI/CD secret manager.")


class CiCdScanRequest(BaseModel):
    endpoint_ids: list[Annotated[int, Field(ge=1)]] = Field(default_factory=list, max_length=250)
    threshold: int = Field(default=70, ge=0, le=100)


class CiCdScanResponse(BaseModel):
    scan_id: int
    project_id: int
    project_name: str
    status: str
    risk_score: int
    risk_grade: str
    threshold: int
    passed: bool
    should_fail_pipeline: bool
    summary: str | None = None
    severity_counts: dict[str, int]
    findings: list[FindingRead] = Field(default_factory=list)
    completed_at: datetime | None = None





