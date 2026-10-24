from functools import lru_cache
from pathlib import Path

from pydantic import Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


_BACKEND_DIR = Path(__file__).resolve().parents[2]
_PROJECT_ROOT = Path(__file__).resolve().parents[3]


class Settings(BaseSettings):
    app_name: str = "APIGuardX API"
    app_version: str = "1.0.0"
    environment: str = "development"
    app_debug: bool = False
    database_url: str = "sqlite:///./apiguardx.db"
    jwt_secret_key: SecretStr = Field(SecretStr("dev-only-change-me"), min_length=16)
    jwt_algorithm: str = "HS256"
    jwt_issuer: str = "apiguardx"
    jwt_audience: str = "apiguardx-api"
    jwt_expire_minutes: int = Field(60, ge=5, le=1440)
    backend_cors_origins: str = "http://localhost:3000,http://127.0.0.1:3000"
    trusted_hosts: str = "localhost,127.0.0.1,testserver"
    scanner_allowed_hosts: str = ""
    scanner_blocked_hosts: str = "localhost,*.localhost,127.*,0.0.0.0,::1,169.254.169.254,100.100.100.200"
    scanner_allow_private_networks: bool = False
    scanner_resolve_dns_for_ssrf: bool = False
    scanner_timeout_seconds: float = Field(8.0, ge=1.0, le=30.0)
    scanner_max_response_bytes: int = Field(512_000, ge=1024, le=2_000_000)
    scanner_rate_limit_probe_count: int = Field(3, ge=1, le=5)
    scanner_rate_limit_probe_delay_seconds: float = Field(0.25, ge=0.0, le=5.0)
    api_rate_limit_enabled: bool = True
    api_rate_limit_window_seconds: int = Field(60, ge=10, le=3600)
    api_rate_limit_public_requests: int = Field(120, ge=1, le=1000)
    api_rate_limit_authenticated_requests: int = Field(300, ge=1, le=5000)
    request_id_header: str = "X-Request-ID"

    model_config = SettingsConfigDict(
        env_file=(_PROJECT_ROOT / ".env", _BACKEND_DIR / ".env"),
        env_file_encoding="utf-8",
        extra="ignore",
    )

    @field_validator("environment")
    @classmethod
    def normalize_environment(cls, value: str) -> str:
        return value.strip().lower()

    @field_validator("backend_cors_origins", "trusted_hosts", "scanner_allowed_hosts", "scanner_blocked_hosts")
    @classmethod
    def strip_csv(cls, value: str) -> str:
        return ",".join(item.strip() for item in value.split(",") if item.strip())

    @model_validator(mode="after")
    def validate_security_settings(self) -> "Settings":
        if self.environment != "production":
            uses_compose_db_host = "@db:" in self.database_url or "@db/" in self.database_url
            if uses_compose_db_host and not Path("/.dockerenv").exists():
                self.database_url = f"sqlite:///{(_BACKEND_DIR / 'apiguardx.db').as_posix()}"
        if self.environment == "production":
            secret = self.jwt_secret_key.get_secret_value()
            if secret in {"dev-only-change-me", "replace-with-a-long-random-secret"} or len(secret) < 32:
                raise ValueError("JWT_SECRET_KEY must be a unique secret of at least 32 characters in production")
            if "*" in self.cors_origins:
                raise ValueError("Wildcard CORS origins are not allowed in production")
            if not self.trusted_host_list or "*" in self.trusted_host_list:
                raise ValueError("TRUSTED_HOSTS must be explicit in production")
            if self.app_debug:
                raise ValueError("APP_DEBUG must be false in production")
            if self.database_url.startswith("sqlite"):
                raise ValueError("DATABASE_URL must use PostgreSQL or another production database in production")
            if "change-me" in self.database_url:
                raise ValueError("DATABASE_URL must not use default credentials in production")
            if not self.scanner_resolve_dns_for_ssrf and not self.scanner_allow_private_networks:
                raise ValueError("SCANNER_RESOLVE_DNS_FOR_SSRF must be true in production unless private-network scanning is explicitly enabled")
        return self

    @property
    def jwt_secret(self) -> str:
        return self.jwt_secret_key.get_secret_value()

    @property
    def cors_origins(self) -> list[str]:
        return [origin.strip() for origin in self.backend_cors_origins.split(",") if origin.strip()]

    @property
    def trusted_host_list(self) -> list[str]:
        return [host.strip() for host in self.trusted_hosts.split(",") if host.strip()]

    @property
    def scanner_allowed_host_patterns(self) -> list[str]:
        return [host.strip().lower() for host in self.scanner_allowed_hosts.split(",") if host.strip()]

    @property
    def scanner_blocked_host_patterns(self) -> list[str]:
        return [host.strip().lower() for host in self.scanner_blocked_hosts.split(",") if host.strip()]


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()





