from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.router import api_router
from app.core.config import settings
from app.core.exceptions import register_exception_handlers
from app.core.logging import configure_logging
from app.core.middleware import register_middleware
from app.db.migrations import apply_development_migrations
from app.db.session import Base, check_database_connection, engine


@asynccontextmanager
async def lifespan(app: FastAPI):
    configure_logging()
    if settings.environment != "production":
        Base.metadata.create_all(bind=engine)
        apply_development_migrations()
    yield


def create_app() -> FastAPI:
    app = FastAPI(
        title=settings.app_name,
        version=settings.app_version,
        debug=settings.app_debug,
        description="Authorized, low-risk API security scanning and reporting platform.",
        lifespan=lifespan,
        docs_url="/docs" if settings.environment != "production" else None,
        redoc_url="/redoc" if settings.environment != "production" else None,
    )

    register_exception_handlers(app)
    register_middleware(app)

    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials="*" not in settings.cors_origins,
        allow_methods=["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type", "X-APIGUARDX-TOKEN", settings.request_id_header],
        max_age=600,
    )

    app.include_router(api_router)

    @app.get("/health", tags=["system"])
    def health() -> dict[str, Any]:
        try:
            database_ok = check_database_connection()
        except Exception:
            database_ok = False
        return {
            "status": "ok" if database_ok else "degraded",
            "service": settings.app_name,
            "version": settings.app_version,
            "environment": settings.environment,
            "database": "ok" if database_ok else "unavailable",
        }

    return app


app = create_app()
