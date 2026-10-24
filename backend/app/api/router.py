from fastapi import APIRouter

from app.api.routes import auth, ci_cd, endpoints, reports, scans, targets


api_router = APIRouter()
api_router.include_router(auth.router, prefix="/auth", tags=["auth"])
api_router.include_router(ci_cd.router, prefix="/ci", tags=["ci-cd"])
api_router.include_router(targets.router, prefix="/targets", tags=["targets"])
api_router.include_router(endpoints.router, prefix="/endpoints", tags=["endpoints"])
api_router.include_router(scans.router, prefix="/scans", tags=["scans"])
api_router.include_router(reports.router, prefix="/reports", tags=["reports"])


