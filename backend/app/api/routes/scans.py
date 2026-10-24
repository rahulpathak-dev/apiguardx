from fastapi import APIRouter, Depends, Query, status
from sqlalchemy.orm import Session

from app.api.deps import get_current_user
from app.db.session import get_db
from app.models import Finding, Scan, User
from app.schemas import AnalyticsRead, FindingRead, FindingUpdate, ScanCompareRead, ScanCreate, ScanRead
from app.services.scans import compare_latest_user_scans, create_user_scan, get_user_analytics, get_user_scan, list_user_scans, update_user_finding


router = APIRouter()


@router.get("", response_model=list[ScanRead])
def list_scans(
    target_id: int | None = Query(default=None),
    severity: str | None = Query(default=None, pattern="^(Low|Medium|High|Critical)$"),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> list[Scan]:
    return list_user_scans(db, current_user, target_id=target_id, severity=severity)


@router.post("", response_model=ScanRead, status_code=status.HTTP_201_CREATED)
def create_scan(
    payload: ScanCreate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> Scan:
    return create_user_scan(db, current_user, payload)


@router.get("/analytics", response_model=AnalyticsRead)
def analytics(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)) -> AnalyticsRead:
    return get_user_analytics(db, current_user)


@router.get("/compare/latest", response_model=ScanCompareRead)
def compare_latest(target_id: int, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)) -> ScanCompareRead:
    return compare_latest_user_scans(db, current_user, target_id)


@router.patch("/findings/{finding_id}", response_model=FindingRead)
def update_finding(
    finding_id: int,
    payload: FindingUpdate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> Finding:
    return update_user_finding(db, current_user, finding_id, payload)


@router.get("/{scan_id}", response_model=ScanRead)
def get_scan(
    scan_id: int,
    severity: str | None = Query(default=None, pattern="^(Low|Medium|High|Critical)$"),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> Scan:
    return get_user_scan(db, current_user, scan_id, severity=severity)
