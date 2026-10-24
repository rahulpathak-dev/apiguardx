from fastapi import APIRouter, Depends, Header, Query, status
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session

from app.api.deps import get_current_user
from app.db.session import get_db
from app.models import CiCdToken, User
from app.schemas import CiCdScanRequest, CiCdScanResponse, CiCdTokenCreate, CiCdTokenCreateResponse, CiCdTokenRead
from app.services.ci_cd import authenticate_ci_token, create_ci_token, extract_ci_token, list_ci_tokens, revoke_ci_token, run_ci_scan


router = APIRouter()


@router.post("/tokens", response_model=CiCdTokenCreateResponse, status_code=status.HTTP_201_CREATED)
def create_token(
    payload: CiCdTokenCreate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> CiCdTokenCreateResponse:
    token, raw_token = create_ci_token(db, current_user, payload)
    token_read = CiCdTokenRead.model_validate(token, from_attributes=True)
    return CiCdTokenCreateResponse(**token_read.model_dump(), token=raw_token)


@router.get("/tokens", response_model=list[CiCdTokenRead])
def list_tokens(
    project_id: int | None = Query(default=None),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> list[CiCdToken]:
    return list_ci_tokens(db, current_user, project_id=project_id)


@router.post("/tokens/{token_id}/revoke", response_model=CiCdTokenRead)
def revoke_token(
    token_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> CiCdToken:
    return revoke_ci_token(db, current_user, token_id)


@router.post("/scan", response_model=CiCdScanResponse)
def trigger_ci_scan(
    payload: CiCdScanRequest,
    authorization: str | None = Header(default=None),
    x_apiguardx_token: str | None = Header(default=None, alias="X-APIGUARDX-TOKEN"),
    db: Session = Depends(get_db),
) -> JSONResponse:
    token = authenticate_ci_token(db, extract_ci_token(authorization, x_apiguardx_token))
    result = run_ci_scan(db, token, payload)
    status_code = status.HTTP_200_OK if result.passed else status.HTTP_422_UNPROCESSABLE_ENTITY
    return JSONResponse(status_code=status_code, content=result.model_dump(mode="json"))


