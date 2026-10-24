from fastapi import APIRouter, Depends, status
from sqlalchemy.orm import Session

from app.api.deps import get_current_user
from app.db.session import get_db
from app.models import Endpoint, User
from app.schemas import EndpointCreate, EndpointImportOpenAPI, EndpointImportResult, EndpointRead
from app.services.endpoints import create_project_endpoint, import_openapi_endpoints, list_project_endpoints


router = APIRouter()


@router.get("", response_model=list[EndpointRead])
def list_endpoints(
    target_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> list[Endpoint]:
    return list_project_endpoints(db, target_id, current_user)


@router.post("", response_model=EndpointRead, status_code=status.HTTP_201_CREATED)
def create_endpoint(
    payload: EndpointCreate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> Endpoint:
    return create_project_endpoint(db, current_user, payload)


@router.post("/import-openapi", response_model=EndpointImportResult, status_code=status.HTTP_201_CREATED)
def import_openapi(
    payload: EndpointImportOpenAPI,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> EndpointImportResult:
    return import_openapi_endpoints(db, current_user, payload)
