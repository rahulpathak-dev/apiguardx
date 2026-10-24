from fastapi import APIRouter, Depends, Response, status
from sqlalchemy.orm import Session

from app.api.deps import get_current_user
from app.db.session import get_db
from app.models import ApiTarget, User
from app.schemas import TargetCreate, TargetRead, TargetUpdate
from app.services.projects import create_project, delete_project, get_owned_project, list_projects, update_project


router = APIRouter()


@router.get("", response_model=list[TargetRead])
def list_targets(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)) -> list[ApiTarget]:
    return list_projects(db, current_user)


@router.post("", response_model=TargetRead, status_code=status.HTTP_201_CREATED)
def create_target(
    payload: TargetCreate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> ApiTarget:
    return create_project(db, current_user, payload)


@router.get("/{target_id}", response_model=TargetRead)
def get_target(target_id: int, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)) -> ApiTarget:
    return get_owned_project(db, target_id, current_user)


@router.patch("/{target_id}", response_model=TargetRead)
def patch_target(
    target_id: int,
    payload: TargetUpdate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> ApiTarget:
    return update_project(db, current_user, target_id, payload)


@router.delete("/{target_id}", status_code=status.HTTP_204_NO_CONTENT)
def remove_target(target_id: int, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)) -> Response:
    delete_project(db, current_user, target_id)
    return Response(status_code=status.HTTP_204_NO_CONTENT)
