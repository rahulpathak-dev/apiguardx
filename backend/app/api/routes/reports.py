from fastapi import APIRouter, Depends
from fastapi.responses import Response
from sqlalchemy.orm import Session

from app.api.deps import get_current_user
from app.db.session import get_db
from app.models import User
from app.services.reports import build_user_scan_pdf


router = APIRouter()


@router.get("/{scan_id}.pdf")
def download_report(scan_id: int, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)) -> Response:
    content = build_user_scan_pdf(db, current_user, scan_id)
    return Response(
        content=content,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="apiguardx-scan-{scan_id}.pdf"'},
    )
