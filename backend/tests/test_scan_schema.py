from datetime import UTC, datetime

from app.models import Scan
from app.schemas import ScanRead


def test_scan_schema_includes_computed_risk_grade_and_explanation() -> None:
    scan = Scan(
        id=1,
        project_id=1,
        status="completed",
        total_risk_score=70,
        high_count=1,
        summary="Completed 1 safe endpoint checks with 1 findings. Grade D: total risk 70/100 from 1 finding.",
        created_at=datetime.now(UTC),
    )

    payload = ScanRead.model_validate(scan)

    assert payload.risk_grade == "D"
    assert payload.risk_explanation.startswith("Grade D")
