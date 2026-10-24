from collections import Counter
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from app.models import ApiTarget, Endpoint, Finding, Scan, ScanStatus
from app.scanner.endpoint_scanner import EndpointScanner
from app.scanner.http_client import SAFE_METHODS, SafeHttpClient
from app.scanner.risk_scoring import calculate_risk_score
from app.scanner.types import FindingDraft


SEVERITY_ORDER = {"Low": 1, "Medium": 2, "High": 3, "Critical": 4}


class ScanManager:
    def __init__(self, endpoint_scanner: EndpointScanner | None = None) -> None:
        self.endpoint_scanner = endpoint_scanner or EndpointScanner()

    def run(self, db: Session, target: ApiTarget, endpoint_ids: list[int] | None = None) -> Scan:
        scan = Scan(target_id=target.id, status=ScanStatus.running.value, started_at=datetime.now(UTC))
        db.add(scan)
        db.commit()
        db.refresh(scan)

        try:
            endpoints = self._load_endpoints(db, target, endpoint_ids)
            drafts: list[FindingDraft] = []

            with SafeHttpClient() as client:
                for endpoint in endpoints:
                    snapshot, findings = self.endpoint_scanner.scan(client, target, endpoint)
                    drafts.extend(findings)
                    if snapshot is not None:
                        endpoint.last_status_code = snapshot.status_code
                        endpoint.last_risk_score = calculate_risk_score(findings, [endpoint]).total_score

            for draft in drafts:
                db.add(
                    Finding(
                        scan_id=scan.id,
                        endpoint_path=draft.endpoint_path,
                        check_name=draft.check_name,
                        severity=draft.severity,
                        risk_score=draft.risk_score,
                        title=draft.title,
                        evidence=draft.evidence,
                        recommendation=draft.recommendation,
                    )
                )

            self._complete_scan(scan, target, endpoints, drafts)
            db.commit()
            return db.scalar(select(Scan).where(Scan.id == scan.id).options(selectinload(Scan.findings))) or scan
        except Exception as exc:
            scan.status = ScanStatus.failed.value
            scan.summary = f"Scan failed: {exc}"
            scan.completed_at = datetime.now(UTC)
            db.commit()
            raise

    def _load_endpoints(self, db: Session, target: ApiTarget, endpoint_ids: list[int] | None) -> list[Endpoint]:
        stmt = select(Endpoint).where(
            Endpoint.target_id == target.id,
            Endpoint.method.in_(SAFE_METHODS),
            Endpoint.is_active.is_(True),
        )
        if endpoint_ids:
            stmt = stmt.where(Endpoint.id.in_(endpoint_ids))
        return list(db.scalars(stmt.order_by(Endpoint.path, Endpoint.method)))

    def _complete_scan(self, scan: Scan, target: ApiTarget, endpoints: list[Endpoint], drafts: list[FindingDraft]) -> None:
        counts = Counter(draft.severity for draft in drafts)
        risk = calculate_risk_score(drafts, endpoints)
        scan.total_risk_score = risk.total_score
        scan.max_severity = max(
            (draft.severity for draft in drafts),
            key=lambda severity: SEVERITY_ORDER.get(severity, 0),
            default=None,
        )
        scan.critical_count = counts.get("Critical", 0)
        scan.high_count = counts.get("High", 0)
        scan.medium_count = counts.get("Medium", 0)
        scan.low_count = counts.get("Low", 0)
        scan.status = ScanStatus.completed.value
        scan.completed_at = datetime.now(UTC)
        scan.summary = f"Completed {len(endpoints)} safe endpoint checks with {len(drafts)} findings. {risk.explanation}"
        target.risk_score = scan.total_risk_score
        target.last_scan_at = scan.completed_at


def run_scan(db: Session, target: ApiTarget, endpoint_ids: list[int] | None = None) -> Scan:
    return ScanManager().run(db=db, target=target, endpoint_ids=endpoint_ids)
