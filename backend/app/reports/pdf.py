from collections import Counter
from datetime import UTC, datetime
from html import escape
from io import BytesIO

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import LETTER
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from app.models import Scan


SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
SEVERITY_COLORS = {
    "Critical": "#991b1b",
    "High": "#dc2626",
    "Medium": "#d97706",
    "Low": "#2563eb",
}


def build_scan_pdf(scan: Scan) -> bytes:
    buffer = BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=LETTER,
        title=f"APIGuardX Security Report - Scan {scan.id}",
        rightMargin=0.55 * inch,
        leftMargin=0.55 * inch,
        topMargin=0.55 * inch,
        bottomMargin=0.55 * inch,
    )
    styles = _styles()
    story: list = []

    story.extend(_cover(scan, styles))
    story.extend(_executive_summary(scan, styles))
    story.extend(_metadata(scan, styles))
    story.extend(_severity_summary(scan, styles))
    story.extend(_detailed_findings(scan, styles))
    story.extend(_compliance_notes(styles))

    doc.build(story, onFirstPage=_footer, onLaterPages=_footer)
    return buffer.getvalue()


def _cover(scan: Scan, styles) -> list:
    target = scan.target
    generated_at = datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC")
    return [
        Paragraph("APIGuardX", styles["Title"]),
        Paragraph("Enterprise API Security Scan Report", styles["Subtitle"]),
        Spacer(1, 12),
        _risk_banner(scan, styles),
        Spacer(1, 12),
        _kv_table(
            [
                ("Target API", target.name),
                ("Base URL", target.base_url),
                ("Scan ID", str(scan.id)),
                ("Status", scan.status.title()),
                ("Generated", generated_at),
            ]
        ),
        Spacer(1, 18),
        Paragraph(
            "This report summarizes a safe, authorized, low-risk API security scan. APIGuardX uses non-destructive HTTP checks and does not perform credential theft, brute force, exploit chaining, session attacks, or destructive payloads.",
            styles["Body"],
        ),
        Spacer(1, 18),
    ]


def _executive_summary(scan: Scan, styles) -> list:
    finding_count = len(scan.findings)
    critical_high = scan.critical_count + scan.high_count
    if finding_count == 0:
        narrative = "No security findings were recorded during this scan. Continue periodic scanning and confirm that endpoint coverage remains complete."
    elif critical_high:
        narrative = f"The scan identified {finding_count} finding(s), including {critical_high} high-impact item(s). Prioritize remediation for Critical and High findings before expanding API exposure."
    else:
        narrative = f"The scan identified {finding_count} finding(s), primarily lower-severity hardening opportunities. Address these items to improve defense in depth and reporting posture."
    return [
        Paragraph("Executive Summary", styles["Heading1"]),
        Paragraph(narrative, styles["Body"]),
        Spacer(1, 6),
        Paragraph(_safe_text(scan.risk_explanation), styles["Body"]),
        Spacer(1, 14),
    ]


def _metadata(scan: Scan, styles) -> list:
    target = scan.target
    started = _format_dt(scan.started_at)
    completed = _format_dt(scan.completed_at)
    return [
        Paragraph("Scan Metadata", styles["Heading1"]),
        _kv_table(
            [
                ("Project", target.name),
                ("Target Base URL", target.base_url),
                ("Authorization Confirmed", "Yes" if target.authorization_ack else "No"),
                ("Scan Started", started),
                ("Scan Completed", completed),
                ("Scanner Mode", "Safe passive and low-risk HTTP checks"),
                ("Total Findings", str(len(scan.findings))),
                ("Risk Grade", scan.risk_grade),
                ("Risk Score", f"{scan.total_risk_score}/100"),
            ]
        ),
        Spacer(1, 14),
    ]


def _severity_summary(scan: Scan, styles) -> list:
    rows = [
        ["Severity", "Count", "Risk Priority"],
        ["Critical", scan.critical_count, "Immediate remediation"],
        ["High", scan.high_count, "High priority"],
        ["Medium", scan.medium_count, "Planned remediation"],
        ["Low", scan.low_count, "Hardening backlog"],
    ]
    table = Table(rows, repeatRows=1, colWidths=[1.4 * inch, 1.0 * inch, 4.1 * inch])
    table.setStyle(_table_style())
    return [Paragraph("Severity Summary", styles["Heading1"]), table, Spacer(1, 14)]


def _detailed_findings(scan: Scan, styles) -> list:
    if not scan.findings:
        return [
            Paragraph("Detailed Findings", styles["Heading1"]),
            Paragraph("No findings were recorded for this scan.", styles["Body"]),
            Spacer(1, 14),
        ]

    story = [Paragraph("Detailed Findings", styles["Heading1"])]
    sorted_findings = sorted(scan.findings, key=lambda item: (SEVERITY_ORDER.get(item.severity, 99), item.endpoint_path, item.title))
    for index, finding in enumerate(sorted_findings, start=1):
        story.append(Paragraph(f"{index}. {_safe_text(finding.title)}", styles["Heading2"]))
        story.append(
            _kv_table(
                [
                    ("Severity", finding.severity),
                    ("Endpoint", finding.endpoint_path),
                    ("Check", finding.check_name),
                    ("Risk Contribution", f"{finding.risk_score}/100"),
                ]
            )
        )
        story.append(Spacer(1, 4))
        story.append(Paragraph("Evidence", styles["Heading3"]))
        story.append(Paragraph(_safe_text(finding.evidence), styles["BodySmall"]))
        story.append(Paragraph("Remediation Steps", styles["Heading3"]))
        story.append(Paragraph(_safe_text(finding.recommendation), styles["BodySmall"]))
        story.append(Spacer(1, 12))
    return story


def _compliance_notes(styles) -> list:
    notes = [
        "Maintain written authorization and asset ownership records for all scanned APIs.",
        "Treat Critical and High findings as remediation candidates for security review and change tracking.",
        "Retain scan reports as evidence for security monitoring, SDLC, SOC 2, ISO 27001, and internal risk-management workflows where applicable.",
        "Validate remediations with a follow-up safe scan and document accepted risks separately.",
    ]
    rows = [["Compliance-Style Note"]] + [[note] for note in notes]
    table = Table(rows, repeatRows=1, colWidths=[6.5 * inch])
    table.setStyle(_table_style())
    return [Paragraph("Compliance-Style Notes", styles["Heading1"]), table, Spacer(1, 8)]


def _risk_banner(scan: Scan, styles):
    color = _grade_color(scan.risk_grade)
    data = [[Paragraph("Risk Score", styles["BannerLabel"]), Paragraph("Grade", styles["BannerLabel"])], [Paragraph(f"{scan.total_risk_score}/100", styles["BannerValue"]), Paragraph(scan.risk_grade, styles["BannerValue"])]]
    table = Table(data, colWidths=[3.25 * inch, 3.25 * inch])
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor(color)),
                ("TEXTCOLOR", (0, 0), (-1, -1), colors.white),
                ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor(color)),
                ("TOPPADDING", (0, 0), (-1, -1), 8),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
            ]
        )
    )
    return table


def _kv_table(rows: list[tuple[str, str]]):
    data = [[Paragraph(f"<b>{_safe_text(label)}</b>", getSampleStyleSheet()["BodyText"]), Paragraph(_safe_text(str(value)), getSampleStyleSheet()["BodyText"])] for label, value in rows]
    table = Table(data, colWidths=[1.8 * inch, 4.7 * inch])
    table.setStyle(
        TableStyle(
            [
                ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#d1d5db")),
                ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#f8fafc")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("TOPPADDING", (0, 0), (-1, -1), 5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
            ]
        )
    )
    return table


def _table_style() -> TableStyle:
    return TableStyle(
        [
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#111827")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#d1d5db")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 8.5),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ]
    )


def _styles():
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name="Subtitle", parent=styles["Heading2"], alignment=TA_CENTER, textColor=colors.HexColor("#475569"), spaceAfter=8))
    styles.add(ParagraphStyle(name="Body", parent=styles["BodyText"], fontSize=9.5, leading=13))
    styles.add(ParagraphStyle(name="BodySmall", parent=styles["BodyText"], fontSize=8.5, leading=11))
    styles.add(ParagraphStyle(name="BannerLabel", parent=styles["BodyText"], alignment=TA_CENTER, fontSize=9, textColor=colors.white))
    styles.add(ParagraphStyle(name="BannerValue", parent=styles["Heading1"], alignment=TA_CENTER, fontSize=20, textColor=colors.white))
    return styles


def _footer(canvas, doc) -> None:
    canvas.saveState()
    canvas.setFont("Helvetica", 7)
    canvas.setFillColor(colors.HexColor("#64748b"))
    canvas.drawString(0.55 * inch, 0.35 * inch, "APIGuardX Security Report - authorized low-risk API scan")
    canvas.drawRightString(7.95 * inch, 0.35 * inch, f"Page {doc.page}")
    canvas.restoreState()


def _grade_color(grade: str) -> str:
    return {"A": "#047857", "B": "#0f766e", "C": "#d97706", "D": "#ea580c", "F": "#dc2626"}.get(grade, "#334155")


def _safe_text(value: str | None) -> str:
    return escape(value or "")


def _format_dt(value) -> str:
    return value.strftime("%Y-%m-%d %H:%M UTC") if value else "Not recorded"
