import re
from dataclasses import dataclass
from re import Pattern

from app.scanner.types import FindingDraft, ResponseSnapshot


RISK_BY_SEVERITY = {"Low": 5, "Medium": 12, "High": 25, "Critical": 40}
MAX_EVIDENCE_CHARS = 180


@dataclass(frozen=True)
class ErrorTraceRule:
    check_name: str
    title: str
    severity: str
    pattern: Pattern[str]
    remediation: str


ERROR_TRACE_RULES = [
    ErrorTraceRule(
        check_name="python_stack_trace",
        title="Python stack trace exposed in response",
        severity="High",
        pattern=re.compile(r"Traceback \(most recent call last\):[\s\S]{0,1200}?(?:[A-Z][A-Za-z_]+(?:Error|Exception):[^\r\n<]*)", re.I),
        remediation="Disable debug mode, catch unexpected exceptions, and return sanitized API error responses without stack traces.",
    ),
    ErrorTraceRule(
        check_name="java_stack_trace",
        title="Java stack trace exposed in response",
        severity="High",
        pattern=re.compile(r"(?:[a-zA-Z_$][\w$]*\.)+[A-Za-z_$][\w$]*(?:Exception|Error)[\s\S]{0,800}?\bat\s+(?:[\w$]+\.)+[\w$]+\([^\r\n)]*\.java:\d+\)", re.I),
        remediation="Configure production exception handlers and application servers to suppress Java stack traces in client responses.",
    ),
    ErrorTraceRule(
        check_name="node_stack_trace",
        title="Node.js exception stack exposed in response",
        severity="High",
        pattern=re.compile(r"(?:TypeError|ReferenceError|SyntaxError|RangeError|Error):[^\r\n<]*[\s\S]{0,800}?\bat\s+[^\r\n]+:\d+:\d+", re.I),
        remediation="Disable verbose error handlers and return generic API errors while logging Node.js stack traces server-side.",
    ),
    ErrorTraceRule(
        check_name="framework_debug_error",
        title="Framework debug error page exposed",
        severity="High",
        pattern=re.compile(r"Werkzeug Debugger|Django Version|Laravel Framework|Rails\.root|Spring Boot Whitelabel Error Page|Starlette Debugger|FastAPI error|Express error handler", re.I),
        remediation="Disable framework debug mode in production and configure a sanitized global exception handler.",
    ),
    ErrorTraceRule(
        check_name="sql_error",
        title="SQL/database error exposed in response",
        severity="High",
        pattern=re.compile(r"SQL syntax.*MySQL|PostgreSQL.*ERROR|ORA-\d{5}|SQLSTATE\[[^\]]+\]|SQLite(?:3)?::SQLException|Microsoft OLE DB Provider for SQL Server|Unclosed quotation mark after the character string", re.I),
        remediation="Return generic database error messages to clients, log detailed database errors internally, and review affected queries for safe parameterization.",
    ),
    ErrorTraceRule(
        check_name="source_file_path",
        title="Server file path exposed in response",
        severity="Medium",
        pattern=re.compile(r"(?:/[A-Za-z0-9_.-]+){2,}/[A-Za-z0-9_.-]+\.(?:py|js|ts|java|php|rb|go|cs)|[A-Za-z]:\\(?:[^\\/:*?\"<>|\r\n]+\\)+[^\\/:*?\"<>|\r\n]+\.(?:py|js|ts|java|php|rb|go|cs)", re.I),
        remediation="Remove absolute file paths from client-facing errors and map exceptions to sanitized response bodies.",
    ),
    ErrorTraceRule(
        check_name="internal_server_detail",
        title="Internal server detail exposed in response",
        severity="Medium",
        pattern=re.compile(r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|127\.0\.0\.1(?::\d+)?|localhost:\d+)\b|\b(?:hostname|container|pod|instance|node)\s*[:=]\s*[A-Za-z0-9_.-]+", re.I),
        remediation="Avoid exposing hostnames, internal IP addresses, container names, or infrastructure identifiers in API responses.",
    ),
]


def check_error_traces(snapshot: ResponseSnapshot) -> list[FindingDraft]:
    findings: list[FindingDraft] = []
    seen_titles: set[str] = set()

    for rule in ERROR_TRACE_RULES:
        match = rule.pattern.search(snapshot.body)
        if match is None or rule.title in seen_titles:
            continue
        seen_titles.add(rule.title)
        findings.append(
            FindingDraft(
                endpoint_path=snapshot.endpoint_path,
                check_name=rule.check_name,
                severity=rule.severity,
                title=rule.title,
                evidence=f"Affected endpoint: {snapshot.endpoint_path}. Matched evidence: {_snippet(match.group(0))}",
                recommendation=rule.remediation,
                risk_score=RISK_BY_SEVERITY[rule.severity],
            )
        )

    return findings


def _snippet(value: str) -> str:
    normalized = re.sub(r"\s+", " ", value).strip()
    if len(normalized) <= MAX_EVIDENCE_CHARS:
        return normalized
    return f"{normalized[: MAX_EVIDENCE_CHARS - 3]}..."
