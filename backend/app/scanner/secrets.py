import re
from dataclasses import dataclass
from re import Pattern
from urllib.parse import urlsplit, urlunsplit

from app.scanner.types import FindingDraft, ResponseSnapshot


RISK_BY_SEVERITY = {"Low": 5, "Medium": 12, "High": 25, "Critical": 40}
MAX_EVIDENCE_CHARS = 220


@dataclass(frozen=True)
class SecretRule:
    secret_type: str
    title: str
    severity: str
    pattern: Pattern[str]
    remediation: str


SECRET_RULES = [
    SecretRule(
        secret_type="AWS access key ID",
        title="Cloud access key exposed in API response",
        severity="Critical",
        pattern=re.compile(r"(?P<secret>AKIA[0-9A-Z]{16})"),
        remediation="Remove cloud access keys from API responses, rotate the exposed key, and use server-side secret storage or short-lived credentials.",
    ),
    SecretRule(
        secret_type="cloud secret access key",
        title="Cloud secret credential exposed in API response",
        severity="Critical",
        pattern=re.compile(r"(?i)\b(?:aws_secret_access_key|awsSecretAccessKey|cloud_secret|client_secret)\b\s*[:=]\s*[\"']?(?P<secret>[A-Za-z0-9/+=._\-]{32,})"),
        remediation="Remove cloud secret values from responses, rotate affected credentials, and store secrets in a managed secrets vault.",
    ),
    SecretRule(
        secret_type="private key",
        title="Private key material exposed in API response",
        severity="Critical",
        pattern=re.compile(r"(?P<secret>-----BEGIN (?:RSA |OPENSSH |EC |DSA )?PRIVATE KEY-----[\s\S]{0,2000}?-----END (?:RSA |OPENSSH |EC |DSA )?PRIVATE KEY-----)"),
        remediation="Remove private key material immediately, rotate the key pair, and ensure key files are never serialized into API responses.",
    ),
    SecretRule(
        secret_type="database URL",
        title="Database connection URL exposed in API response",
        severity="Critical",
        pattern=re.compile(r"(?P<secret>\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|sqlserver)://[^\s\"'<>]+)", re.I),
        remediation="Remove database connection strings from responses, rotate embedded credentials, and keep connection configuration server-side only.",
    ),
    SecretRule(
        secret_type="JWT token",
        title="JWT token exposed in API response",
        severity="High",
        pattern=re.compile(r"(?P<secret>eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,})"),
        remediation="Avoid returning unintended JWTs, revoke or expire exposed tokens where possible, and validate logs/responses do not leak authorization artifacts.",
    ),
    SecretRule(
        secret_type="API key or token",
        title="API key or token exposed in API response",
        severity="High",
        pattern=re.compile(r"(?i)\b(?:api[_-]?key|x-api-key|access[_-]?token|refresh[_-]?token|auth[_-]?token|bearer_token|secret)\b\s*[:=]\s*[\"']?(?P<secret>[A-Za-z0-9._~+/=\-]{20,})"),
        remediation="Remove API keys and tokens from responses, rotate exposed values, and return only references or scoped short-lived tokens when required.",
    ),
    SecretRule(
        secret_type="password-like credential",
        title="Password-like value exposed in API response",
        severity="High",
        pattern=re.compile(r"(?i)\b(?:password|passwd|pwd)\b\s*[:=]\s*[\"']?(?P<secret>[^\s\"',}]{8,})"),
        remediation="Never return password or password-like values. Remove the field, reset affected credentials, and store only salted password hashes server-side.",
    ),
    SecretRule(
        secret_type="email/password-like leak",
        title="Email and password-like fields exposed together",
        severity="Critical",
        pattern=re.compile(r"(?is)(?:email|username)\s*[:=]\s*[\"']?(?P<email>[A-Z0-9._%+\-]+@[A-Z0-9.\-]+\.[A-Z]{2,})[\"']?.{0,300}\b(?:password|passwd|pwd)\b\s*[:=]\s*[\"']?(?P<secret>[^\s\"',}]{8,})"),
        remediation="Remove credential fields from API responses, force reset for exposed accounts, and review serialization rules for user objects.",
    ),
]


def check_exposed_secrets(snapshot: ResponseSnapshot) -> list[FindingDraft]:
    findings: list[FindingDraft] = []
    seen: set[tuple[str, str]] = set()

    for rule in SECRET_RULES:
        for match in rule.pattern.finditer(snapshot.body):
            raw_secret = _match_secret(match)
            if not raw_secret:
                continue
            masked = _mask_secret(raw_secret, rule.secret_type)
            dedupe_key = (rule.secret_type, masked)
            if dedupe_key in seen:
                continue
            seen.add(dedupe_key)
            findings.append(
                FindingDraft(
                    endpoint_path=snapshot.endpoint_path,
                    check_name="exposed_secret",
                    severity=rule.severity,
                    title=rule.title,
                    evidence=(
                        f"Endpoint: {snapshot.endpoint_path}. Secret type: {rule.secret_type}. "
                        f"Masked evidence: {masked}."
                    ),
                    recommendation=rule.remediation,
                    risk_score=RISK_BY_SEVERITY[rule.severity],
                )
            )

    return findings


def _match_secret(match: re.Match[str]) -> str:
    if "secret" in match.groupdict() and match.group("secret"):
        return match.group("secret")
    return match.group(0)


def _mask_secret(value: str, secret_type: str) -> str:
    sanitized = re.sub(r"\s+", " ", value).strip()
    if secret_type == "private key":
        return "-----BEGIN [MASKED PRIVATE KEY]-----"
    if secret_type == "database URL":
        return _mask_database_url(sanitized)
    if len(sanitized) > MAX_EVIDENCE_CHARS:
        sanitized = sanitized[:MAX_EVIDENCE_CHARS]
    if len(sanitized) <= 8:
        return "[MASKED]"
    if len(sanitized) <= 16:
        return f"{sanitized[:2]}***{sanitized[-2:]}"
    return f"{sanitized[:4]}***{sanitized[-4:]}"


def _mask_database_url(value: str) -> str:
    try:
        parsed = urlsplit(value)
    except ValueError:
        return _mask_secret(value[:80], "database URL fallback")

    host = parsed.hostname or "host"
    port = f":{parsed.port}" if parsed.port else ""
    path = parsed.path or ""
    if parsed.username or parsed.password:
        netloc = f"[MASKED]@{host}{port}"
    else:
        netloc = f"{host}{port}"
    return urlunsplit((parsed.scheme, netloc, path, "", ""))
