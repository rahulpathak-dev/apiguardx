from app.scanner.types import FindingDraft, ResponseSnapshot


CORS_PROBE_ORIGIN = "https://apiguardx.invalid"
PUBLIC_SUCCESS_STATUSES = {200, 201, 204}
UNSAFE_CORS_METHODS = {"DELETE", "PATCH", "PUT", "TRACE"}
RISK_BY_SEVERITY = {"Low": 5, "Medium": 12, "High": 25, "Critical": 40}


def check_cors(snapshot: ResponseSnapshot) -> list[FindingDraft]:
    headers = _headers_lower(snapshot.headers)
    allow_origin = headers.get("access-control-allow-origin", "").strip()
    allow_credentials = headers.get("access-control-allow-credentials", "").strip().lower() == "true"
    allow_methods = _header_tokens(headers.get("access-control-allow-methods", ""))
    allow_headers = _header_tokens(headers.get("access-control-allow-headers", ""))
    vary_values = _header_tokens(headers.get("vary", ""))

    findings: list[FindingDraft] = []

    if allow_origin == "*" and allow_credentials:
        findings.append(
            _finding(
                snapshot=snapshot,
                severity="Critical",
                title="Wildcard CORS origin allows credentialed requests",
                evidence="Access-Control-Allow-Origin is '*' and Access-Control-Allow-Credentials is true.",
                business_risk="Browsers may expose authenticated API responses to untrusted origins if clients send credentials.",
                remediation="Do not combine wildcard origins with credentials. Use an explicit allowlist of trusted origins and disable credentialed CORS unless required.",
            )
        )
    elif allow_origin == "*":
        findings.append(
            _finding(
                snapshot=snapshot,
                severity="Medium",
                title="Wildcard CORS origin allowed",
                evidence="Access-Control-Allow-Origin is '*'.",
                business_risk="Any website can read responses from this endpoint when browser CORS rules apply.",
                remediation="Replace wildcard CORS with a minimal trusted-origin allowlist for production APIs.",
            )
        )

    if allow_origin.lower() == CORS_PROBE_ORIGIN.lower():
        severity = "Critical" if allow_credentials else "High"
        findings.append(
            _finding(
                snapshot=snapshot,
                severity=severity,
                title="CORS origin reflection observed",
                evidence=f"The response reflected the scanner's benign Origin header: {CORS_PROBE_ORIGIN}.",
                business_risk="Origin reflection can allow attacker-controlled sites to read API responses, especially when credentials are enabled.",
                remediation="Validate Origin against a strict allowlist before echoing it. Return no CORS header for untrusted origins.",
            )
        )

    if allow_origin.lower() == "null":
        findings.append(
            _finding(
                snapshot=snapshot,
                severity="Medium",
                title="Null CORS origin allowed",
                evidence="Access-Control-Allow-Origin is 'null'.",
                business_risk="Sandboxed, local, or opaque origins may be able to read API responses unexpectedly.",
                remediation="Avoid allowing the null origin unless there is a documented business requirement and compensating controls.",
            )
        )

    unsafe_methods = sorted(method for method in allow_methods if method == "*" or method in UNSAFE_CORS_METHODS)
    if unsafe_methods:
        severity = "High" if allow_credentials or allow_origin in {"*", CORS_PROBE_ORIGIN} else "Medium"
        findings.append(
            _finding(
                snapshot=snapshot,
                severity=severity,
                title="Unsafe CORS methods allowed",
                evidence=f"Access-Control-Allow-Methods includes: {', '.join(unsafe_methods)}.",
                business_risk="Cross-origin browser clients may be permitted to invoke state-changing API methods.",
                remediation="Limit CORS methods to the minimum required safe methods for browser clients. Avoid wildcard methods.",
            )
        )

    if "*" in allow_headers:
        findings.append(
            _finding(
                snapshot=snapshot,
                severity="Medium",
                title="Wildcard CORS request headers allowed",
                evidence="Access-Control-Allow-Headers is '*'.",
                business_risk="Untrusted browser clients may send arbitrary headers in cross-origin requests, increasing exposure of browser-accessible API surfaces.",
                remediation="Use an explicit allowlist of required request headers instead of wildcard request headers.",
            )
        )

    if _is_dynamic_origin(allow_origin) and "origin" not in vary_values:
        findings.append(
            _finding(
                snapshot=snapshot,
                severity="Low",
                title="Dynamic CORS response missing Vary: Origin",
                evidence="A specific Access-Control-Allow-Origin value was returned without Vary: Origin.",
                business_risk="Shared caches may serve a response authorized for one origin to another origin.",
                remediation="Add Vary: Origin whenever CORS responses depend on the request Origin header.",
            )
        )

    if snapshot.status_code in PUBLIC_SUCCESS_STATUSES and not allow_origin:
        findings.append(
            _finding(
                snapshot=snapshot,
                severity="Low",
                title="CORS restrictions are not declared",
                evidence="No Access-Control-Allow-Origin header was returned for a successful response.",
                business_risk="Browser clients may experience inconsistent access controls if CORS is configured elsewhere or added by an upstream gateway.",
                remediation="Document the intended browser access policy. If browser access is required, enforce CORS centrally with an explicit trusted-origin allowlist.",
            )
        )

    return findings


def _finding(snapshot: ResponseSnapshot, severity: str, title: str, evidence: str, business_risk: str, remediation: str) -> FindingDraft:
    return FindingDraft(
        endpoint_path=snapshot.endpoint_path,
        check_name="cors_policy",
        severity=severity,
        title=title,
        evidence=f"Affected endpoint: {snapshot.endpoint_path}. {evidence} Business risk: {business_risk}",
        recommendation=f"Remediation advice: {remediation}",
        risk_score=RISK_BY_SEVERITY[severity],
    )


def _headers_lower(headers: dict[str, str]) -> dict[str, str]:
    return {key.lower(): value for key, value in headers.items()}


def _header_tokens(value: str) -> set[str]:
    return {token.strip().lower() if token.strip().lower() == "origin" else token.strip().upper() for token in value.split(",") if token.strip()}


def _is_dynamic_origin(allow_origin: str) -> bool:
    return bool(allow_origin and allow_origin != "*" and allow_origin.lower() != "null")
