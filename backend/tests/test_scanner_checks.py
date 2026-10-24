from app.scanner.checks import ResponseSnapshot, check_cors, check_exposed_secrets, check_missing_auth, check_rate_limit, check_security_headers, check_stack_traces, score_findings
from app.scanner.cors import CORS_PROBE_ORIGIN


def snapshot(headers: dict[str, str], body: str = "ok", endpoint_path: str = "/health", status_code: int = 200) -> ResponseSnapshot:
    return ResponseSnapshot(url=f"https://api.example.com{endpoint_path}", endpoint_path=endpoint_path, status_code=status_code, headers=headers, body=body)


def test_detects_wildcard_cors() -> None:
    findings = check_cors(snapshot({"Access-Control-Allow-Origin": "*"}))
    assert findings[0].severity == "Medium"
    assert findings[0].risk_score == 12
    assert "Affected endpoint: /health" in findings[0].evidence
    assert "Business risk:" in findings[0].evidence
    assert "Remediation advice:" in findings[0].recommendation


def test_detects_wildcard_cors_with_credentials() -> None:
    findings = check_cors(
        snapshot(
            {
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Credentials": "true",
            }
        )
    )
    assert findings[0].severity == "Critical"
    assert findings[0].risk_score == 40
    assert "credentialed" in findings[0].title.lower()


def test_detects_reflected_origin_behavior() -> None:
    findings = check_cors(snapshot({"Access-Control-Allow-Origin": CORS_PROBE_ORIGIN}))
    names = [finding.title for finding in findings]
    assert "CORS origin reflection observed" in names
    reflected = next(finding for finding in findings if finding.title == "CORS origin reflection observed")
    assert reflected.severity == "High"
    assert CORS_PROBE_ORIGIN in reflected.evidence


def test_detects_unsafe_cors_methods_and_wildcard_headers() -> None:
    findings = check_cors(
        snapshot(
            {
                "Access-Control-Allow-Origin": "https://app.example.com",
                "Access-Control-Allow-Methods": "GET, POST, DELETE, PATCH",
                "Access-Control-Allow-Headers": "*",
                "Vary": "Origin",
            }
        )
    )
    titles = {finding.title for finding in findings}
    assert "Unsafe CORS methods allowed" in titles
    assert "Wildcard CORS request headers allowed" in titles


def test_detects_missing_cors_restrictions_on_successful_response() -> None:
    findings = check_cors(snapshot({}))
    assert findings[0].title == "CORS restrictions are not declared"
    assert findings[0].severity == "Low"


def test_detects_missing_security_headers_individually() -> None:
    findings = check_security_headers(snapshot({}))
    titles = {finding.title for finding in findings}

    assert "Strict-Transport-Security header is missing" in titles
    assert "Content-Security-Policy header is missing" in titles
    assert "X-Content-Type-Options header is missing" in titles
    assert "X-Frame-Options header is missing" in titles
    assert "Referrer-Policy header is missing" in titles
    assert "Permissions-Policy header is missing" in titles
    assert all(finding.check_name == "security_headers" for finding in findings)
    assert all("Affected endpoint: /health" in finding.evidence for finding in findings)


def test_detects_weak_security_headers() -> None:
    findings = check_security_headers(
        snapshot(
            {
                "Strict-Transport-Security": "max-age=300",
                "Content-Security-Policy": "default-src *; script-src 'unsafe-inline'",
                "X-Content-Type-Options": "none",
                "X-Frame-Options": "ALLOW-FROM https://legacy.example.com",
                "Referrer-Policy": "unsafe-url",
                "Permissions-Policy": "geolocation=*",
            }
        )
    )
    titles = {finding.title for finding in findings}

    assert "Strict-Transport-Security max-age is short" in titles
    assert "Content-Security-Policy contains weak directives" in titles
    assert "X-Content-Type-Options header is weak" in titles
    assert "X-Frame-Options header is weak" in titles
    assert "Referrer-Policy header is weak" in titles
    assert "Permissions-Policy allows wildcard access" in titles


def test_security_headers_pass_when_strong() -> None:
    findings = check_security_headers(
        snapshot(
            {
                "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
                "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
                "X-Content-Type-Options": "nosniff",
                "X-Frame-Options": "DENY",
                "Referrer-Policy": "strict-origin-when-cross-origin",
                "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
            }
        )
    )

    assert findings == []


def test_detects_missing_cache_control_on_sensitive_endpoint() -> None:
    findings = check_security_headers(
        snapshot(
            {
                "Strict-Transport-Security": "max-age=31536000",
                "Content-Security-Policy": "default-src 'none'",
                "X-Content-Type-Options": "nosniff",
                "X-Frame-Options": "DENY",
                "Referrer-Policy": "same-origin",
                "Permissions-Policy": "camera=()",
            },
            endpoint_path="/v1/profile",
        )
    )

    assert findings[0].title == "Cache-Control is missing on sensitive endpoint"
    assert findings[0].severity == "High"
    assert "no-store" in findings[0].recommendation


def test_detects_weak_cache_control_on_sensitive_endpoint() -> None:
    findings = check_security_headers(
        snapshot(
            {
                "Strict-Transport-Security": "max-age=31536000",
                "Content-Security-Policy": "default-src 'none'",
                "X-Content-Type-Options": "nosniff",
                "X-Frame-Options": "DENY",
                "Referrer-Policy": "same-origin",
                "Permissions-Policy": "camera=()",
                "Cache-Control": "public, max-age=3600",
            },
            endpoint_path="/payments/history",
        )
    )

    assert findings[0].title == "Cache-Control is weak on sensitive endpoint"
    assert findings[0].severity == "High"
    assert "public caching is allowed" in findings[0].evidence


def test_detects_python_stack_trace() -> None:
    body = """
    Traceback (most recent call last):
      File "/srv/api/app.py", line 42, in handler
        raise ValueError("bad input")
    ValueError: bad input
    """
    findings = check_stack_traces(snapshot({}, body, status_code=500))

    assert findings[0].title == "Python stack trace exposed in response"
    assert findings[0].severity == "High"
    assert "Matched evidence:" in findings[0].evidence
    assert "Disable debug mode" in findings[0].recommendation


def test_detects_java_and_node_exceptions() -> None:
    java_findings = check_stack_traces(
        snapshot({}, "java.lang.NullPointerException\n    at com.example.Service.run(Service.java:42)", status_code=500)
    )
    node_findings = check_stack_traces(
        snapshot({}, "TypeError: Cannot read properties of undefined\n    at handler (/srv/app/index.js:12:7)", status_code=500)
    )

    assert java_findings[0].title == "Java stack trace exposed in response"
    assert node_findings[0].title == "Node.js exception stack exposed in response"


def test_detects_framework_debug_sql_file_paths_and_internal_details() -> None:
    body = """
    Werkzeug Debugger active
    PostgreSQL ERROR: relation users does not exist
    Template rendered from /srv/api/templates/error.py
    hostname=api-prod-01
    upstream=10.0.4.12
    """
    findings = check_stack_traces(snapshot({}, body, status_code=500))
    titles = {finding.title for finding in findings}

    assert "Framework debug error page exposed" in titles
    assert "SQL/database error exposed in response" in titles
    assert "Server file path exposed in response" in titles
    assert "Internal server detail exposed in response" in titles
    assert all(finding.recommendation for finding in findings)


def test_detects_possible_secret() -> None:
    findings = check_exposed_secrets(snapshot({}, "api_key='abcdefghijklmnopqrstuvwxyz123456'"))
    assert findings[0].severity == "High"
    assert "Masked evidence:" in findings[0].evidence


def test_missing_auth_only_flags_sensitive_public_endpoints() -> None:
    assert check_missing_auth(snapshot({})) == []

    findings = check_missing_auth(snapshot({}, endpoint_path="/admin/users"))

    assert findings[0].check_name == "missing_auth"
    assert findings[0].severity == "Critical"
    assert findings[0].risk_score == 40
    assert "publicly accessible" in findings[0].title.lower()
    assert "Unauthenticated safe GET request" in findings[0].evidence


def test_missing_auth_detects_profile_endpoint_exposure() -> None:
    findings = check_missing_auth(snapshot({}, endpoint_path="/v1/profile"))

    assert findings[0].severity == "High"
    assert findings[0].risk_score == 25
    assert "authentication and authorization" in findings[0].recommendation


def test_missing_auth_detects_inconsistent_auth_behavior() -> None:
    findings = check_missing_auth(
        ResponseSnapshot(
            url="https://api.example.com/profile",
            endpoint_path="/profile",
            status_code=200,
            headers={},
            body="{}",
            observed_statuses=(200, 401),
        )
    )

    assert {finding.check_name for finding in findings} == {"missing_auth", "inconsistent_auth"}
    inconsistent = next(finding for finding in findings if finding.check_name == "inconsistent_auth")
    assert inconsistent.severity == "Medium"
    assert inconsistent.risk_score == 12
    assert "200, 401" in inconsistent.evidence


def test_score_is_capped() -> None:
    findings = check_security_headers(snapshot({})) * 20
    assert score_findings(findings) <= 100


def test_detects_api_key_and_masks_evidence() -> None:
    raw_key = "abcdefghijklmnopqrstuvwxyz123456"
    findings = check_exposed_secrets(snapshot({}, f"api_key='{raw_key}'", endpoint_path="/config"))

    assert findings[0].title == "API key or token exposed in API response"
    assert findings[0].severity == "High"
    assert "Secret type: API key or token" in findings[0].evidence
    assert "Masked evidence: abcd***3456" in findings[0].evidence
    assert raw_key not in findings[0].evidence
    assert findings[0].endpoint_path == "/config"
    assert "rotate" in findings[0].recommendation.lower()


def test_detects_cloud_credentials_private_keys_and_masks_values() -> None:
    aws_key = "AKIA1234567890ABCDEF"
    private_key = "-----BEGIN PRIVATE KEY-----\nMIIEvAIBADANBgkqhkiG9w0BAQEFAASC\n-----END PRIVATE KEY-----"
    findings = check_exposed_secrets(snapshot({}, f"access={aws_key}\n{private_key}", endpoint_path="/debug"))
    titles = {finding.title for finding in findings}
    evidence = "\n".join(finding.evidence for finding in findings)

    assert "Cloud access key exposed in API response" in titles
    assert "Private key material exposed in API response" in titles
    assert aws_key not in evidence
    assert "-----BEGIN [MASKED PRIVATE KEY]-----" in evidence
    assert private_key not in evidence


def test_detects_database_url_and_masks_credentials() -> None:
    db_url = "postgresql://app_user:SuperSecretPassword@db.internal.local:5432/app"
    findings = check_exposed_secrets(snapshot({}, f"DATABASE_URL={db_url}", endpoint_path="/env"))

    assert findings[0].title == "Database connection URL exposed in API response"
    assert findings[0].severity == "Critical"
    assert "Secret type: database URL" in findings[0].evidence
    assert "postgresql://[MASKED]@db.internal.local:5432/app" in findings[0].evidence
    assert "SuperSecretPassword" not in findings[0].evidence


def test_detects_jwt_and_email_password_like_leaks() -> None:
    jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature123456789"
    password = "CorrectHorseBatteryStaple"
    body = f"token={jwt}\nemail='person@example.com', password='{password}'"
    findings = check_exposed_secrets(snapshot({}, body, endpoint_path="/session"))
    titles = {finding.title for finding in findings}
    evidence = "\n".join(finding.evidence for finding in findings)

    assert "JWT token exposed in API response" in titles
    assert "Email and password-like fields exposed together" in titles
    assert jwt not in evidence
    assert password not in evidence
    assert "person@example.com" not in evidence
    assert all(finding.recommendation for finding in findings)




def test_rate_limit_detects_suspicious_unlimited_access() -> None:
    findings = check_rate_limit(snapshot({}, endpoint_path="/v1/profile"), (200, 200, 200))

    assert findings[0].title == "Suspicious unlimited access during limited safe probe"
    assert findings[0].severity == "Medium"
    assert "3 delayed safe request" in findings[0].evidence
    assert "No HTTP 429" in findings[0].evidence
    assert "Apply rate limiting" in findings[0].recommendation


def test_rate_limit_detects_missing_headers_without_repeated_success() -> None:
    findings = check_rate_limit(snapshot({}, status_code=404), (404,))

    assert findings[0].title == "Rate-limit headers are missing"
    assert findings[0].severity == "Low"
    assert "No standard rate-limit headers" in findings[0].evidence


def test_rate_limit_accepts_429_response() -> None:
    findings = check_rate_limit(snapshot({"RateLimit-Limit": "60"}), (200, 429))

    assert findings == []


def test_rate_limit_detects_no_429_even_with_headers() -> None:
    findings = check_rate_limit(snapshot({"X-RateLimit-Limit": "60"}), (200, 200, 200))

    assert findings[0].title == "No rate-limit response observed during limited safe probe"
    assert findings[0].severity == "Low"
