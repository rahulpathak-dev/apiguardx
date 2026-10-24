import argparse
import sys
from dataclasses import dataclass

import httpx

from app.scanner.checks import ResponseSnapshot, check_cors, check_exposed_secrets, check_security_headers, check_stack_traces, score_findings


@dataclass(frozen=True)
class CliEndpoint:
    path: str


def scan(base_url: str, path: str) -> int:
    url = f"{base_url.rstrip('/')}/{path.lstrip('/')}"
    response = httpx.get(url, timeout=8.0, follow_redirects=False, headers={"User-Agent": "APIGuardX-CI/1.0"})
    snapshot = ResponseSnapshot(
        url=url,
        endpoint_path=path if path.startswith("/") else f"/{path}",
        status_code=response.status_code,
        headers=dict(response.headers),
        body=response.text[:512_000],
    )
    findings = []
    for check in [check_cors, check_security_headers, check_stack_traces, check_exposed_secrets]:
        findings.extend(check(snapshot))
    risk = score_findings(findings)
    print(f"APIGuardX CI scan risk score: {risk}/100")
    for finding in findings:
        print(f"[{finding.severity}] {finding.endpoint_path} - {finding.title}")
    return 1 if any(f.severity in {"High", "Critical"} for f in findings) else 0


def main() -> int:
    parser = argparse.ArgumentParser(description="APIGuardX authorized CI scanner")
    subparsers = parser.add_subparsers(dest="command", required=True)
    scan_parser = subparsers.add_parser("scan")
    scan_parser.add_argument("--base-url", required=True)
    scan_parser.add_argument("--path", required=True)
    args = parser.parse_args()
    if args.command == "scan":
        return scan(args.base_url, args.path)
    return 2


if __name__ == "__main__":
    sys.exit(main())

