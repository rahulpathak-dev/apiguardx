from time import perf_counter, sleep
from urllib.parse import urljoin

import httpx

from app.core.config import settings
from app.core.url_security import assert_safe_target_url
from app.models import ApiTarget, Endpoint
from app.scanner.cors import CORS_PROBE_ORIGIN
from app.scanner.types import ResponseSnapshot


SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}
SCANNER_USER_AGENT = "APIGuardX/1.0"
MAX_RATE_LIMIT_PROBE_REQUESTS = 5


class UnsafeMethodError(ValueError):
    pass


class SafeHttpClient:
    def __init__(
        self,
        transport: httpx.BaseTransport | None = None,
        rate_limit_probe_count: int | None = None,
        rate_limit_probe_delay_seconds: float | None = None,
    ) -> None:
        timeout = httpx.Timeout(settings.scanner_timeout_seconds)
        self._client = httpx.Client(timeout=timeout, follow_redirects=False, transport=transport)
        configured_count = rate_limit_probe_count if rate_limit_probe_count is not None else settings.scanner_rate_limit_probe_count
        self._rate_limit_probe_count = max(1, min(int(configured_count), MAX_RATE_LIMIT_PROBE_REQUESTS))
        configured_delay = (
            rate_limit_probe_delay_seconds
            if rate_limit_probe_delay_seconds is not None
            else settings.scanner_rate_limit_probe_delay_seconds
        )
        self._rate_limit_probe_delay_seconds = max(0.0, float(configured_delay))

    def __enter__(self) -> "SafeHttpClient":
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        self.close()

    def close(self) -> None:
        self._client.close()

    def build_url(self, target: ApiTarget, endpoint: Endpoint) -> str:
        base_url = target.base_url.rstrip("/")
        assert_safe_target_url(base_url)
        return urljoin(f"{base_url}/", endpoint.path.lstrip("/"))

    def execute(self, target: ApiTarget, endpoint: Endpoint) -> ResponseSnapshot:
        method = endpoint.method.upper()
        if method not in SAFE_METHODS:
            raise UnsafeMethodError(f"Unsafe method blocked: {method}")

        url = self.build_url(target, endpoint)
        assert_safe_target_url(url)
        request_headers = {"User-Agent": SCANNER_USER_AGENT, "Origin": CORS_PROBE_ORIGIN}
        started_at = perf_counter()
        response = self._client.request(method, url, headers=request_headers)
        elapsed_ms = (perf_counter() - started_at) * 1000
        observed_statuses = [response.status_code]

        for _ in range(self._rate_limit_probe_count - 1):
            if observed_statuses[-1] == 429:
                break
            if self._rate_limit_probe_delay_seconds > 0:
                sleep(self._rate_limit_probe_delay_seconds)
            try:
                probe_response = self._client.request(method, url, headers=request_headers)
            except httpx.HTTPError:
                break
            observed_statuses.append(probe_response.status_code)
            if probe_response.status_code == 429:
                break

        body = response.content[: settings.scanner_max_response_bytes].decode(response.encoding or "utf-8", errors="replace")
        return ResponseSnapshot(
            url=url,
            endpoint_path=endpoint.path,
            status_code=response.status_code,
            headers=dict(response.headers),
            body=body,
            method=method,
            elapsed_ms=elapsed_ms,
            observed_statuses=tuple(observed_statuses),
        )
