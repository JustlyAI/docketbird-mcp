"""Tests for the security utilities in docketbird_mcp.py.

Covers path-traversal protection, SSRF download-URL allowlisting, filename
sanitization, the sliding-window rate limiter, client-IP extraction, and
API error formatting. All pure/fast - no network, no DB.
"""

from pathlib import Path

import httpx
import pytest

from docketbird_mcp import (
    ALLOWED_DOWNLOAD_DOMAINS,
    RateLimiter,
    get_client_ip,
    handle_api_error,
    sanitize_filename,
    validate_download_url,
    validate_save_path,
)


# ---------------------------------------------------------------------------
# validate_save_path
# ---------------------------------------------------------------------------


def test_validate_save_path_rejects_dotdot():
    with pytest.raises(ValueError, match="Path traversal"):
        validate_save_path("/tmp/../etc/passwd")


def test_validate_save_path_rejects_relative_dotdot():
    with pytest.raises(ValueError, match="Path traversal"):
        validate_save_path("../secrets")


def test_validate_save_path_returns_resolved_absolute(tmp_path):
    result = validate_save_path(str(tmp_path / "downloads"))
    assert isinstance(result, Path)
    assert result.is_absolute()


def test_validate_save_path_expands_user():
    result = validate_save_path("~/docketbird_downloads")
    assert "~" not in str(result)
    assert result.is_absolute()


# ---------------------------------------------------------------------------
# validate_download_url (SSRF protection)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "url",
    [
        "https://s3.amazonaws.com/bucket/file.pdf",
        "https://docketbird.s3.amazonaws.com/file.pdf",
        "https://api.docketbird.com/documents/1",
        "https://sub.s3.amazonaws.com/file.pdf",  # subdomain of allowed domain
    ],
)
def test_validate_download_url_allows_listed_domains(url):
    assert validate_download_url(url) == url


def test_validate_download_url_rejects_http():
    with pytest.raises(ValueError, match="scheme"):
        validate_download_url("http://s3.amazonaws.com/file.pdf")


def test_validate_download_url_rejects_unknown_domain():
    with pytest.raises(ValueError, match="not allowed"):
        validate_download_url("https://evil.com/file.pdf")


def test_validate_download_url_rejects_lookalike_suffix():
    # "notamazonaws.com" must not pass the endswith(".s3.amazonaws.com") check
    with pytest.raises(ValueError, match="not allowed"):
        validate_download_url("https://s3.amazonaws.com.evil.com/file.pdf")


def test_allowed_domains_is_nonempty():
    # Guard against an accidental empty allowlist (would still reject everything,
    # but signals misconfiguration if it ever happens).
    assert ALLOWED_DOWNLOAD_DOMAINS


# ---------------------------------------------------------------------------
# sanitize_filename
# ---------------------------------------------------------------------------


def test_sanitize_filename_strips_path_and_query():
    assert sanitize_filename("https://s3.amazonaws.com/a/b/doc.pdf?sig=abc") == "doc.pdf"


def test_sanitize_filename_replaces_unsafe_chars():
    result = sanitize_filename("my file (1).pdf")
    assert " " not in result
    assert "(" not in result
    assert result.endswith(".pdf")


def test_sanitize_filename_strips_leading_dots():
    # Prevents hidden files / traversal via leading dots
    assert not sanitize_filename("...hidden").startswith(".")


def test_sanitize_filename_empty_falls_back():
    assert sanitize_filename("https://host/path/?q=1") == "document.pdf"


def test_sanitize_filename_truncates_long_names():
    long_name = "a" * 500 + ".pdf"
    assert len(sanitize_filename(long_name)) <= 255


# ---------------------------------------------------------------------------
# RateLimiter
# ---------------------------------------------------------------------------


def test_rate_limiter_allows_under_limit():
    limiter = RateLimiter(max_requests=3, window_seconds=60)
    assert all(limiter.is_allowed("1.2.3.4") for _ in range(3))


def test_rate_limiter_blocks_over_limit():
    limiter = RateLimiter(max_requests=3, window_seconds=60)
    for _ in range(3):
        limiter.is_allowed("1.2.3.4")
    assert limiter.is_allowed("1.2.3.4") is False


def test_rate_limiter_is_per_ip():
    limiter = RateLimiter(max_requests=1, window_seconds=60)
    assert limiter.is_allowed("1.1.1.1") is True
    # A different IP has its own independent budget
    assert limiter.is_allowed("2.2.2.2") is True
    # The first IP is now exhausted
    assert limiter.is_allowed("1.1.1.1") is False


# ---------------------------------------------------------------------------
# get_client_ip
# ---------------------------------------------------------------------------


def _scope(headers=None, client=None):
    return {"headers": headers or [], "client": client}


def test_get_client_ip_uses_last_xff_value():
    # Caddy appends the real client IP last; we must trust the last entry.
    scope = _scope(headers=[(b"x-forwarded-for", b"1.1.1.1, 2.2.2.2, 9.9.9.9")])
    assert get_client_ip(scope) == "9.9.9.9"


def test_get_client_ip_falls_back_to_scope_client():
    scope = _scope(client=("8.8.8.8", 12345))
    assert get_client_ip(scope) == "8.8.8.8"


def test_get_client_ip_unknown_when_nothing_available():
    assert get_client_ip(_scope()) == "unknown"


# ---------------------------------------------------------------------------
# handle_api_error
# ---------------------------------------------------------------------------


def _http_status_error(code: int) -> httpx.HTTPStatusError:
    request = httpx.Request("GET", "https://api.docketbird.com/x")
    response = httpx.Response(code, request=request)
    return httpx.HTTPStatusError("err", request=request, response=response)


@pytest.mark.parametrize(
    "code,needle",
    [
        (401, "Authentication failed"),
        (403, "forbidden"),
        (404, "not found"),
        (429, "Rate limited"),
        (504, "Gateway timeout"),
    ],
)
def test_handle_api_error_maps_status_codes(code, needle):
    msg = handle_api_error(_http_status_error(code), "operation")
    assert needle.lower() in msg.lower()


def test_handle_api_error_handles_timeout():
    msg = handle_api_error(httpx.TimeoutException("slow"), "fetch")
    assert "timed out" in msg.lower()


def test_handle_api_error_handles_connect_error():
    msg = handle_api_error(httpx.ConnectError("no route"), "fetch")
    assert "connection failed" in msg.lower()


def test_handle_api_error_generic_fallback():
    msg = handle_api_error(RuntimeError("boom"), "fetch")
    assert "fetch" in msg
