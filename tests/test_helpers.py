"""Unit tests for pure helper functions in docketbird_mcp.

These cover the security helpers, pagination math, rate limiter, and reference
data loading — the parts that are easy to get subtly wrong and that several
tools depend on.
"""

import os

os.environ.setdefault("DATA_DIR", "/tmp/docketbird-test-data")

import httpx
import pytest

import docketbird_mcp as d

# --------------------------------------------------------------------------- #
# Pagination
# --------------------------------------------------------------------------- #


def test_clamp_pagination_floors_and_caps():
    assert d._clamp_pagination(1, 20) == (1, 20)
    assert d._clamp_pagination(0, 20) == (1, 20)          # page floored to 1
    assert d._clamp_pagination(-5, 20) == (1, 20)
    assert d._clamp_pagination(3, 999) == (3, d.MAX_PAGE_SIZE)  # page_size capped
    assert d._clamp_pagination(3, 0) == (3, 1)            # page_size floored to 1
    assert d._clamp_pagination(3, -1) == (3, 1)


def test_paginate_windows_and_total_pages():
    items = list(range(0, 45))
    page_items, total, total_pages = d._paginate(items, page=1, page_size=20)
    assert page_items == list(range(0, 20))
    assert total == 45
    assert total_pages == 3

    page_items, _, _ = d._paginate(items, page=3, page_size=20)
    assert page_items == [40, 41, 42, 43, 44]


def test_paginate_empty_list_is_one_page():
    page_items, total, total_pages = d._paginate([], page=1, page_size=20)
    assert page_items == []
    assert total == 0
    assert total_pages == 1


# --------------------------------------------------------------------------- #
# Filename sanitization
# --------------------------------------------------------------------------- #


def test_sanitize_filename_strips_path_and_query():
    assert d.sanitize_filename("https://x/a/b/doc.pdf?sig=abc") == "doc.pdf"


def test_sanitize_filename_neutralizes_traversal_and_hidden():
    out = d.sanitize_filename("../../etc/passwd")
    assert ".." not in out
    assert "/" not in out
    assert not out.startswith(".")


def test_sanitize_filename_empty_falls_back():
    assert d.sanitize_filename("https://x/?q=1") == "document.pdf"


# --------------------------------------------------------------------------- #
# URL / path validation (SSRF + traversal)
# --------------------------------------------------------------------------- #


def test_validate_download_url_allows_s3():
    url = "https://docketbird.s3.amazonaws.com/file.pdf"
    assert d.validate_download_url(url) == url


def test_validate_download_url_rejects_non_https():
    with pytest.raises(ValueError):
        d.validate_download_url("http://docketbird.s3.amazonaws.com/file.pdf")


def test_validate_download_url_rejects_foreign_domain():
    with pytest.raises(ValueError):
        d.validate_download_url("https://evil.example.com/file.pdf")


def test_validate_save_path_rejects_traversal():
    with pytest.raises(ValueError):
        d.validate_save_path("/tmp/../etc")


def test_validate_save_path_resolves_ok(tmp_path):
    resolved = d.validate_save_path(str(tmp_path))
    assert resolved == tmp_path.resolve()


def test_validate_save_path_allows_dotdot_substring_in_name():
    """'..' inside a path segment (not a traversal segment) is legitimate."""
    d.validate_save_path("my..docs")  # should not raise


def test_validate_save_path_still_rejects_dotdot_segment():
    with pytest.raises(ValueError):
        d.validate_save_path("a/../b")


# --------------------------------------------------------------------------- #
# Rate limiter
# --------------------------------------------------------------------------- #


def test_rate_limiter_blocks_after_max():
    rl = d.RateLimiter(max_requests=3, window_seconds=60)
    assert all(rl.is_allowed("1.2.3.4") for _ in range(3))
    assert rl.is_allowed("1.2.3.4") is False
    # A different IP is unaffected.
    assert rl.is_allowed("5.6.7.8") is True


def test_rate_limiter_prune_removes_idle(monkeypatch):
    rl = d.RateLimiter(max_requests=3, window_seconds=60)
    rl.is_allowed("1.2.3.4")
    # Jump time forward beyond the window so the entry is stale.
    real = d.time.monotonic()
    monkeypatch.setattr(d.time, "monotonic", lambda: real + 1000)
    assert rl.prune() == 1
    assert "1.2.3.4" not in rl._requests


# --------------------------------------------------------------------------- #
# Error formatting
# --------------------------------------------------------------------------- #


def _http_error(status: int, body=None) -> httpx.HTTPStatusError:
    request = httpx.Request("GET", "https://api.docketbird.com/x")
    response = httpx.Response(status, json=body or {}, request=request)
    return httpx.HTTPStatusError("err", request=request, response=response)


def test_handle_api_error_maps_status_codes():
    assert "Authentication failed" in d.handle_api_error(_http_error(401), "op")
    assert "not found" in d.handle_api_error(_http_error(404), "op").lower()
    assert "Rate limited" in d.handle_api_error(_http_error(429), "op")


def test_handle_api_error_includes_docketbird_message():
    msg = d.handle_api_error(_http_error(403, {"message": "Charges may apply."}), "op")
    assert "Charges may apply." in msg


def test_handle_api_error_timeout_and_connect():
    assert "timed out" in d.handle_api_error(httpx.TimeoutException("t"), "op")
    assert "Connection failed" in d.handle_api_error(httpx.ConnectError("c"), "op")
