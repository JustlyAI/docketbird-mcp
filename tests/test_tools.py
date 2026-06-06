"""Async tests for the DocketBird tools and the streaming download helper.

Network access is faked by monkeypatching ``make_request`` / ``get_http_client``
so these run fully offline.
"""

import os

os.environ.setdefault("DATA_DIR", "/tmp/docketbird-test-data")

import pytest

import docketbird_mcp as d


@pytest.fixture(autouse=True)
def _fake_auth(monkeypatch):
    """Every tool calls get_user_api_key(); give it a dummy key."""
    monkeypatch.setattr(d, "get_user_api_key", lambda: "test-key")


def _fake_api(documents=None, cases=None):
    docs = documents if documents is not None else [
        {"id": i, "title": f"doc {i}", "filing_date": "2020-01-01"} for i in range(45)
    ]
    case_rows = cases if cases is not None else [
        {"id": i, "title": f"case {i}", "court_id": "txnd"} for i in range(45)
    ]

    async def fake_make_request(endpoint, params=None, api_key=""):
        if endpoint == "/documents":
            return {"data": {"case": {"title": "T"}, "parties": [], "documents": docs}}
        if endpoint.startswith("/cases/"):
            return {"data": {"case": {}}}
        if endpoint == "/cases":
            return {"data": {"cases": case_rows}}
        return {"data": {}}

    return fake_make_request


# --------------------------------------------------------------------------- #
# Pagination-crash regressions (page_size=0 / page<1 used to raise / misbehave)
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_get_case_details_handles_zero_page_size(monkeypatch):
    monkeypatch.setattr(d, "make_request", _fake_api())
    out = await d.docketbird_get_case_details("txnd-1:2020-cv-1", page=0, page_size=0)
    assert "# Case:" in out
    assert "page 1/" in out  # clamped, no ZeroDivisionError


@pytest.mark.asyncio
async def test_list_cases_handles_zero_page_size(monkeypatch):
    monkeypatch.setattr(d, "make_request", _fake_api())
    out = await d.docketbird_list_cases("user", page=0, page_size=0)
    assert "Cases (page 1/" in out


@pytest.mark.asyncio
async def test_search_documents_handles_zero_page_size(monkeypatch):
    monkeypatch.setattr(d, "make_request", _fake_api())
    out = await d.docketbird_search_documents("txnd-1:2020-cv-1", "doc", page=0, page_size=0)
    assert "Found 45 documents" in out


# --------------------------------------------------------------------------- #
# list_courts: returns all courts (not just the first 20) + search filter
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_list_courts_returns_all():
    out = await d.docketbird_list_courts()
    # There are 300+ courts; the old code capped at 20.
    court_lines = [ln for ln in out.splitlines() if ln.startswith("- **")]
    assert len(court_lines) > 100


@pytest.mark.asyncio
async def test_list_courts_search_filters():
    out = await d.docketbird_list_courts(search="california")
    assert "matching 'california'" in out
    assert "California" in out
    # Far fewer than the full list.
    court_lines = [ln for ln in out.splitlines() if ln.startswith("- **")]
    assert 0 < len(court_lines) < 50


@pytest.mark.asyncio
async def test_list_courts_search_no_match():
    out = await d.docketbird_list_courts(search="zzzznotacourt")
    assert "No courts matched" in out


# --------------------------------------------------------------------------- #
# Streaming download helper: size cap + partial-file cleanup
# --------------------------------------------------------------------------- #


class _FakeResponse:
    def __init__(self, chunks, headers=None):
        self._chunks = chunks
        self.headers = headers or {}

    def raise_for_status(self):
        return None

    async def aiter_bytes(self, chunk_size=8192):
        for c in self._chunks:
            yield c


class _FakeStreamCtx:
    def __init__(self, resp):
        self._resp = resp

    async def __aenter__(self):
        return self._resp

    async def __aexit__(self, *exc):
        return False


class _FakeClient:
    def __init__(self, chunks, headers=None):
        self._chunks = chunks
        self._headers = headers

    def stream(self, method, url):
        return _FakeStreamCtx(_FakeResponse(self._chunks, self._headers))


@pytest.mark.asyncio
async def test_stream_to_file_writes_bytes(monkeypatch, tmp_path):
    monkeypatch.setattr(d, "get_http_client", lambda: _FakeClient([b"hello ", b"world"]))
    dest = tmp_path / "out.pdf"
    n = await d._stream_to_file("https://docketbird.s3.amazonaws.com/x.pdf", dest)
    assert n == 11
    assert dest.read_bytes() == b"hello world"


@pytest.mark.asyncio
async def test_stream_to_file_enforces_size_cap(monkeypatch, tmp_path):
    monkeypatch.setattr(d, "MAX_DOWNLOAD_SIZE", 10)
    monkeypatch.setattr(d, "get_http_client", lambda: _FakeClient([b"x" * 8, b"y" * 8]))
    dest = tmp_path / "big.pdf"
    with pytest.raises(d.DownloadTooLarge):
        await d._stream_to_file("https://docketbird.s3.amazonaws.com/big.pdf", dest)
    # Partial file must be cleaned up.
    assert not dest.exists()


@pytest.mark.asyncio
async def test_stream_to_file_rejects_bad_domain(monkeypatch, tmp_path):
    monkeypatch.setattr(d, "get_http_client", lambda: _FakeClient([b"x"]))
    with pytest.raises(ValueError):
        await d._stream_to_file("https://evil.example.com/x.pdf", tmp_path / "x.pdf")
