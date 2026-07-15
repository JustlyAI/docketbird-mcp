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
# list_courts: live /courts endpoint (faked here) + static case-type appendix
# --------------------------------------------------------------------------- #


def _fake_courts_api(courts):
    async def fake_make_request(endpoint, params=None, api_key=""):
        assert endpoint == "/courts"
        rows = courts
        q = (params or {}).get("q") if params else None
        if q:
            rows = [c for c in courts if q.lower() in c["court_name"].lower()]
        return {"status": "success", "data": {"courts": rows, "count": len(rows)}}

    return fake_make_request


_COURTS = [
    {"court_id": "nysd", "court_name": "Southern District of New York", "court_system": "usa_federal", "timezone": "US/Eastern"},
    {"court_id": "cand", "court_name": "Northern District of California", "court_system": "usa_federal", "timezone": "US/Pacific"},
]


@pytest.mark.asyncio
async def test_list_courts_default_includes_case_types(monkeypatch):
    monkeypatch.setattr(d, "make_request", _fake_courts_api(_COURTS))
    out = await d.docketbird_list_courts()
    assert "## Courts (2)" in out
    assert "**nysd**: Southern District of New York" in out
    # The no-argument listing carries the case-type reference (static file).
    assert "## Case Types" in out
    assert "**cv**" in out


@pytest.mark.asyncio
async def test_list_courts_search_passes_q_and_skips_case_types(monkeypatch):
    monkeypatch.setattr(d, "make_request", _fake_courts_api(_COURTS))
    out = await d.docketbird_list_courts(search="california")
    assert "matching 'california'" in out
    assert "cand" in out and "nysd" not in out
    assert "## Case Types" not in out


@pytest.mark.asyncio
async def test_list_courts_search_no_match(monkeypatch):
    monkeypatch.setattr(d, "make_request", _fake_courts_api(_COURTS))
    out = await d.docketbird_list_courts(search="zzzznotacourt")
    assert "No courts matched" in out


# --------------------------------------------------------------------------- #
# Cursor-paginated search tools: footer contract + snippet rendering
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_search_cases_renders_cursor_footer(monkeypatch):
    async def fake(endpoint, params=None, api_key=""):
        assert endpoint == "/cases/search"
        assert params["q"] == "Natera"
        return {"status": "success", "data": {
            "cases": [{"id": "txwd-1:2022-cv-00398", "title": "T", "court_id": "txwd",
                       "court_name": "Western District of Texas", "case_type": "civil",
                       "date_filed": "2022-04-27", "canonical_url": "https://x",
                       "complaint_document_id": "txwd-1:2022-cv-00398-00001",
                       "complaint_status": "available"}],
            "found": 194, "next_cursor": "CURSOR123"}}

    monkeypatch.setattr(d, "make_request", fake)
    out = await d.docketbird_search_cases("Natera")
    assert "194 cases matched" in out
    assert "cursor='CURSOR123'" in out
    assert "Complaint: txwd-1:2022-cv-00398-00001 (available)" in out


@pytest.mark.asyncio
async def test_search_cases_end_of_results(monkeypatch):
    async def fake(endpoint, params=None, api_key=""):
        return {"status": "success", "data": {"cases": [], "found": 0, "next_cursor": None}}

    monkeypatch.setattr(d, "make_request", fake)
    out = await d.docketbird_search_cases("nothing")
    assert "No cases matched" in out
    assert "End of results" in out


@pytest.mark.asyncio
async def test_fulltext_search_renders_snippets_and_scope(monkeypatch):
    captured = {}

    async def fake(endpoint, params=None, api_key=""):
        captured.update(params)
        assert endpoint == "/documents/search"
        return {"status": "success", "data": {
            "documents": [{"document_id": "d1", "case_id": "c1", "case_title": "T",
                           "document_title": "Order", "court_id": "txwd",
                           "court_name": "W.D. Tex.", "date_filed": "2025-01-01",
                           "snippets": ["a <em>motion</em> &quot;quoted&quot;"],
                           "canonical_url": "https://x"}],
            "found": 10, "next_cursor": None}}

    monkeypatch.setattr(d, "make_request", fake)
    out = await d.docketbird_fulltext_search("motion", my_cases_only=True)
    assert captured["my_cases_only"] == "true"
    assert "your firm's cases" in out
    assert 'a **motion** "quoted"' in out  # <em> → bold, entities unescaped
    assert "End of results" in out


@pytest.mark.asyncio
async def test_fulltext_search_empty_page_with_cursor_explains(monkeypatch):
    async def fake(endpoint, params=None, api_key=""):
        return {"status": "success", "data": {"documents": [], "found": 5, "next_cursor": "NEXT"}}

    monkeypatch.setattr(d, "make_request", fake)
    out = await d.docketbird_fulltext_search("sealed stuff")
    # Restricted docs removed after matching: empty page but more remain.
    assert "more results remain" in out
    assert "cursor='NEXT'" in out


# --------------------------------------------------------------------------- #
# get_document_text: offset paging + upstream truncation + not-found handling
# --------------------------------------------------------------------------- #


def _fake_text_api(text, truncated=False):
    async def fake(endpoint, params=None, api_key=""):
        return {"status": "success", "data": {"document": {
            "id": "x", "title": "Doc", "text": text, "text_truncated": truncated}}}

    return fake


@pytest.mark.asyncio
async def test_get_document_text_pages_by_offset(monkeypatch):
    monkeypatch.setattr(d, "make_request", _fake_text_api("abcdefghij"))
    out = await d.docketbird_get_document_text("x", offset=2, max_chars=3)
    assert "Characters 2-5 of 10" in out
    assert "cde" in out
    assert "offset=5" in out


@pytest.mark.asyncio
async def test_get_document_text_reports_upstream_truncation(monkeypatch):
    monkeypatch.setattr(d, "make_request", _fake_text_api("abc", truncated=True))
    out = await d.docketbird_get_document_text("x")
    assert "truncated this text server-side" in out


@pytest.mark.asyncio
async def test_get_document_text_offset_past_end(monkeypatch):
    monkeypatch.setattr(d, "make_request", _fake_text_api("abc"))
    out = await d.docketbird_get_document_text("x", offset=99)
    assert "beyond the end" in out


@pytest.mark.asyncio
async def test_get_document_text_400_means_no_text(monkeypatch):
    import httpx

    async def fake(endpoint, params=None, api_key=""):
        request = httpx.Request("GET", "https://api.docketbird.com" + endpoint)
        response = httpx.Response(400, request=request,
                                  json={"status": "error", "message": "document not found"})
        raise httpx.HTTPStatusError("400", request=request, response=response)

    monkeypatch.setattr(d, "make_request", fake)
    out = await d.docketbird_get_document_text("missing-id")
    assert "No extracted text is available" in out
    assert "document not found" in out


# --------------------------------------------------------------------------- #
# get_calendar: company-wide scope (pending, empty, entries)
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_get_calendar_companywide_pending(monkeypatch):
    async def fake(endpoint, params=None, api_key=""):
        return {"status": "pending", "message": "being prepared; retry"}

    monkeypatch.setattr(d, "make_request", fake)
    out = await d.docketbird_get_calendar(days=30)
    assert "being built for the first time" in out


@pytest.mark.asyncio
async def test_get_calendar_companywide_entries(monkeypatch):
    async def fake(endpoint, params=None, api_key=""):
        assert params == {"days": 7}
        return {"status": "success", "data": {
            "calendar_entries": [{"case_id": "c1", "case_name": "A v. B",
                                  "date": "2026-07-20", "time": "10:00",
                                  "title": "Hearing", "source_document_id": "d9"}],
            "window_start": "2026-07-15", "window_end": "2026-07-22",
            "calendar_last_updated": "2026-07-15T20:21:36"}}

    monkeypatch.setattr(d, "make_request", fake)
    out = await d.docketbird_get_calendar()
    assert "Company-wide Calendar (2026-07-15 to 2026-07-22, 1 entries)" in out
    assert "2026-07-20 10:00" in out
    assert "A v. B" in out


@pytest.mark.asyncio
async def test_get_calendar_companywide_404_suggests_autocalendar(monkeypatch):
    import httpx

    async def fake(endpoint, params=None, api_key=""):
        request = httpx.Request("GET", "https://api.docketbird.com/calendar_entries")
        response = httpx.Response(404, request=request,
                                  json={"status": "error", "message": "no active autocalendars"})
        raise httpx.HTTPStatusError("404", request=request, response=response)

    monkeypatch.setattr(d, "make_request", fake)
    out = await d.docketbird_get_calendar()
    assert "no active autocalendars" in out
    assert "docketbird_create_autocalendar" in out


# --------------------------------------------------------------------------- #
# ask_litigation_graph: zero-record caveat + truncation notice
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_graph_zero_records_carries_coverage_caveat(monkeypatch):
    async def fake_post(endpoint, body, api_key=""):
        assert endpoint == "/graph/ask"
        return {"status": "success", "data": {
            "records": [], "num_records": 0, "interpretation": None,
            "truncated": False, "coverage_note": "federal civil only", "message": None}}

    monkeypatch.setattr(d, "make_post_request", fake_post)
    out = await d.docketbird_ask_litigation_graph("who sued nobody?")
    assert "NOT proof that no such cases exist" in out
    assert "federal civil only" in out


@pytest.mark.asyncio
async def test_graph_truncated_records_render(monkeypatch):
    async def fake_post(endpoint, body, api_key=""):
        return {"status": "success", "data": {
            "records": [{"attorney.full_name": "A. Lawyer", "lawfirm.name": "Firm LLP"}],
            "num_records": 1, "interpretation": "Find lawyers",
            "truncated": True, "coverage_note": "note", "message": None}}

    monkeypatch.setattr(d, "make_post_request", fake_post)
    out = await d.docketbird_ask_litigation_graph("who?")
    assert "attorney.full_name: A. Lawyer" in out
    assert "200-record cap" in out
    assert "Understood as" in out


@pytest.mark.asyncio
async def test_graph_populated_response_still_states_coverage(monkeypatch):
    # Live API omits coverage_note on populated responses (spec says it's on
    # every response); the tool must state the ceiling itself regardless.
    async def fake_post(endpoint, body, api_key=""):
        return {"status": "success", "data": {
            "records": [{"lawfirm.name": "Firm LLP"}], "num_records": 1,
            "interpretation": "Find firms", "truncated": False}}

    monkeypatch.setattr(d, "make_post_request", fake_post)
    out = await d.docketbird_ask_litigation_graph("who?")
    assert "Coverage:" in out
    assert "~30% of federal civil cases" in out


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
