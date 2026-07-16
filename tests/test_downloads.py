"""Tests for the remote-aware document download behavior.

In remote (HTTP/OAuth) mode the download tools return content to the client
instead of writing to the server's filesystem; in local stdio mode with a
save_path they still stream to disk. Network access is faked so these run
fully offline.
"""

import base64
import os

os.environ.setdefault("DATA_DIR", "/tmp/docketbird-test-data")

import pytest
from mcp.types import EmbeddedResource, TextContent

import docketbird_mcp as d


@pytest.fixture(autouse=True)
def _fake_auth(monkeypatch):
    """Every tool calls get_user_api_key(); give it a dummy key."""
    monkeypatch.setattr(d, "get_user_api_key", lambda: "test-key")


# --------------------------------------------------------------------------- #
# Fake S3 streaming client (mirrors the shape httpx.AsyncClient.stream expects)
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


def _fake_single_document(document):
    async def fake_make_request(endpoint, params=None, api_key=""):
        return {"data": {"document": document}}

    return fake_make_request


def _fake_case_documents(documents):
    async def fake_make_request(endpoint, params=None, api_key=""):
        return {"data": {"documents": documents}}

    return fake_make_request


S3 = "https://docketbird.s3.amazonaws.com/order.pdf?sig=abc"


# --------------------------------------------------------------------------- #
# _stream_to_memory: size cap + SSRF, mirroring the on-disk helper
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_stream_to_memory_returns_bytes(monkeypatch):
    monkeypatch.setattr(d, "get_http_client", lambda: _FakeClient([b"hello ", b"world"]))
    out = await d._stream_to_memory("https://docketbird.s3.amazonaws.com/x.pdf")
    assert out == b"hello world"


@pytest.mark.asyncio
async def test_stream_to_memory_enforces_inline_cap(monkeypatch):
    monkeypatch.setattr(d, "MAX_INLINE_SIZE", 10)
    monkeypatch.setattr(d, "get_http_client", lambda: _FakeClient([b"x" * 8, b"y" * 8]))
    with pytest.raises(d.DownloadTooLarge):
        await d._stream_to_memory("https://docketbird.s3.amazonaws.com/big.pdf")


@pytest.mark.asyncio
async def test_stream_to_memory_early_exits_on_content_length(monkeypatch):
    """A Content-Length over the cap aborts before the body is read."""
    monkeypatch.setattr(d, "MAX_INLINE_SIZE", 10)
    # If the body were read, these chunks are well under the cap; the header alone
    # must trigger the abort, so we know the early exit (not the running total) fired.
    client = _FakeClient([b"tiny"], headers={"content-length": "999"})
    monkeypatch.setattr(d, "get_http_client", lambda: client)
    with pytest.raises(d.DownloadTooLarge):
        await d._stream_to_memory("https://docketbird.s3.amazonaws.com/big.pdf")


@pytest.mark.asyncio
async def test_stream_to_file_uses_disk_cap_above_inline_cap(monkeypatch, tmp_path):
    """A file between the inline and disk caps still streams to disk fine."""
    monkeypatch.setattr(d, "MAX_INLINE_SIZE", 4)
    monkeypatch.setattr(d, "MAX_DOWNLOAD_SIZE", 100)
    monkeypatch.setattr(d, "get_http_client", lambda: _FakeClient([b"x" * 8]))
    dest = tmp_path / "mid.pdf"
    n = await d._stream_to_file("https://docketbird.s3.amazonaws.com/mid.pdf", dest)
    assert n == 8 and dest.read_bytes() == b"x" * 8


@pytest.mark.asyncio
async def test_stream_to_memory_rejects_bad_domain(monkeypatch):
    monkeypatch.setattr(d, "get_http_client", lambda: _FakeClient([b"x"]))
    with pytest.raises(ValueError):
        await d._stream_to_memory("https://evil.example.com/x.pdf")


# --------------------------------------------------------------------------- #
# download_document: remote mode returns content to the client
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_download_document_remote_returns_embedded_resource(monkeypatch):
    monkeypatch.setattr(d, "_is_remote_session", lambda: True)
    monkeypatch.setattr(
        d, "make_request",
        _fake_single_document({"title": "Order", "custom_filename": "order.pdf", "docketbird_document_url": S3}),
    )
    monkeypatch.setattr(d, "get_http_client", lambda: _FakeClient([b"%PDF-", b"bytes"]))

    out = await d.docketbird_download_document("doc1")

    assert isinstance(out, list) and len(out) == 2
    summary, resource = out
    assert isinstance(summary, TextContent)
    assert "Order" in summary.text
    assert isinstance(resource, EmbeddedResource)
    assert base64.b64decode(resource.resource.blob) == b"%PDF-bytes"
    assert resource.resource.mimeType == "application/pdf"


@pytest.mark.asyncio
async def test_download_document_remote_ignores_save_path(monkeypatch, tmp_path):
    """A save_path passed over a remote connection must not write to disk."""
    monkeypatch.setattr(d, "_is_remote_session", lambda: True)
    monkeypatch.setattr(
        d, "make_request",
        _fake_single_document({"title": "Order", "custom_filename": "order.pdf", "docketbird_document_url": S3}),
    )
    monkeypatch.setattr(d, "get_http_client", lambda: _FakeClient([b"data"]))

    out = await d.docketbird_download_document("doc1", save_path=str(tmp_path))

    assert isinstance(out, list)  # returned content, not a disk write
    assert not any(tmp_path.iterdir())  # nothing written to the server


@pytest.mark.asyncio
async def test_download_document_remote_bad_save_path_still_returns_content(monkeypatch):
    """A traversal save_path is ignored (not validated) remotely, not a hard error."""
    monkeypatch.setattr(d, "_is_remote_session", lambda: True)
    monkeypatch.setattr(
        d, "make_request",
        _fake_single_document({"title": "Order", "custom_filename": "order.pdf", "docketbird_document_url": S3}),
    )
    monkeypatch.setattr(d, "get_http_client", lambda: _FakeClient([b"data"]))

    out = await d.docketbird_download_document("doc1", save_path="/tmp/../etc")

    assert isinstance(out, list)  # content returned, not a "Security error" string


@pytest.mark.asyncio
async def test_download_document_remote_oversize_returns_url(monkeypatch):
    monkeypatch.setattr(d, "_is_remote_session", lambda: True)
    monkeypatch.setattr(d, "MAX_INLINE_SIZE", 4)
    monkeypatch.setattr(
        d, "make_request",
        _fake_single_document({"title": "Big", "docketbird_document_url": S3}),
    )
    monkeypatch.setattr(d, "get_http_client", lambda: _FakeClient([b"x" * 8]))

    out = await d.docketbird_download_document("doc1")

    assert isinstance(out, str)
    assert S3 in out  # fall back to the direct link rather than inlining
    assert "inline limit" in out


@pytest.mark.asyncio
async def test_download_document_restricted_is_text(monkeypatch):
    monkeypatch.setattr(d, "_is_remote_session", lambda: True)
    monkeypatch.setattr(d, "make_request", _fake_single_document({"restricted": True}))
    out = await d.docketbird_download_document("doc1")
    assert isinstance(out, str)
    assert "restricted" in out.lower()


# --------------------------------------------------------------------------- #
# download_document: local stdio mode with save_path still writes to disk
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_download_document_local_saves_to_disk(monkeypatch, tmp_path):
    monkeypatch.setattr(d, "_is_remote_session", lambda: False)
    monkeypatch.setattr(
        d, "make_request",
        _fake_single_document({"title": "Order", "custom_filename": "order.pdf", "docketbird_document_url": S3}),
    )
    monkeypatch.setattr(d, "get_http_client", lambda: _FakeClient([b"on-", b"disk"]))

    out = await d.docketbird_download_document("doc1", save_path=str(tmp_path))

    assert isinstance(out, str) and "Downloaded:" in out
    assert (tmp_path / "order.pdf").read_bytes() == b"on-disk"


# --------------------------------------------------------------------------- #
# download_files: remote mode lists per-document download links
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_download_files_remote_lists_links(monkeypatch):
    monkeypatch.setattr(d, "_is_remote_session", lambda: True)
    docs = [
        {"id": 1, "title": "Avail", "docketbird_document_url": S3},
        {"id": 2, "title": "Sealed", "restricted": True},
        {"id": 3, "title": "Pending"},  # no URL yet
    ]
    monkeypatch.setattr(d, "make_request", _fake_case_documents(docs))

    out = await d.docketbird_download_files("txnd-1:2020-cv-1")

    assert S3 in out
    assert "1 available to download" in out
    assert "Restricted**: 1" in out
    assert "Not yet available**: 1" in out


@pytest.mark.asyncio
async def test_download_files_remote_drops_off_allowlist_urls(monkeypatch):
    """A URL outside the SSRF allowlist must not be relayed to the client."""
    monkeypatch.setattr(d, "_is_remote_session", lambda: True)
    evil = "https://evil.example.com/secret.pdf"
    docs = [
        {"id": 1, "title": "Good", "docketbird_document_url": S3},
        {"id": 2, "title": "Evil", "docketbird_document_url": evil},
    ]
    monkeypatch.setattr(d, "make_request", _fake_case_documents(docs))

    out = await d.docketbird_download_files("txnd-1:2020-cv-1")

    assert S3 in out
    assert evil not in out
    assert "1 available to download" in out
    assert "Not yet available**: 1" in out


@pytest.mark.asyncio
async def test_download_files_local_saves_to_disk(monkeypatch, tmp_path):
    monkeypatch.setattr(d, "_is_remote_session", lambda: False)
    docs = [{"id": 1, "title": "Avail", "custom_filename": "a.pdf", "docketbird_document_url": S3}]
    monkeypatch.setattr(d, "make_request", _fake_case_documents(docs))
    monkeypatch.setattr(d, "get_http_client", lambda: _FakeClient([b"bulk"]))

    out = await d.docketbird_download_files("txnd-1:2020-cv-1", save_path=str(tmp_path))

    assert "Downloaded**: 1 files" in out
    assert (tmp_path / "a.pdf").read_bytes() == b"bulk"


@pytest.mark.asyncio
async def test_download_files_local_dedupes_colliding_filenames(monkeypatch, tmp_path):
    """Two documents that sanitize to the same filename must not overwrite
    each other; the second gets a numeric suffix."""
    monkeypatch.setattr(d, "_is_remote_session", lambda: False)
    docs = [
        {"id": 1, "title": "First", "custom_filename": "order.pdf", "docketbird_document_url": S3},
        {"id": 2, "title": "Second", "custom_filename": "order.pdf", "docketbird_document_url": S3},
    ]
    monkeypatch.setattr(d, "make_request", _fake_case_documents(docs))
    monkeypatch.setattr(d, "get_http_client", lambda: _FakeClient([b"content"]))

    out = await d.docketbird_download_files("txnd-1:2020-cv-1", save_path=str(tmp_path))

    assert "Downloaded**: 2 files" in out
    files = sorted(p.name for p in tmp_path.iterdir())
    assert files == ["order-2.pdf", "order.pdf"]
    assert (tmp_path / "order.pdf").read_bytes() == b"content"
    assert (tmp_path / "order-2.pdf").read_bytes() == b"content"
