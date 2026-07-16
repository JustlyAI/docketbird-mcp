#!/usr/bin/env python3
"""DocketBird MCP Server - Production Ready (MCP Spec 2025-03-26)

Provides tools for searching and downloading federal court documents via DocketBird API.
Deployed on DigitalOcean with Streamable HTTP transport.

Auth: Per-user DocketBird API keys via OAuth. Users register at /signup with their
own API key, then authenticate via OAuth when connecting from Claude.ai.
In stdio mode, falls back to DOCKETBIRD_API_KEY env var.
"""

import asyncio
import base64
import html
import json
import mimetypes
import os
import re
import sys
import time
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, Literal
from urllib.parse import urlparse

import httpx
from mcp.server.auth.middleware.auth_context import get_access_token
from mcp.server.auth.settings import AuthSettings, ClientRegistrationOptions
from mcp.server.fastmcp import FastMCP
from mcp.types import BlobResourceContents, EmbeddedResource, TextContent, ToolAnnotations
from starlette.requests import Request
from starlette.responses import JSONResponse
from termcolor import cprint as _cprint

from auth_provider import (
    AuthDB,
    DocketBirdAccessToken,
    DocketBirdAuthProvider,
    handle_change_api_key,
    handle_change_password,
    handle_login,
    handle_signup,
)


def cprint(*args, **kwargs):
    """Log to stderr, never stdout.

    The stdio transport speaks JSON-RPC over stdout; any stray stdout write
    corrupts that stream and breaks the client. Routing all diagnostic output
    to stderr keeps stdio mode working and is harmless in HTTP mode.
    """
    kwargs.setdefault("file", sys.stderr)
    _cprint(*args, **kwargs)


# =============================================================================
# Configuration
# =============================================================================

SCRIPT_DIR = Path(__file__).parent.resolve()
BASE_URL = "https://api.docketbird.com"
SERVER_URL = os.getenv("SERVER_URL", "http://localhost:8080")

# Deployed git commit, surfaced at /health so a single curl proves which build is
# live. The deploy pipeline injects it via `-e GIT_SHA`; "dev" when unset locally.
GIT_SHA = os.getenv("GIT_SHA", "dev")

# Fallback API key for stdio mode (no OAuth in stdio)
FALLBACK_API_KEY = os.getenv("DOCKETBIRD_API_KEY", "")

# Allowed domains for document downloads (SSRF protection)
ALLOWED_DOWNLOAD_DOMAINS = {
    "s3.amazonaws.com",
    "docketbird.s3.amazonaws.com",
    "api.docketbird.com",
}

# Max file size for downloads to the server's disk (local stdio mode).
MAX_DOWNLOAD_SIZE = 50 * 1024 * 1024

# Max file size to return inline to a remote client as a base64 blob. Smaller
# than the disk cap: base64 inflates ~33% and the whole payload sits in memory
# and the JSON-RPC response, so large filings are returned as a download URL
# instead of being inlined.
MAX_INLINE_SIZE = 10 * 1024 * 1024

# Rate limiting
RATE_LIMIT_REQUESTS = 30
RATE_LIMIT_WINDOW = 60  # seconds

# Service token for trusted server-to-server clients (e.g. AIFintel). When both
# are set, a non-expiring access token is seeded at HTTP startup. Empty = disabled.
SERVICE_TOKEN = os.getenv("SERVICE_TOKEN", "")
SERVICE_DOCKETBIRD_API_KEY = os.getenv("SERVICE_DOCKETBIRD_API_KEY", "")

# =============================================================================
# Auth: Database + OAuth Provider
# =============================================================================

auth_db = AuthDB()
auth_provider = DocketBirdAuthProvider(auth_db, server_url=SERVER_URL)

# =============================================================================
# FastMCP Server (with OAuth)
# =============================================================================


async def _periodic_cleanup():
    """Periodically clean up expired tokens, auth codes, and pending sessions."""
    while True:
        await asyncio.sleep(3600)  # Run every hour
        try:
            await auth_db.cleanup_expired()
            pruned = rate_limiter.prune()
            cprint(f"[MCP] Cleaned up expired auth records (pruned {pruned} rate-limit entries)", "yellow")
        except Exception as e:
            cprint(f"[MCP] Cleanup error: {e}", "red")


@asynccontextmanager
async def lifespan(server: FastMCP):
    """Initialize auth DB on startup, clean up on shutdown.

    In HTTP mode, the ASGI wrapper's lifespan handler manages the DB lifecycle,
    so this is a no-op. This lifespan also fires per-session in HTTP mode via
    streamable_http_app(), so it must not re-initialize or close the DB.
    In stdio mode (mcp.run()), this is the only init/cleanup path.
    """
    if auth_db._db is not None:
        # Already initialized by ASGI lifespan wrapper (HTTP mode)
        cprint("[MCP] FastMCP lifespan: DB already initialized, skipping", "cyan")
        yield {}
        return
    # stdio mode: we are the only init path
    cprint("[MCP] Starting up (stdio): initializing auth database", "yellow")
    await auth_db.initialize()
    cleanup_task = asyncio.create_task(_periodic_cleanup())
    yield {}
    cleanup_task.cancel()
    cprint("[MCP] Shutting down: closing connections", "yellow")
    await auth_db.close()
    await cleanup_http_client()


mcp = FastMCP(
    "docketbird",
    stateless_http=True,
    host="0.0.0.0",
    auth_server_provider=auth_provider,
    auth=AuthSettings(
        issuer_url=SERVER_URL,
        resource_server_url=SERVER_URL,
        client_registration_options=ClientRegistrationOptions(
            enabled=True,
            valid_scopes=["docketbird"],
            default_scopes=["docketbird"],
        ),
        required_scopes=["docketbird"],
    ),
    lifespan=lifespan,
)

# =============================================================================
# HTTP Client (Reusable with Connection Pooling)
# =============================================================================

_http_client: httpx.AsyncClient | None = None


def get_http_client() -> httpx.AsyncClient:
    """Get or create reusable HTTP client with connection pooling.

    No default API key headers. Each request passes its own auth via make_request().
    """
    global _http_client
    if _http_client is None:
        cprint("[MCP] Initializing HTTP client with connection pooling", "yellow")
        _http_client = httpx.AsyncClient(
            base_url=BASE_URL,
            timeout=httpx.Timeout(30.0, connect=5.0),
            limits=httpx.Limits(max_keepalive_connections=20, max_connections=100),
        )
    return _http_client


async def make_request(
    endpoint: str,
    params: dict[str, Any] | None = None,
    api_key: str = "",
) -> dict[str, Any]:
    """Make authenticated request to DocketBird API with per-user API key."""
    client = get_http_client()
    headers = {"Authorization": f"Bearer {api_key}"} if api_key else {}
    cprint(f"[MCP] API Request: {endpoint} params={params}", "cyan")
    response = await client.get(endpoint, params=params, headers=headers)
    response.raise_for_status()
    return response.json()


async def make_post_request(
    endpoint: str,
    body: dict[str, Any],
    api_key: str = "",
) -> dict[str, Any]:
    """Make an authenticated POST request to DocketBird API with per-user API key.

    The write endpoints return a success status with no documented body schema,
    so we return the parsed JSON when present and fall back to a status dict.
    """
    client = get_http_client()
    headers = {"Authorization": f"Bearer {api_key}"} if api_key else {}
    cprint(f"[MCP] API POST: {endpoint} body={body}", "cyan")
    response = await client.post(endpoint, json=body, headers=headers)
    response.raise_for_status()
    if response.content:
        try:
            return response.json()
        except ValueError:
            pass
    return {"status": "ok"}


async def validate_docketbird_api_key(api_key: str) -> bool:
    """Check a DocketBird API key by making the lightest authenticated call.

    Returns True if the key authenticates, False if DocketBird rejects it (401/403).
    Raises on network/other errors so the caller can report "couldn't verify" rather
    than silently saving an unverifiable key. Uses GET /cases?scope=user — the
    lightest auth-only endpoint (no dedicated account endpoint exists in the API).
    """
    try:
        await make_request("/cases", params={"scope": "user"}, api_key=api_key)
        return True
    except httpx.HTTPStatusError as e:
        if e.response.status_code in (401, 403):
            return False
        raise


async def cleanup_http_client() -> None:
    """Clean up HTTP client on shutdown."""
    global _http_client
    if _http_client is not None:
        await _http_client.aclose()
        _http_client = None


# =============================================================================
# Per-User API Key Helper
# =============================================================================


def get_user_api_key() -> str:
    """Get the DocketBird API key for the current user.

    In HTTP mode: extracted from the OAuth access token (set by SDK middleware).
    In stdio mode: falls back to DOCKETBIRD_API_KEY env var.
    """
    token = get_access_token()
    if token is not None and isinstance(token, DocketBirdAccessToken):
        return token.docketbird_api_key
    # Fallback for stdio mode or local dev
    if FALLBACK_API_KEY:
        return FALLBACK_API_KEY
    raise ValueError(
        "No DocketBird API key available. "
        "In HTTP mode: authenticate via OAuth. "
        "In stdio mode: set DOCKETBIRD_API_KEY env var."
    )


# =============================================================================
# Error Handling
# =============================================================================


def _api_error_message(error: httpx.HTTPStatusError) -> str | None:
    """Extract DocketBird's own error message from the response body, if present.

    DocketBird returns {"status": "error", "message": "..."} on failures, and the
    message is often more actionable than our generic text (e.g. a 403 that says
    "please follow it. Charges may apply.").
    """
    try:
        body = error.response.json()
    except (ValueError, AttributeError):
        return None
    if isinstance(body, dict):
        msg = body.get("message")
        if isinstance(msg, str) and msg.strip():
            return msg.strip()
    return None


def handle_api_error(error: Exception, operation: str) -> str:
    """Format API errors with actionable messages."""
    if isinstance(error, httpx.HTTPStatusError):
        status = error.response.status_code
        messages = {
            401: f"Authentication failed for {operation}. Check your DocketBird API key.",
            403: f"Access forbidden to {operation}. Verify account permissions.",
            404: f"Resource not found: {operation}. Verify case ID format (e.g., 'txnd-3:2007-cv-01697').",
            429: f"Rate limited. Wait 60 seconds before retrying {operation}.",
            504: f"Gateway timeout for {operation}. Try again.",
        }
        base = messages.get(status, f"HTTP {status} error for {operation}.")
        api_msg = _api_error_message(error)
        return f"{base} DocketBird: {api_msg}" if api_msg else base
    if isinstance(error, httpx.TimeoutException):
        return f"Request timed out for {operation}. Try again."
    if isinstance(error, httpx.ConnectError):
        return f"Connection failed for {operation}. Check internet connection."
    return f"Error for {operation}: {type(error).__name__}: {error}"


# =============================================================================
# Security: Path Validation
# =============================================================================


def validate_save_path(save_path: str) -> Path:
    """Validate a save path to prevent path traversal attacks.

    Rejects '..' as a path segment before resolution (a '..' inside a
    name, like 'my..docs', is legitimate)."""
    if ".." in Path(save_path).parts:
        raise ValueError("Path traversal not allowed: '..' detected in path")
    return Path(save_path).expanduser().resolve()


def validate_download_url(url: str) -> str:
    """Validate that a download URL points to an allowed domain (SSRF protection)."""
    parsed = urlparse(url)
    if parsed.scheme != "https":
        raise ValueError(f"Invalid URL scheme: {parsed.scheme}")
    # Check hostname against allowlist (supports subdomains of allowed domains)
    hostname = parsed.hostname or ""
    if not any(hostname == d or hostname.endswith(f".{d}") for d in ALLOWED_DOWNLOAD_DOMAINS):
        raise ValueError(f"Download domain not allowed: {hostname}")
    return url


def sanitize_filename(raw: str) -> str:
    """Sanitize a filename extracted from a URL to prevent injection."""
    # Extract just the filename part, strip query params
    name = raw.split("/")[-1].split("?")[0].split("#")[0]
    # Remove anything that isn't alphanumeric, dash, underscore, or dot
    name = re.sub(r"[^\w.\-]", "_", name)
    # Prevent hidden files and path traversal
    name = name.lstrip(".")
    # Fallback if empty
    if not name:
        name = "document.pdf"
    # Truncate overly long filenames
    if len(name) > 255:
        name = name[:255]
    return name


# =============================================================================
# Rate Limiting
# =============================================================================


class RateLimiter:
    """In-memory sliding window rate limiter per client IP."""

    def __init__(self, max_requests: int, window_seconds: int):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._requests: dict[str, list[float]] = {}

    def is_allowed(self, client_ip: str) -> bool:
        now = time.monotonic()
        cutoff = now - self.window_seconds

        timestamps = self._requests.get(client_ip, [])
        # Evict stale timestamps
        timestamps = [t for t in timestamps if t > cutoff]

        if len(timestamps) >= self.max_requests:
            self._requests[client_ip] = timestamps
            return False

        # Record this request
        timestamps.append(now)
        self._requests[client_ip] = timestamps
        return True

    def prune(self) -> int:
        """Drop IPs with no requests inside the current window.

        Called periodically so the map doesn't grow unboundedly as unique client
        IPs come and go. Returns the number of entries removed.
        """
        cutoff = time.monotonic() - self.window_seconds
        stale = [ip for ip, ts in self._requests.items() if not any(t > cutoff for t in ts)]
        for ip in stale:
            del self._requests[ip]
        return len(stale)


rate_limiter = RateLimiter(RATE_LIMIT_REQUESTS, RATE_LIMIT_WINDOW)


def get_client_ip(scope) -> str:
    """Extract client IP from ASGI scope.

    Uses the LAST value in X-Forwarded-For since Caddy (our trusted proxy)
    appends the real client IP. An attacker can prepend fake IPs, but cannot
    control the last entry appended by Caddy.
    """
    headers = dict(scope.get("headers", []))
    forwarded = headers.get(b"x-forwarded-for", b"").decode("utf-8", errors="ignore")
    if forwarded:
        return forwarded.split(",")[-1].strip()
    client = scope.get("client")
    if client:
        return client[0]
    return "unknown"


# =============================================================================
# Pagination + Download Helpers
# =============================================================================

MAX_PAGE_SIZE = 50


def _clamp_pagination(page: int, page_size: int) -> tuple[int, int]:
    """Clamp pagination args to safe ranges.

    Guards against page < 1 (which yields negative slice indices) and
    page_size <= 0 (which causes a ZeroDivisionError when computing total_pages).
    """
    return max(page, 1), max(1, min(page_size, MAX_PAGE_SIZE))


def _paginate(items: list[Any], page: int, page_size: int) -> tuple[list[Any], int, int]:
    """Slice items for the given (already clamped) page.

    Returns (page_items, total, total_pages).
    """
    total = len(items)
    total_pages = max(1, (total + page_size - 1) // page_size)
    start = (page - 1) * page_size
    return items[start : start + page_size], total, total_pages


def _clamp_cursor_size(size: int) -> int:
    """Clamp a cursor-endpoint page size to a sane range.

    The cursor endpoints (/cases/search, /documents/search) paginate upstream,
    so this only bounds how much lands in one response, not what gets fetched.
    """
    return max(1, min(size, MAX_PAGE_SIZE))


def _render_snippet(snippet: str) -> str:
    """Convert an API search snippet to markdown.

    The search API wraps matched terms in <em> tags and HTML-escapes the text;
    render the matches as bold and unescape everything else.
    """
    return html.unescape(snippet.replace("<em>", "**").replace("</em>", "**"))


def _cursor_footer(found: int, shown: int, next_cursor: str | None, thing: str) -> list[str]:
    """Standard footer lines for a cursor-paginated result page.

    Per the API's pagination contract, next_cursor is the ONLY end-of-results
    signal: a page may hold fewer than `size` items (restricted documents are
    removed after matching) while more results remain, and `found` may count
    items that will never be returned.
    """
    lines = [f"\n_{found} {thing} matched; {shown} on this page._"]
    if next_cursor:
        lines.append(f"_More results: pass cursor='{next_cursor}' to get the next page._")
    else:
        lines.append("_End of results._")
    return lines


class DownloadTooLarge(Exception):
    """Raised when a streamed download exceeds MAX_DOWNLOAD_SIZE."""


async def _iter_capped_chunks(s3_url: str, max_bytes: int):
    """Yield a validated S3 download in 8 KB chunks under a hard size cap.

    The single place the download invariants live: it validates the URL domain
    (SSRF protection) and requires HTTPS before opening the stream, and raises
    DownloadTooLarge as soon as the running total would exceed max_bytes. When S3
    declares a Content-Length over the cap, it bails before reading the body so an
    over-cap file isn't transferred just to be discarded. httpx errors propagate.
    S3 URLs are pre-signed, so no API key is attached.
    """
    validate_download_url(s3_url)
    client = get_http_client()
    downloaded = 0
    async with client.stream("GET", s3_url) as response:
        response.raise_for_status()
        # Early exit on the advertised size; the running total below is the
        # authoritative guard since Content-Length may be absent, wrong, or
        # malformed (so a non-numeric value is ignored rather than crashing).
        try:
            declared = int(response.headers.get("content-length") or 0)
        except ValueError:
            declared = 0
        if declared > max_bytes:
            raise DownloadTooLarge("document")
        async for chunk in response.aiter_bytes(chunk_size=8192):
            downloaded += len(chunk)
            if downloaded > max_bytes:
                raise DownloadTooLarge("document")
            yield chunk


async def _stream_to_file(s3_url: str, dest: Path) -> int:
    """Stream a document from a validated S3 URL to dest with a hard size cap.

    Returns the number of bytes written. Deletes any partial file and re-raises
    if the download exceeds MAX_DOWNLOAD_SIZE (the disk cap).
    """
    # Validate before creating the file so a rejected domain leaves nothing behind.
    validate_download_url(s3_url)
    downloaded = 0
    try:
        with open(dest, "wb") as f:
            async for chunk in _iter_capped_chunks(s3_url, MAX_DOWNLOAD_SIZE):
                f.write(chunk)
                downloaded += len(chunk)
    except DownloadTooLarge:
        dest.unlink(missing_ok=True)
        raise
    return downloaded


async def _stream_to_memory(s3_url: str) -> bytes:
    """Stream a document from a validated S3 URL into memory with a hard size cap.

    The in-memory sibling of _stream_to_file, used to return document content to
    the client (remote HTTP mode) instead of writing to the server's disk. Shares
    the SSRF/HTTPS validation via _iter_capped_chunks but applies the smaller
    MAX_INLINE_SIZE cap, since the bytes are base64-encoded into the response.
    """
    buffer = bytearray()
    async for chunk in _iter_capped_chunks(s3_url, MAX_INLINE_SIZE):
        buffer += chunk
    return bytes(buffer)


def _is_remote_session() -> bool:
    """True when serving a remote (HTTP/OAuth) client, False in local stdio mode.

    The discriminator is OAuth-token presence: the SDK's auth middleware sets it
    only in HTTP mode, so it precisely captures the question that matters for
    downloads — can the user retrieve a file written to the server's filesystem?
    Remote: no (return content to the client). Local stdio: yes (save to disk).
    """
    return get_access_token() is not None


def _guess_mime_type(filename: str) -> str:
    """Best-effort MIME type for a downloaded document.

    Court filings are overwhelmingly PDFs, so that is the fallback when the
    extension is unknown.
    """
    mime, _ = mimetypes.guess_type(filename)
    return mime or "application/pdf"


def _document_resource(document_id: str, filename: str, content: bytes) -> EmbeddedResource:
    """Wrap downloaded bytes as an MCP embedded resource (base64 blob).

    Uses a stable docketbird:// URI rather than the pre-signed S3 URL so no
    short-lived signature leaks into the resource identity.
    """
    return EmbeddedResource(
        type="resource",
        resource=BlobResourceContents(
            uri=f"docketbird://documents/{document_id}/{filename}",
            mimeType=_guess_mime_type(filename),
            blob=base64.b64encode(content).decode("ascii"),
        ),
    )


def _format_download_links(case_id: str, documents: list[dict[str, Any]]) -> str:
    """Render available documents as a markdown list of direct download links.

    Used for bulk retrieval over a remote connection, where inlining every PDF
    would be far too large. Each available document exposes its pre-signed
    ``docketbird_document_url`` (already returned by the API) so the client can
    fetch it directly. Restricted and not-yet-available filings are summarized
    as counts rather than linked. URLs are run through the same SSRF/HTTPS
    allowlist as the streaming path, so only allowlisted https links are surfaced.
    """
    available = []
    restricted = 0
    unavailable = 0
    for doc in documents:
        if doc.get("restricted"):
            restricted += 1
            continue
        s3_url = doc.get("docketbird_document_url")
        if not s3_url:
            unavailable += 1
            continue
        try:
            validate_download_url(s3_url)
        except ValueError:
            # An off-allowlist or non-https URL should never be relayed to the
            # client; treat it as not (safely) available.
            unavailable += 1
            continue
        available.append(doc)

    lines = [f"## Documents for {case_id} ({len(available)} available to download)"]
    if not available:
        lines.append("\n_No documents are currently available for direct download._")
    for doc in available:
        title = doc.get("title", "N/A")
        lines.append(f"\n**{title}**")
        lines.append(f"- ID: {doc.get('id')}")
        if doc.get("filing_date"):
            lines.append(f"- Filed: {doc.get('filing_date')}")
        lines.append(f"- Download (link expires shortly): {doc.get('docketbird_document_url')}")

    if restricted:
        lines.append(f"\n**Restricted**: {restricted} documents (sealed/access-limited)")
    if unavailable:
        lines.append(f"**Not yet available**: {unavailable} documents")
    lines.append(
        "\n_Tip: call `docketbird_download_document` with a document ID to get that "
        "file's content directly._"
    )
    return "\n".join(lines)


# =============================================================================
# Tool Annotation Constants
# =============================================================================

READ_ONLY_API_TOOL = ToolAnnotations(
    readOnlyHint=True,
    destructiveHint=False,
    idempotentHint=True,
    openWorldHint=True,
)

DOWNLOAD_TOOL = ToolAnnotations(
    readOnlyHint=False,  # Writes files to disk
    destructiveHint=False,
    idempotentHint=False,  # Re-download may overwrite
    openWorldHint=True,
)

WRITE_TOOL = ToolAnnotations(
    readOnlyHint=False,  # Mutates state on the DocketBird side
    destructiveHint=False,
    idempotentHint=False,  # POST is not idempotent
    openWorldHint=True,
)

# =============================================================================
# Tools
# =============================================================================


@mcp.tool(annotations=READ_ONLY_API_TOOL)
async def docketbird_get_case_details(case_id: str, page: int = 1, page_size: int = 20) -> str:
    """Get a case's full docket sheet: case info plus its list of documents.

    When to use:
    - User wants the docket sheet (every filing in the case)
    - Before downloading documents (to see what's available)

    Notes:
    - Parties and attorneys are NOT available from the docket endpoints; for
      them, use docketbird_ask_litigation_graph.
    - The upstream /documents endpoint has no pagination: the entire docket is
      always fetched, and page/page_size only shape this response. Very large
      dockets can hit DocketBird's own ~29s gateway timeout (a 504).
    - For a case's metadata alone (no docket fetch), use docketbird_get_case.

    Args:
        case_id: DocketBird case ID (e.g., 'txnd-3:2007-cv-01697')
                 Format: {court_id}-{district}:{year}-{type}-{number}
        page: Page number for documents (starts at 1, default 1)
        page_size: Number of documents per page (default 20, max 50)
    """
    try:
        api_key = get_user_api_key()
        cprint(f"[MCP] docketbird_get_case_details: {case_id} (page={page})", "green")
        page, page_size = _clamp_pagination(page, page_size)
        data = await make_request("/documents", params={"case_id": case_id}, api_key=api_key)

        case = data.get("data", {}).get("case", {})
        documents = data.get("data", {}).get("documents", [])

        # Best-effort: the dedicated single-case endpoint adds PACER case ID,
        # client code, and the complaint pointer that /documents does not
        # return. Never fail the tool on this.
        pacer_case_id = None
        client_code = None
        complaint_document_id = None
        complaint_status = None
        try:
            case_data = await make_request(f"/cases/{case_id}", api_key=api_key)
            case_detail = case_data.get("data", {}).get("case", {})
            pacer_case_id = case_detail.get("pacer_case_id")
            client_code = case_detail.get("client_code")
            complaint_document_id = case_detail.get("complaint_document_id")
            complaint_status = case_detail.get("complaint_status")
        except Exception as e:
            cprint(f"[MCP] Could not fetch single-case detail for {case_id}: {e}", "yellow")

        page_docs, total_docs, total_pages = _paginate(documents, page, page_size)

        lines = [
            f"# Case: {case.get('title', 'N/A')}",
            f"**Court**: {case.get('court_id', 'N/A')}",
            f"**Filed**: {case.get('date_filed', 'N/A')}",
            f"**Closed**: {case.get('date_closed') or 'Open'}",
            f"**URL**: {case.get('url', 'N/A')}",
        ]
        if pacer_case_id:
            lines.append(f"**PACER Case ID**: {pacer_case_id}")
        if client_code:
            lines.append(f"**Client Code**: {client_code}")
        if complaint_document_id:
            status_note = f" ({complaint_status})" if complaint_status else ""
            lines.append(f"**Complaint**: {complaint_document_id}{status_note}")
        lines.append(
            "\n_Parties and attorneys are not available from the docket API; "
            "use docketbird_ask_litigation_graph for them._"
        )

        lines.append(f"\n## Documents (page {page}/{total_pages}, {total_docs} total)")
        for doc in page_docs:
            doc_id = doc.get("id")
            title = doc.get("title", "N/A")
            filed = doc.get("filing_date", "N/A")
            available = "yes" if doc.get("docketbird_document_url") else "no"
            lines.append(f"- [{doc_id}] {title} (Filed: {filed}) [Download: {available}]")

        if page < total_pages:
            lines.append(f"\n*Use page={page + 1} to see more documents*")

        return "\n".join(lines)

    except ValueError as e:
        return str(e)
    except Exception as e:
        return handle_api_error(e, f"case {case_id}")


@mcp.tool(annotations=READ_ONLY_API_TOOL)
async def docketbird_search_documents(case_id: str, search_term: str, page: int = 1, page_size: int = 20) -> str:
    """Find docket entries in ONE case whose title/description contains a term.

    This matches docket-entry METADATA only (the title and description shown on
    the docket sheet), not the text inside the filings. To search the full text
    of filing bodies — across all courts or within one case — use
    docketbird_fulltext_search instead.

    When to use:
    - User wants filings TITLED a certain way in a known case
      (e.g. docket entries labeled "motion to dismiss")
    - Narrowing down a docket sheet before download

    Note: the upstream /documents endpoint has no pagination, so the entire
    docket is always fetched and matched in memory; very large dockets can hit
    DocketBird's own ~29s gateway timeout (a 504).

    Args:
        case_id: DocketBird case ID
        search_term: Term to match against docket-entry titles/descriptions
        page: Page number (starts at 1, default 1)
        page_size: Results per page (default 20, max 50)
    """
    try:
        api_key = get_user_api_key()
        cprint(f"[MCP] docketbird_search_documents: {case_id} / {search_term} (page={page})", "green")
        page, page_size = _clamp_pagination(page, page_size)
        data = await make_request("/documents", params={"case_id": case_id}, api_key=api_key)

        documents = data.get("data", {}).get("documents", [])
        search_lower = search_term.lower()

        matches = [
            doc for doc in documents
            if search_lower in doc.get("title", "").lower()
            or search_lower in doc.get("description", "").lower()
        ]

        if not matches:
            return f"No documents matching '{search_term}' in case {case_id}"

        page_matches, total, total_pages = _paginate(matches, page, page_size)

        lines = [f"Found {total} documents matching '{search_term}' (page {page}/{total_pages}):"]
        for doc in page_matches:
            lines.append(f"\n**{doc.get('title', 'N/A')}**")
            lines.append(f"- ID: {doc.get('id')}")
            lines.append(f"- Filed: {doc.get('filing_date', 'N/A')}")
            if doc.get("docketbird_document_url"):
                lines.append("- Status: Available for download")
            else:
                lines.append("- Status: Not yet available")

        if page < total_pages:
            lines.append(f"\n*Use page={page + 1} to see more results*")

        return "\n".join(lines)

    except ValueError as e:
        return str(e)
    except Exception as e:
        return handle_api_error(e, f"search in case {case_id}")


@mcp.tool(annotations=READ_ONLY_API_TOOL)
async def docketbird_fulltext_search(
    query: str,
    court_id: str = "",
    case_id: str = "",
    filed_after: str = "",
    filed_before: str = "",
    my_cases_only: bool = False,
    sort: Literal["relevance", "recency"] = "relevance",
    size: int = 25,
    cursor: str = "",
) -> str:
    """Full-text search of the BODIES of court filings across DocketBird's
    entire document index — all courts, all cases, not just your account.

    This searches what the filings actually say, not what they are titled. To
    match docket-entry titles within one case, use docketbird_search_documents.

    When to use:
    - Scanning recent filings for a company, industry, or legal topic
      (e.g. new suits naming a target company — set sort='recency')
    - Finding every filing whose text mentions a term, phrase, or citation
    - Practice research inside your firm's own cases (set my_cases_only=True)

    Scope boundary: with my_cases_only=False (default) this is cross-corpus
    RESEARCH over public court records. With my_cases_only=True it is limited
    to cases associated with your firm's account (resolved from your API key).

    Query syntax:
    - space / and: all terms must appear.  or: either term.
    - -term: exclude (the word 'not' is NOT supported).
    - term* or term!: word endings (end of word only).
    - /n, /s, /p: terms within n words / same sentence / same paragraph.
    - "...": exact phrase. Email addresses and legal symbols (§, ¶) work.

    Pagination contract (upstream cursors, bounded requests):
    - next_cursor is the ONLY end-of-results signal. A page may hold fewer
      than `size` documents — even zero — while more remain, because
      restricted documents are removed after matching. Keep following the
      cursor until it is null. The 'found' count may include documents that
      will never be returned. Result window is the first 10,000 matches —
      narrow with court_id/case_id/dates if you need the deep tail.

    Args:
        query: Full-text query (max 500 chars), e.g. '"summary judgment" and forfeit* -insurance'
        court_id: Comma-separated court restriction; each entry may be a slug
                  ('nysd'), an abbreviation ('S.D.N.Y.'), or a full court name.
        case_id: Restrict to a single case by DocketBird case ID.
        filed_after: Only documents filed on/after this date (YYYY-MM-DD).
        filed_before: Only documents filed on/before this date (YYYY-MM-DD).
        my_cases_only: True = only your firm's cases (practice scope);
                       False = the whole corpus (research/marketing scope).
        sort: 'relevance' (default) or 'recency' (most recently filed first).
        size: Results per page (default 25, max 50).
        cursor: Pagination cursor from a previous response's next-page note.
    """
    try:
        api_key = get_user_api_key()
        cprint(f"[MCP] docketbird_fulltext_search: {query!r} (my_cases_only={my_cases_only})", "green")
        params: dict[str, Any] = {"q": query, "size": _clamp_cursor_size(size), "sort": sort}
        if court_id:
            params["court_id"] = court_id
        if case_id:
            params["case_id"] = case_id
        if filed_after:
            params["filed_after"] = filed_after
        if filed_before:
            params["filed_before"] = filed_before
        if my_cases_only:
            params["my_cases_only"] = "true"
        if cursor:
            params["cursor"] = cursor
        data = await make_request("/documents/search", params=params, api_key=api_key)

        payload = data.get("data", {})
        documents = payload.get("documents", [])
        found = payload.get("found", 0)
        next_cursor = payload.get("next_cursor")

        scope_label = "your firm's cases" if my_cases_only else "all courts"
        if case_id:
            scope_label += f", within case {case_id}"
        elif court_id:
            scope_label += f", courts: {court_id}"
        lines = [f"## Full-text search: {query!r} ({scope_label})"]
        if not documents:
            if next_cursor:
                lines.append(
                    "\n_This page is empty (restricted documents were removed after "
                    "matching), but more results remain — follow the cursor below._"
                )
            else:
                lines.append("\n_No documents matched._")
        for doc in documents:
            lines.append(f"\n**{doc.get('document_title', 'N/A')}**")
            lines.append(f"- Document ID: {doc.get('document_id')}")
            lines.append(f"- Case: {doc.get('case_title', 'N/A')} ({doc.get('case_id')})")
            lines.append(f"- Court: {doc.get('court_name') or doc.get('court_id', 'N/A')}")
            lines.append(f"- Filed: {doc.get('date_filed', 'N/A')}")
            for snippet in (doc.get("snippets") or [])[:3]:
                lines.append(f"  > {_render_snippet(snippet)}")
            if doc.get("canonical_url"):
                lines.append(f"- Page: {doc.get('canonical_url')}")

        lines.extend(_cursor_footer(found, len(documents), next_cursor, "documents"))
        return "\n".join(lines)

    except ValueError as e:
        return str(e)
    except Exception as e:
        return handle_api_error(e, f"full-text search {query!r}")


@mcp.tool(annotations=READ_ONLY_API_TOOL)
async def docketbird_list_cases(scope: Literal["company", "user"], page: int = 1, page_size: int = 20) -> str:
    """List the cases on YOUR DocketBird account (practice scope).

    This is your firm's tracked caseload only. To search all cases across all
    courts, use docketbird_search_cases.

    When to use:
    - User wants to see their own/their firm's tracked cases
    - Finding case IDs for calendar, follow, or autocalendar operations

    Args:
        scope: 'company' for all company cases, 'user' for personal cases
        page: Page number (starts at 1, default 1)
        page_size: Results per page (default 20, max 50)
    """
    try:
        api_key = get_user_api_key()
        cprint(f"[MCP] docketbird_list_cases: {scope} (page={page})", "green")
        page, page_size = _clamp_pagination(page, page_size)
        data = await make_request("/cases", params={"scope": scope}, api_key=api_key)

        cases = data.get("data", {}).get("cases", [])

        if not cases:
            return f"No cases found for {scope} scope"

        page_cases, total, total_pages = _paginate(cases, page, page_size)

        lines = [f"## {scope.title()} Cases (page {page}/{total_pages}, {total} total)"]
        for case in page_cases:
            lines.append(f"\n**{case.get('title', 'N/A')}**")
            lines.append(f"- ID: {case.get('id')}")
            lines.append(f"- Court: {case.get('court_id')}")
            if case.get("case_number"):
                lines.append(f"- Case Number: {case.get('case_number')}")
            lines.append(f"- Filed: {case.get('date_filed', 'N/A')}")

        if page < total_pages:
            lines.append(f"\n*Use page={page + 1} to see more cases*")

        return "\n".join(lines)

    except ValueError as e:
        return str(e)
    except Exception as e:
        return handle_api_error(e, f"list {scope} cases")


@mcp.tool(annotations=READ_ONLY_API_TOOL)
async def docketbird_get_case(case_id: str) -> str:
    """Get one case's metadata, including a pointer to its complaint.

    A lightweight, research-scope lookup: works for any case in DocketBird's
    index (not just your account's cases) and does NOT fetch the docket, so it
    can't hit the large-docket timeout. Use docketbird_get_case_details for the
    full docket sheet, and docketbird_ask_litigation_graph for parties/attorneys.

    When to use:
    - Resolving a case ID (e.g. from docketbird_search_cases) to its metadata
    - Jumping straight to the initiating complaint
    - Checking PACER case ID / client code without pulling the docket

    Args:
        case_id: DocketBird case ID (e.g., 'txwd-1:2022-cv-00398')
    """
    try:
        api_key = get_user_api_key()
        cprint(f"[MCP] docketbird_get_case: {case_id}", "green")
        data = await make_request(f"/cases/{case_id}", api_key=api_key)
        case = data.get("data", {}).get("case", {})

        lines = [
            f"# Case: {case.get('title', 'N/A')}",
            f"**ID**: {case.get('id', case_id)}",
            f"**Court**: {case.get('court_id', 'N/A')}",
            f"**Filed**: {case.get('date_filed') or 'N/A'}",
            f"**URL**: {case.get('url', 'N/A')}",
        ]
        if case.get("case_number"):
            lines.append(f"**Case Number**: {case.get('case_number')}")
        if case.get("pacer_case_id"):
            lines.append(f"**PACER Case ID**: {case.get('pacer_case_id')}")
        if case.get("client_code"):
            lines.append(f"**Client Code**: {case.get('client_code')}")

        complaint_id = case.get("complaint_document_id")
        complaint_status = case.get("complaint_status")
        if complaint_id:
            lines.append(f"\n**Complaint**: {complaint_id} ({complaint_status or 'status unknown'})")
            if complaint_status == "available":
                lines.append(
                    "_Fetch it with docketbird_download_document or "
                    "docketbird_get_document_text using that document ID._"
                )
        else:
            lines.append("\n_No complaint document is identified for this case._")

        return "\n".join(lines)

    except ValueError as e:
        return str(e)
    except Exception as e:
        return handle_api_error(e, f"case {case_id}")


@mcp.tool(annotations=READ_ONLY_API_TOOL)
async def docketbird_search_cases(
    query: str,
    court_id: str = "",
    filed_after: str = "",
    filed_before: str = "",
    exclude_unknown_dates: bool = False,
    size: int = 25,
    cursor: str = "",
) -> str:
    """Search ALL cases in DocketBird's index by case name or case number.

    Research scope: this covers every court and every case DocketBird knows
    about — not just cases on your account (that's docketbird_list_cases).

    Matching: case-number-shaped queries (e.g. '2:2017-bk-00112' or
    '17-bk-112') match on filing year, case type, and terminating digits;
    anything else matches against case names.

    Date filters match in tiers: cases with an exact filing date match at day
    precision; cases with only a known filing year match at year granularity;
    cases with no known date are included unless exclude_unknown_dates=True.

    When to use:
    - Finding a case's DocketBird ID from a name or number
    - Checking whether a company has been sued (pair with
      docketbird_ask_litigation_graph for who represented whom)

    Args:
        query: Case name (e.g. 'Immedia Semiconductor') or case number
               (e.g. '4:2022-cv-04775'). Max 500 chars.
        court_id: Comma-separated court restriction; each entry may be a slug
                  ('nysd'), an abbreviation ('S.D.N.Y.'), or a full court name.
        filed_after: Only cases filed on/after this date (YYYY-MM-DD, inclusive).
        filed_before: Only cases filed on/before this date (YYYY-MM-DD, inclusive).
        exclude_unknown_dates: Drop cases whose filing date and year are both
                               unknown from date-filtered results (default False).
        size: Results per page (default 25, max 50).
        cursor: Pagination cursor from a previous response's next-page note.
    """
    try:
        api_key = get_user_api_key()
        cprint(f"[MCP] docketbird_search_cases: {query!r}", "green")
        params: dict[str, Any] = {"q": query, "size": _clamp_cursor_size(size)}
        if court_id:
            params["court_id"] = court_id
        if filed_after:
            params["filed_after"] = filed_after
        if filed_before:
            params["filed_before"] = filed_before
        if exclude_unknown_dates:
            params["exclude_unknown_dates"] = "true"
        if cursor:
            params["cursor"] = cursor
        data = await make_request("/cases/search", params=params, api_key=api_key)

        payload = data.get("data", {})
        cases = payload.get("cases", [])
        found = payload.get("found", 0)
        next_cursor = payload.get("next_cursor")

        lines = [f"## Case search: {query!r}"]
        if not cases:
            lines.append("\n_No cases matched._")
        for case in cases:
            lines.append(f"\n**{case.get('title', 'N/A')}**")
            lines.append(f"- ID: {case.get('id')}")
            lines.append(f"- Court: {case.get('court_name') or case.get('court_id', 'N/A')}")
            lines.append(f"- Type: {case.get('case_type', 'N/A')}")
            if case.get("case_number"):
                lines.append(f"- Case Number: {case.get('case_number')}")
            filed = case.get("date_filed") or case.get("year_filed") or "unknown"
            lines.append(f"- Filed: {filed}")
            if case.get("complaint_document_id"):
                lines.append(
                    f"- Complaint: {case.get('complaint_document_id')} "
                    f"({case.get('complaint_status') or 'status unknown'})"
                )
            if case.get("canonical_url"):
                lines.append(f"- Page: {case.get('canonical_url')}")

        lines.extend(_cursor_footer(found, len(cases), next_cursor, "cases"))
        return "\n".join(lines)

    except ValueError as e:
        return str(e)
    except Exception as e:
        return handle_api_error(e, f"case search {query!r}")


_case_types_cache: list[dict[str, Any]] | None = None


def _load_case_types() -> list[dict[str, Any]]:
    """Load and cache the static case-types reference data.

    Case-type abbreviations have no API endpoint, so this stays a bundled file.
    (Courts, by contrast, are served live from GET /courts — the old bundled
    courts.json snapshot is no longer read by any tool.)
    """
    global _case_types_cache
    if _case_types_cache is None:
        with open(SCRIPT_DIR / "case_types.json", encoding="utf-8") as f:
            _case_types_cache = json.load(f).get("case_types", [])
    return _case_types_cache


@mcp.tool(annotations=READ_ONLY_API_TOOL)
async def docketbird_list_courts(search: str = "", court_system: str = "", court_type: str = "") -> str:
    """Look up the courts DocketBird covers (live from the API).

    Research scope — the full court set, independent of your account.

    Behavior:
    - No arguments: the curated set (~300 rows: all federal courts plus named
      state courts), followed by the case-type reference for the case ID format.
    - search: free-text lookup by court name ('Southern District of New York'),
      abbreviation ('S.D.N.Y.'), or court_id ('nysd'); returns up to 25 ranked
      matches from the FULL set of enabled courts, including several thousand
      unlisted state courts. The fastest way to resolve a court to its court_id.
    - court_system: browse every court inside one system (identifier from
      docketbird_list_court_systems), including unlisted ones.

    Args:
        search: Free-text court lookup (name, abbreviation, or court_id).
        court_system: Court-system identifier to browse (e.g. 'uc-tx-distct').
        court_type: Optional filter: 'federal' or 'state'.
    """
    try:
        api_key = get_user_api_key()
        cprint(f"[MCP] docketbird_list_courts (search={search!r}, court_system={court_system!r}, court_type={court_type!r})", "green")
        params: dict[str, Any] = {}
        if search.strip():
            params["q"] = search.strip()
        if court_system.strip():
            params["court_system"] = court_system.strip()
        if court_type.strip():
            params["type"] = court_type.strip()
        data = await make_request("/courts", params=params or None, api_key=api_key)

        courts = data.get("data", {}).get("courts", [])
        count = data.get("data", {}).get("count", len(courts))

        if search.strip():
            heading = f"## Courts matching '{search.strip()}' ({count}; top 25 ranked matches)"
        elif court_system.strip():
            heading = f"## Courts in system '{court_system.strip()}' ({count})"
        else:
            heading = f"## Courts ({count})"
        lines = [heading]
        if not courts:
            lines.append("_No courts matched. Try a broader term._")
        for court in courts:
            system = court.get("court_system")
            suffix = f" [{system}]" if system else ""
            lines.append(f"- **{court.get('court_id')}**: {court.get('court_name')}{suffix}")

        # Case-type reference only in the no-argument listing: it explains the
        # case ID format and would be noise on a targeted lookup.
        if not params:
            lines.extend(["", "## Case Types"])
            for ct in _load_case_types():
                lines.append(f"- **{ct['abbreviature']}**: {ct['name']} (e.g., {ct['example']})")

        return "\n".join(lines)

    except ValueError as e:
        return str(e)
    except Exception as e:
        return handle_api_error(e, "list courts")


@mcp.tool(annotations=READ_ONLY_API_TOOL)
async def docketbird_list_court_systems() -> str:
    """List every court system DocketBird covers (live from the API).

    Returns the federal system plus each state court system, with a
    human-readable name and how many covered courts each holds. Use a
    court_system_id with docketbird_list_courts(court_system=...) to browse the
    courts inside a system, including unlisted courts that don't appear in the
    default listing. Changes rarely; safe to cache.

    When to use:
    - Discovering what state-court coverage exists
    - Getting the identifier to browse one system's courts
    """
    try:
        api_key = get_user_api_key()
        cprint("[MCP] docketbird_list_court_systems", "green")
        data = await make_request("/court_systems", api_key=api_key)

        systems = data.get("data", {}).get("court_systems", [])
        count = data.get("data", {}).get("count", len(systems))

        lines = [f"## Court Systems ({count})"]
        for system in systems:
            state = f", state: {system.get('state')}" if system.get("state") else ""
            lines.append(
                f"- **{system.get('court_system_id')}**: {system.get('name')} "
                f"({system.get('court_count')} courts{state})"
            )
        lines.append(
            "\n_Browse one system's courts with docketbird_list_courts(court_system='<id>')._"
        )
        return "\n".join(lines)

    except ValueError as e:
        return str(e)
    except Exception as e:
        return handle_api_error(e, "list court systems")


@mcp.tool(annotations=DOWNLOAD_TOOL, structured_output=False)
async def docketbird_download_document(document_id: str, save_path: str | None = None) -> Any:
    """Download a specific document by ID.

    Returns the document content to **you** (the client) as an embedded resource
    so you can read or save it — this works over the remote HTTP connection. In
    local stdio mode, passing ``save_path`` instead writes the file to that folder
    on your own machine (the server runs locally there).

    When to use:
    - User wants to retrieve a specific filing
    - After searching for documents
    - Downloading individual documents

    Args:
        document_id: DocketBird document ID
        save_path: Local folder to save into. Only honored in local stdio mode,
                   where the server shares your filesystem. Ignored over a remote
                   HTTP connection (the file would land on the server, not your
                   machine), where the content is returned to you directly.

    Returns:
        - Remote, or local with no save_path: a list of content blocks — a text
          summary plus an embedded resource holding the document bytes (base64),
          capped at MAX_INLINE_SIZE. If the document exceeds that cap, returns a
          text message with its direct download URL instead of inlining it.
        - Local stdio with save_path: a text confirmation of the saved file path.
        - On error / unavailable / restricted: a plain text message.
    """
    try:
        api_key = get_user_api_key()
        cprint(f"[MCP] docketbird_download_document: {document_id}", "green")

        # Honor save_path only where it is useful: local stdio mode, where the
        # server shares the user's filesystem. Remote clients can't reach the
        # server's disk, so the path is ignored there (and not validated, since a
        # value we never use shouldn't be able to fail the request).
        save_to_disk = bool(save_path) and not _is_remote_session()
        save_dir = validate_save_path(save_path) if save_to_disk else None

        data = await make_request(f"/documents/{document_id}", api_key=api_key)
        document = data.get("data", {}).get("document", {})

        if document.get("restricted"):
            return (
                f"Document {document_id} is restricted and cannot be downloaded. "
                "Restricted filings are sealed or access-limited on PACER/DocketBird."
            )

        s3_url = document.get("docketbird_document_url")
        if not s3_url:
            return f"Document {document_id} exists but is not yet available for download"

        # Prefer the API-provided custom filename; fall back to the S3 URL.
        # Always sanitize (path-safety) regardless of source.
        filename = sanitize_filename(document.get("custom_filename") or s3_url)
        title = document.get("title") or filename

        if save_to_disk:
            save_dir.mkdir(parents=True, exist_ok=True)
            full_path = save_dir / filename
            cprint(f"[MCP] Downloading from S3 to disk: {s3_url[:50]}...", "cyan")
            try:
                downloaded_bytes = await _stream_to_file(s3_url, full_path)
            except DownloadTooLarge:
                return f"Download aborted: file exceeds {MAX_DOWNLOAD_SIZE // (1024 * 1024)}MB limit"
            cprint(f"[MCP] Downloaded: {full_path} ({downloaded_bytes} bytes)", "green")
            return f"Downloaded: {title} -> {full_path}"

        # Return content to the client (remote HTTP, or local with no save_path).
        cprint(f"[MCP] Streaming to client: {s3_url[:50]}...", "cyan")
        try:
            content = await _stream_to_memory(s3_url)
        except DownloadTooLarge:
            limit_mb = MAX_INLINE_SIZE // (1024 * 1024)
            return (
                f"'{title}' exceeds the {limit_mb}MB inline limit, so it was not "
                f"returned directly. Download it from this link instead (expires "
                f"shortly): {s3_url}"
            )

        cprint(f"[MCP] Returning {len(content)} bytes to client as embedded resource", "green")
        summary = TextContent(
            type="text",
            text=f"Retrieved '{title}' ({len(content)} bytes) as {filename}.",
        )
        return [summary, _document_resource(document_id, filename, content)]

    except ValueError as e:
        return f"Security error: {e}"
    except Exception as e:
        return handle_api_error(e, f"download document {document_id}")


@mcp.tool(annotations=DOWNLOAD_TOOL)
async def docketbird_download_files(case_id: str, save_path: str | None = None) -> str:
    """List or save every available document for a case.

    A case can hold many large PDFs, so over a remote HTTP connection this returns
    a list of per-document **direct download links** (pre-signed, short-lived)
    rather than inlining every file — fetch the ones you need, or call
    ``docketbird_download_document`` for a single document's content. In local
    stdio mode, passing ``save_path`` instead streams every file to that folder on
    your own machine.

    When to use:
    - User wants the complete case file archive
    - Bulk document retrieval
    - Surveying which filings are available to download

    Args:
        case_id: DocketBird case ID
        save_path: Local folder to save into. Only honored in local stdio mode,
                   where the server shares your filesystem. Over a remote HTTP
                   connection it is ignored and download links are returned instead.

    Returns:
        str: Markdown. Remote (or local with no save_path) lists each available
        document's title, ID, and direct download URL, plus counts of
        restricted/unavailable filings. Local stdio with save_path reports how
        many files were saved to disk and any that were skipped or failed.
    """
    try:
        api_key = get_user_api_key()
        cprint(f"[MCP] docketbird_download_files: {case_id}", "green")

        save_to_disk = bool(save_path) and not _is_remote_session()
        # Validate the path only when we'll actually write to disk; remote clients
        # can't reach the server's filesystem, so the path is ignored there.
        save_dir = validate_save_path(save_path) if save_to_disk else None

        data = await make_request("/documents", params={"case_id": case_id}, api_key=api_key)
        documents = data.get("data", {}).get("documents", [])

        if not save_to_disk:
            return _format_download_links(case_id, documents)

        downloaded = []
        skipped = []
        restricted = []
        failed = []

        save_dir.mkdir(parents=True, exist_ok=True)
        used_names: set[str] = set()

        for doc in documents:
            # Restricted filings are sealed/access-limited; skip defensively
            # (the /documents list may or may not carry this flag).
            if doc.get("restricted"):
                restricted.append(doc.get("id"))
                continue

            s3_url = doc.get("docketbird_document_url")
            if not s3_url:
                skipped.append(doc.get("id"))
                continue

            # Prefer API-provided custom filename when present; always sanitize.
            filename = sanitize_filename(doc.get("custom_filename") or s3_url)
            if filename in used_names:
                stem, dot, ext = filename.rpartition(".")
                base = stem if dot else filename
                suffix = ext if dot else ""
                n = 2
                while f"{base}-{n}{dot}{suffix}" in used_names:
                    n += 1
                filename = f"{base}-{n}{dot}{suffix}"
            used_names.add(filename)
            full_path = save_dir / filename
            try:
                cprint(f"[MCP] Downloading: {doc.get('title', 'N/A')[:40]}...", "cyan")
                await _stream_to_file(s3_url, full_path)
                downloaded.append(filename)
            except DownloadTooLarge:
                cprint(f"[MCP] Skipped {doc.get('id')}: exceeds size limit", "yellow")
                failed.append(f"{doc.get('id')} (too large)")
            except ValueError as ve:
                cprint(f"[MCP] Blocked download {doc.get('id')}: {ve}", "red")
                failed.append(f"{doc.get('id')} (blocked: {ve})")
            except Exception as e:
                cprint(f"[MCP] Failed to download {doc.get('id')}: {e}", "red")
                failed.append(str(doc.get("id")))

        lines = [f"## Download Results for {case_id}"]
        lines.append(f"**Downloaded**: {len(downloaded)} files to {save_dir}")
        if skipped:
            lines.append(f"**Skipped**: {len(skipped)} documents (not available)")
        if restricted:
            lines.append(f"**Restricted**: {len(restricted)} documents (sealed/access-limited)")
        if failed:
            lines.append(f"**Failed**: {len(failed)} documents")

        return "\n".join(lines)

    except ValueError as e:
        return f"Security error: {e}"
    except Exception as e:
        return handle_api_error(e, f"download files for case {case_id}")


@mcp.tool(annotations=READ_ONLY_API_TOOL)
async def docketbird_get_document(document_id: str) -> str:
    """Get one document's metadata and download links — without the bytes.

    Lightweight lookup for a single filing: title, filing date, restricted
    status, and (when retrieved) a direct PDF download link. Use
    docketbird_download_document for the file content itself, or
    docketbird_get_document_text for the extracted text.

    When to use:
    - Checking whether a filing is available/restricted before downloading
    - Getting a direct PDF link to hand to the user
    - Resolving a document ID from search results to its metadata

    Args:
        document_id: DocketBird document ID (e.g., 'txwd-1:2022-cv-00398-00177')
    """
    try:
        api_key = get_user_api_key()
        cprint(f"[MCP] docketbird_get_document: {document_id}", "green")
        data = await make_request(f"/documents/{document_id}", api_key=api_key)
        document = data.get("data", {}).get("document", {})

        lines = [
            f"# Document: {document.get('title', 'N/A')}",
            f"**ID**: {document.get('id', document_id)}",
            f"**Filed**: {document.get('filing_date') or 'N/A'}",
        ]
        if document.get("primary_docket_sheet_number") is not None:
            lines.append(f"**Docket #**: {document.get('primary_docket_sheet_number')}")
        if document.get("restricted"):
            lines.append("**Restricted**: yes (sealed/access-limited)")

        s3_url = document.get("docketbird_document_url")
        if s3_url:
            lines.append(f"**Download (link expires shortly)**: {s3_url}")
        elif not document.get("restricted"):
            lines.append("**Download**: not yet available (PDF not retrieved from the court yet)")
        if document.get("pacer_document_url"):
            lines.append(f"**Court/PACER link**: {document.get('pacer_document_url')}")
        if document.get("custom_filename"):
            lines.append(f"**Filename**: {document.get('custom_filename')}")

        return "\n".join(lines)

    except ValueError as e:
        return str(e)
    except Exception as e:
        return handle_api_error(e, f"document {document_id}")


MAX_TEXT_CHARS = 200_000


@mcp.tool(annotations=READ_ONLY_API_TOOL)
async def docketbird_get_document_text(document_id: str, offset: int = 0, max_chars: int = 50000) -> str:
    """Get the extracted plain text of a court filing.

    Returns what the document says (for summarizing, quoting, comparing) rather
    than its metadata or PDF — those come from docketbird_get_document /
    docketbird_download_document.

    Availability varies: some documents aren't downloaded yet, some are scans
    with no text layer, some docket entries are text-only stubs with no
    document. When no text is available this returns a clear message — the PDF
    may still be retrievable via docketbird_get_document.

    When to use:
    - Reading, summarizing, or quoting a filing's contents
    - Pulling the complaint's text after docketbird_get_case points to it

    Args:
        document_id: DocketBird document ID (e.g., 'txwd-1:2022-cv-00398-00177')
        offset: Character offset into the text to start from (for paging
                through long documents; default 0).
        max_chars: Maximum characters to return (default 50000, max 200000).
    """
    try:
        api_key = get_user_api_key()
        cprint(f"[MCP] docketbird_get_document_text: {document_id} (offset={offset})", "green")
        offset = max(0, offset)
        max_chars = max(1, min(max_chars, MAX_TEXT_CHARS))
        data = await make_request(f"/documents/{document_id}/text", api_key=api_key)

        document = data.get("data", {}).get("document", {})
        text = document.get("text") or ""
        upstream_truncated = bool(document.get("text_truncated"))

        if not text:
            return (
                f"No extracted text is available for document {document_id}. "
                "The PDF may still be available via docketbird_get_document."
            )

        total = len(text)
        window = text[offset : offset + max_chars]
        if offset >= total:
            return (
                f"Offset {offset} is beyond the end of the text "
                f"({total} characters available for document {document_id})."
            )

        lines = [
            f"# Text of: {document.get('title', document_id)}",
            f"_Characters {offset}-{offset + len(window)} of {total}._",
        ]
        if upstream_truncated:
            lines.append(
                "_Note: DocketBird truncated this text server-side — the full "
                "document is available as a PDF via docketbird_get_document._"
            )
        lines.extend(["", window])
        if offset + len(window) < total:
            lines.append(f"\n_More text remains: call again with offset={offset + len(window)}._")
        return "\n".join(lines)

    except ValueError as e:
        return str(e)
    except Exception as e:
        # The live API answers a missing/text-less document with 400
        # ("document not found") where the spec says 404; treat both as
        # "no text here," not as a hard error.
        if isinstance(e, httpx.HTTPStatusError) and e.response.status_code in (400, 404):
            api_msg = _api_error_message(e)
            return (
                f"No extracted text is available for document {document_id}"
                + (f" (DocketBird: {api_msg})" if api_msg else "")
                + ". The PDF may still be available via docketbird_get_document."
            )
        return handle_api_error(e, f"text of document {document_id}")


@mcp.tool(annotations=READ_ONLY_API_TOOL)
async def docketbird_get_calendar(case_id: str = "", days: int = 7) -> str:
    """Get calendar entries (deadlines, hearings, conferences) from your
    company's autocalendars — for one case, or company-wide.

    Practice scope: this reads YOUR company's autocalendars (requires a full
    DocketBird account with autocalendars created; see
    docketbird_create_autocalendar).

    Two scopes, one tool:
    - With case_id: every calendar entry for that case.
    - Without case_id: entries across ALL cases your company has active
      autocalendars for, within the next `days` days — "what deadlines does my
      firm have coming up?"

    The company-wide scope is served from a pre-computed rollup; if it has
    never been built, the API starts building it and this tool says to retry
    in a minute or two.

    Args:
        case_id: DocketBird case ID (e.g., 'txnd-3:2007-cv-01697').
                 Omit for the company-wide scope.
        days: Company-wide scope only: how many days ahead to include,
              starting today (default 7, clamped to 1-90 upstream).
              Ignored when case_id is given.
    """
    try:
        api_key = get_user_api_key()
        cprint(f"[MCP] docketbird_get_calendar: case_id={case_id!r} days={days}", "green")

        if case_id:
            data = await make_request("/calendar_entries", params={"case_id": case_id}, api_key=api_key)
            entries = data.get("data", {}).get("calendar_entries", [])
            if not entries:
                return f"No calendar entries found for case {case_id}"

            lines = [f"## Calendar Entries for {case_id} ({len(entries)} total)"]
            for entry in entries:
                lines.append(f"\n**{entry.get('title', 'N/A')}**")
                lines.append(f"- When: {entry.get('iso8601_datetime', 'N/A')}")
                lines.append(f"- ID: {entry.get('id')} (uuid: {entry.get('uuid', 'N/A')})")
                if entry.get("document_id"):
                    lines.append(f"- Document: {entry.get('document_id')}")
            return "\n".join(lines)

        # Company-wide scope
        data = await make_request("/calendar_entries", params={"days": days}, api_key=api_key)
        if data.get("status") == "pending":
            # 202: the rollup is being built for the first time.
            return (
                "Your company-wide calendar rollup is being built for the first "
                "time. Retry in a minute or two. "
                f"DocketBird: {data.get('message', '')}"
            )

        payload = data.get("data", {})
        entries = payload.get("calendar_entries", [])
        window = f"{payload.get('window_start', '?')} to {payload.get('window_end', '?')}"
        lines = [f"## Company-wide Calendar ({window}, {len(entries)} entries)"]
        if payload.get("calendar_last_updated"):
            lines.append(f"_Rollup last refreshed: {payload.get('calendar_last_updated')}_")
        if not entries:
            lines.append("\n_No calendar entries in this window._")
        for entry in entries:
            when = entry.get("date", "N/A")
            if entry.get("time"):
                when += f" {entry.get('time')}"
            lines.append(f"\n**{entry.get('title', 'N/A')}**")
            lines.append(f"- When: {when}")
            lines.append(f"- Case: {entry.get('case_name') or 'N/A'} ({entry.get('case_id')})")
            if entry.get("source_document_id"):
                lines.append(f"- Source document: {entry.get('source_document_id')}")
        return "\n".join(lines)

    except ValueError as e:
        return str(e)
    except Exception as e:
        # 404 means "nothing to report": for a case, no calendar; company-wide,
        # no active autocalendars. Surface DocketBird's message, not an error.
        if isinstance(e, httpx.HTTPStatusError) and e.response.status_code == 404:
            if case_id:
                return f"No calendar entries found for case {case_id}"
            api_msg = _api_error_message(e)
            return (
                "No company-wide calendar entries: "
                + (api_msg or "your company has no active autocalendars.")
                + " Create one with docketbird_create_autocalendar."
            )
        scope = f"case {case_id}" if case_id else "company-wide calendar"
        return handle_api_error(e, f"calendar for {scope}")


@mcp.tool(annotations=WRITE_TOOL)
async def docketbird_follow_case(case_id: str) -> str:
    """Follow a court case so DocketBird monitors it for new filings.

    When to use:
    - User wants to track/monitor a case for new documents
    - Setting up ongoing monitoring of a docket

    Followed federal cases are checked about twice weekly; state cases about
    once weekly. New filings trigger DocketBird's new-documents notifications.

    Args:
        case_id: DocketBird case ID (e.g., 'txnd-3:2007-cv-01697')
    """
    try:
        api_key = get_user_api_key()
        cprint(f"[MCP] docketbird_follow_case: {case_id}", "green")
        await make_post_request("/follow_case", body={"case_id": case_id}, api_key=api_key)
        return (
            f"Now following case {case_id}. DocketBird will monitor it for new "
            "filings (federal ~2x/week, state ~1x/week)."
        )

    except ValueError as e:
        return str(e)
    except Exception as e:
        return handle_api_error(e, f"follow case {case_id}")


@mcp.tool(annotations=WRITE_TOOL)
async def docketbird_create_autocalendar(case_id: str) -> str:
    """Create an autocalendar for a case, so its deadlines and hearings appear
    in your company's calendar (docketbird_get_calendar).

    Practice scope: acts on YOUR DocketBird account. Creation is queued — the
    case's docket sheet is updated first, then the autocalendar is built.
    Court (PACER) fees may apply for the docket update.

    When to use:
    - Adding a case's deadlines to the firm's calendar
    - After following a case you need to track dates for

    Args:
        case_id: DocketBird case ID (e.g., 'txnd-3:2007-cv-01697')
    """
    try:
        api_key = get_user_api_key()
        cprint(f"[MCP] docketbird_create_autocalendar: {case_id}", "green")
        await make_post_request("/create_autocalendar", body={"case_id": case_id}, api_key=api_key)
        return (
            f"Autocalendar creation queued for case {case_id}. The docket sheet "
            "will be updated first (court fees may apply), then calendar entries "
            "will appear via docketbird_get_calendar."
        )

    except ValueError as e:
        return str(e)
    except Exception as e:
        return handle_api_error(e, f"create autocalendar for case {case_id}")


@mcp.tool(annotations=READ_ONLY_API_TOOL)
async def docketbird_ask_litigation_graph(question: str) -> str:
    """Ask a natural-language question of DocketBird's litigation graph:
    parties, attorneys, law firms, judges, courts, and their connections.

    This is the ONLY source of party/attorney/firm/judge relationships — the
    docket endpoints do not return them. Examples: "What attorneys appeared
    for Google in the Northern District of California?", "Every case where
    Firm A appeared opposite Firm B", "What judges has Quinn Emanuel appeared
    before?".

    COVERAGE CEILING — read before trusting absence: the graph covers federal
    civil cases active in DocketBird's data flows since July 2025 (roughly 30%
    of federal civil cases). No criminal, bankruptcy, or state-court matters.
    Zero records means "not in the graph," NEVER "no such cases exist" — do
    not present an empty result as a finding that something doesn't exist.

    Behavior:
    - Slow: responses can take 10-25 seconds (an AI model interprets the
      question, then queries the graph).
    - Result shape varies with the question; entity IDs accompany names.
    - At most 200 records per response; 'truncated' means more matches exist —
      narrow the question to see the rest.
    - Attorney email addresses are never included. This tool reports exactly
      what the API returned — it never invents contact details.

    Args:
        question: The natural-language question (max 1000 characters).
    """
    try:
        api_key = get_user_api_key()
        cprint(f"[MCP] docketbird_ask_litigation_graph: {question!r}", "green")
        data = await make_post_request("/graph/ask", body={"question": question}, api_key=api_key)

        payload = data.get("data", {})
        records = payload.get("records") or []
        num_records = payload.get("num_records", len(records))
        interpretation = payload.get("interpretation")
        message = payload.get("message")
        coverage_note = payload.get("coverage_note")

        lines = ["## Litigation Graph Answer"]
        if interpretation:
            lines.append(f"**Understood as**: {interpretation}")
        if message:
            lines.append(f"**Note from DocketBird**: {message}")
        lines.append(f"**Records**: {num_records}")

        for i, record in enumerate(records, 1):
            fields = "; ".join(f"{k}: {v}" for k, v in record.items())
            lines.append(f"{i}. {fields}")

        if payload.get("truncated"):
            lines.append(
                "\n_Result truncated at the 200-record cap — more matches exist; "
                "narrow the question to see the rest._"
            )
        if num_records == 0:
            lines.append(
                "\n_Zero records = not in the graph (which covers ~30% of federal "
                "civil cases since July 2025) — NOT proof that no such cases exist._"
            )
        # The spec says coverage_note arrives on every response; live, it is
        # absent on populated ones. Always state the ceiling ourselves so a
        # partial result can't be relayed as an exhaustive one.
        lines.append(
            "\n_Coverage: "
            + (
                coverage_note
                or "federal civil cases in DocketBird's data flows since July 2025 "
                "(~30% of federal civil cases); no criminal, bankruptcy, or "
                "state-court matters — results may be incomplete"
            )
            + "_"
        )
        return "\n".join(lines)

    except ValueError as e:
        return str(e)
    except Exception as e:
        return handle_api_error(e, "litigation graph question")


# =============================================================================
# ASGI App: Rate Limiting + Custom Routes + MCP (with SDK OAuth)
# =============================================================================

mcp_app = mcp.streamable_http_app()

# Background cleanup task handle for HTTP mode (started/stopped via ASGI lifespan).
_cleanup_task: asyncio.Task | None = None


def _health_payload() -> dict[str, str]:
    """Body for GET /health: liveness plus the deployed commit for verifiability."""
    return {"status": "ok", "service": "docketbird-mcp", "version": GIT_SHA}


async def app(scope, receive, send):
    """ASGI app: custom routes + rate limiting + MCP/OAuth.

    Request flow:
    1. Non-HTTP (lifespan, etc.) -> forward to mcp_app (with DB init hook)
    2. /health -> health check (no rate limit)
    3. Rate limit check -> 429 if exceeded
    4. /signup, /login -> custom auth pages
    5. Everything else -> mcp_app (SDK handles /authorize, /token, /register,
       /.well-known/*, /mcp with OAuth middleware)
    """
    if scope["type"] == "lifespan":
        # Wrap the lifespan receive to init/cleanup auth DB alongside mcp_app's
        # own lifespan (StreamableHTTP session manager). FastMCP's lifespan only
        # runs via mcp.run(), not streamable_http_app(), so we hook in here.
        async def wrapped_receive():
            global _cleanup_task
            message = await receive()
            if message["type"] == "lifespan.startup":
                cprint("[MCP] Lifespan startup: initializing auth database", "yellow")
                await auth_db.initialize()
                if SERVICE_TOKEN and SERVICE_DOCKETBIRD_API_KEY:
                    await auth_db.ensure_service_token(SERVICE_TOKEN, SERVICE_DOCKETBIRD_API_KEY)
                    cprint("[MCP] Seeded service access token", "green")
                # Start periodic cleanup here too: FastMCP's lifespan only runs in
                # stdio mode, so without this, expired tokens/auth codes would
                # never be purged in HTTP (production) mode.
                _cleanup_task = asyncio.create_task(_periodic_cleanup())
            elif message["type"] == "lifespan.shutdown":
                cprint("[MCP] Lifespan shutdown: closing connections", "yellow")
                if _cleanup_task is not None:
                    _cleanup_task.cancel()
                await auth_db.close()
                await cleanup_http_client()
            return message

        await mcp_app(scope, wrapped_receive, send)
        return

    if scope["type"] != "http":
        await mcp_app(scope, receive, send)
        return

    path = scope["path"]

    # Health check: no rate limit
    if path == "/health":
        response = JSONResponse(_health_payload())
        await response(scope, receive, send)
        return

    # Rate limit all other endpoints
    client_ip = get_client_ip(scope)
    if not rate_limiter.is_allowed(client_ip):
        cprint(f"[MCP] Rate limit exceeded for {client_ip}", "red")
        response = JSONResponse(
            {"error": "Rate limit exceeded. Try again later."},
            status_code=429,
        )
        await response(scope, receive, send)
        return

    # Signup page (no OAuth auth required)
    if path == "/signup":
        request = Request(scope, receive)
        response = await handle_signup(request, auth_db)
        await response(scope, receive, send)
        return

    # Login page (no OAuth auth required, used during OAuth flow)
    if path == "/login":
        request = Request(scope, receive)
        response = await handle_login(request, auth_db)
        await response(scope, receive, send)
        return

    # Change password page (no OAuth auth required)
    if path == "/change-password":
        request = Request(scope, receive)
        response = await handle_change_password(request, auth_db)
        await response(scope, receive, send)
        return

    # Change API key page (no OAuth auth required)
    if path == "/change-api-key":
        request = Request(scope, receive)
        response = await handle_change_api_key(request, auth_db, validate_docketbird_api_key)
        await response(scope, receive, send)
        return

    # Everything else: SDK routes (OAuth endpoints + MCP with auth middleware)
    await mcp_app(scope, receive, send)


# =============================================================================
# CLI Entry Point
# =============================================================================

if __name__ == "__main__":
    import argparse

    import uvicorn

    parser = argparse.ArgumentParser(description="DocketBird MCP Server")
    parser.add_argument(
        "--transport",
        choices=["stdio", "http"],
        default="stdio",
        help="Transport type: stdio or http",
    )
    parser.add_argument("--host", default="0.0.0.0", help="Host to bind to")
    parser.add_argument("--port", type=int, default=8080, help="Port to listen on")
    args = parser.parse_args()

    if args.transport == "stdio":
        cprint("Starting DocketBird MCP (stdio transport)...", "green")
        if not FALLBACK_API_KEY:
            cprint("WARNING: DOCKETBIRD_API_KEY not set. Tools will fail without it.", "red")
        mcp.run(transport="stdio")
    else:
        cprint(f"Starting DocketBird MCP (HTTP + OAuth) on {args.host}:{args.port}", "green")
        cprint(f"Server URL: {SERVER_URL}", "yellow")
        cprint("Health check: /health", "yellow")
        cprint("MCP endpoint: /mcp (OAuth protected)", "yellow")
        cprint("Signup: /signup", "yellow")
        cprint("OAuth metadata: /.well-known/oauth-authorization-server", "yellow")
        uvicorn.run(app, host=args.host, port=args.port)
