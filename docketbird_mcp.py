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
import mimetypes
import os
import re
import json
import sys
import time
from contextlib import asynccontextmanager
from typing import Literal, Any
from pathlib import Path
from urllib.parse import urlparse

import httpx
from mcp.server.auth.middleware.auth_context import get_access_token
from mcp.server.auth.settings import AuthSettings, ClientRegistrationOptions
from mcp.server.fastmcp import FastMCP
from mcp.types import BlobResourceContents, EmbeddedResource, TextContent, ToolAnnotations
from termcolor import cprint as _cprint
from starlette.requests import Request
from starlette.responses import JSONResponse


def cprint(*args, **kwargs):
    """Log to stderr, never stdout.

    The stdio transport speaks JSON-RPC over stdout; any stray stdout write
    corrupts that stream and breaks the client. Routing all diagnostic output
    to stderr keeps stdio mode working and is harmless in HTTP mode.
    """
    kwargs.setdefault("file", sys.stderr)
    _cprint(*args, **kwargs)

from auth_provider import (
    AuthDB,
    DocketBirdAccessToken,
    DocketBirdAuthProvider,
    handle_change_api_key,
    handle_change_password,
    handle_login,
    handle_signup,
)

# =============================================================================
# Configuration
# =============================================================================

SCRIPT_DIR = Path(__file__).parent.resolve()
BASE_URL = "https://api.docketbird.com"
SERVER_URL = os.getenv("SERVER_URL", "http://localhost:8080")

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

    Rejects any path containing '..' before resolution. (After .resolve() the
    string can no longer contain '..', so there is nothing further to check.)
    """
    if ".." in save_path:
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

LOCAL_READ_TOOL = ToolAnnotations(
    readOnlyHint=True,
    destructiveHint=False,
    idempotentHint=True,
    openWorldHint=False,  # Local JSON files only
)

# =============================================================================
# Tools
# =============================================================================


@mcp.tool(annotations=READ_ONLY_API_TOOL)
async def docketbird_get_case_details(case_id: str, page: int = 1, page_size: int = 20) -> str:
    """Get comprehensive details about a federal court case.

    When to use:
    - User wants full case information including parties and documents
    - Before downloading documents (to see what's available)
    - Starting point for case research

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
        parties = data.get("data", {}).get("parties", [])
        documents = data.get("data", {}).get("documents", [])

        # Best-effort: the dedicated single-case endpoint adds PACER case ID and
        # client code that /documents does not return. Never fail the tool on this.
        pacer_case_id = None
        client_code = None
        try:
            case_data = await make_request(f"/cases/{case_id}", api_key=api_key)
            case_detail = case_data.get("data", {}).get("case", {})
            pacer_case_id = case_detail.get("pacer_case_id")
            client_code = case_detail.get("client_code")
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
        lines.extend(["", "## Parties"])
        for party in parties:
            lines.append(f"- {party.get('name', 'N/A')} ({party.get('type', 'N/A')})")

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
    """Search for specific documents within a case.

    When to use:
    - User wants to find specific filings (e.g., "motion to dismiss")
    - Narrowing down documents before download
    - Finding documents by keyword

    Args:
        case_id: DocketBird case ID
        search_term: Term to search for in document titles/descriptions
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
async def docketbird_list_cases(scope: Literal["company", "user"], page: int = 1, page_size: int = 20) -> str:
    """List cases belonging to your account.

    When to use:
    - User wants to see their tracked cases
    - Starting point for case research
    - Finding case IDs for further operations

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


_reference_cache: dict[str, list[dict[str, Any]]] | None = None


def _load_reference_data() -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Load and cache the static courts/case-types reference data.

    These JSON files ship with the server and never change at runtime, so we
    parse them once and reuse the result on subsequent calls.
    """
    global _reference_cache
    if _reference_cache is None:
        with open(SCRIPT_DIR / "courts.json", "r", encoding="utf-8") as f:
            courts = json.load(f).get("courts", [])
        with open(SCRIPT_DIR / "case_types.json", "r", encoding="utf-8") as f:
            case_types = json.load(f).get("case_types", [])
        _reference_cache = {"courts": courts, "case_types": case_types}
    return _reference_cache["courts"], _reference_cache["case_types"]


@mcp.tool(annotations=LOCAL_READ_TOOL)
async def docketbird_list_courts(search: str = "") -> str:
    """Get reference list of available courts and case types.

    When to use:
    - User needs court codes for case lookup
    - Understanding case ID format
    - Reference for valid court identifiers

    Args:
        search: Optional case-insensitive filter applied to the court code and
                name (e.g. 'california', 'nysd'). Empty returns all courts.
    """
    try:
        cprint(f"[MCP] docketbird_list_courts (search={search!r})", "green")
        courts, case_types = _load_reference_data()

        term = search.strip().lower()
        if term:
            courts = [
                c for c in courts
                if term in c.get("value", "").lower()
                or term in c.get("court_name", "").lower()
            ]

        heading = f"## Courts matching '{search}' ({len(courts)})" if term else f"## Courts ({len(courts)})"
        lines = ["# Court Reference Data", "", heading]
        if not courts:
            lines.append("_No courts matched your search. Try a broader term._")
        for court in courts:
            lines.append(f"- **{court['value']}**: {court['court_name']}")

        lines.extend(["", "## Case Types"])
        for ct in case_types:
            lines.append(f"- **{ct['abbreviature']}**: {ct['name']} (e.g., {ct['example']})")

        return "\n".join(lines)

    except FileNotFoundError as e:
        return f"Error: Reference data file not found: {e}"
    except Exception as e:
        return f"Error loading court data: {e}"


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
async def docketbird_get_calendar(case_id: str) -> str:
    """Get calendar entries (deadlines and hearings) for a case.

    When to use:
    - User wants upcoming deadlines or scheduled hearings for a case
    - Tracking court dates and filing deadlines
    - Reviewing a case's docket schedule

    Args:
        case_id: DocketBird case ID (e.g., 'txnd-3:2007-cv-01697')
    """
    try:
        api_key = get_user_api_key()
        cprint(f"[MCP] docketbird_get_calendar: {case_id}", "green")
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

    except ValueError as e:
        return str(e)
    except Exception as e:
        # The API returns 404 when a case has no calendar; treat as empty, not error.
        if isinstance(e, httpx.HTTPStatusError) and e.response.status_code == 404:
            return f"No calendar entries found for case {case_id}"
        return handle_api_error(e, f"calendar for case {case_id}")


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


# =============================================================================
# ASGI App: Rate Limiting + Custom Routes + MCP (with SDK OAuth)
# =============================================================================

mcp_app = mcp.streamable_http_app()

# Background cleanup task handle for HTTP mode (started/stopped via ASGI lifespan).
_cleanup_task: asyncio.Task | None = None


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
        response = JSONResponse({"status": "ok", "service": "docketbird-mcp"})
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
