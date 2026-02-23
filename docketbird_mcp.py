#!/usr/bin/env python3
"""DocketBird MCP Server - Production Ready (MCP Spec 2025-03-26)

Provides tools for searching and downloading federal court documents via DocketBird API.
Deployed on DigitalOcean with Streamable HTTP transport.

Auth: Per-user DocketBird API keys via OAuth. Users register at /signup with their
own API key, then authenticate via OAuth when connecting from Claude.ai.
In stdio mode, falls back to DOCKETBIRD_API_KEY env var.
"""

import asyncio
import os
import re
import json
import time
from contextlib import asynccontextmanager
from typing import Literal, Any
from pathlib import Path
from urllib.parse import urlparse

import httpx
from mcp.server.auth.middleware.auth_context import get_access_token
from mcp.server.auth.settings import AuthSettings, ClientRegistrationOptions
from mcp.server.fastmcp import FastMCP
from mcp.types import ToolAnnotations
from termcolor import cprint
from starlette.requests import Request
from starlette.responses import JSONResponse

from auth_provider import (
    AuthDB,
    DocketBirdAccessToken,
    DocketBirdAuthProvider,
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

# Max file size for downloads (50 MB)
MAX_DOWNLOAD_SIZE = 50 * 1024 * 1024

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
            cprint("[MCP] Cleaned up expired auth records", "yellow")
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
        return messages.get(status, f"HTTP {status} error for {operation}.")
    if isinstance(error, httpx.TimeoutException):
        return f"Request timed out for {operation}. Try again."
    if isinstance(error, httpx.ConnectError):
        return f"Connection failed for {operation}. Check internet connection."
    return f"Error for {operation}: {type(error).__name__}: {error}"


# =============================================================================
# Security: Path Validation
# =============================================================================


def validate_save_path(save_path: str) -> Path:
    """Validate save path to prevent path traversal attacks."""
    if ".." in save_path:
        raise ValueError("Path traversal not allowed: '..' detected in path")

    resolved = Path(save_path).expanduser().resolve()

    # Ensure the resolved path doesn't contain traversal after resolution
    if ".." in str(resolved):
        raise ValueError("Path traversal detected after resolution")

    return resolved


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
        page_size = min(page_size, 50)
        data = await make_request("/documents", params={"case_id": case_id}, api_key=api_key)

        case = data.get("data", {}).get("case", {})
        parties = data.get("data", {}).get("parties", [])
        documents = data.get("data", {}).get("documents", [])

        total_docs = len(documents)
        start = (page - 1) * page_size
        end = start + page_size
        page_docs = documents[start:end]
        total_pages = (total_docs + page_size - 1) // page_size if total_docs > 0 else 1

        lines = [
            f"# Case: {case.get('title', 'N/A')}",
            f"**Court**: {case.get('court_id', 'N/A')}",
            f"**Filed**: {case.get('date_filed', 'N/A')}",
            f"**Closed**: {case.get('date_closed') or 'Open'}",
            f"**URL**: {case.get('url', 'N/A')}",
            "",
            "## Parties",
        ]
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
        page_size = min(page_size, 50)
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

        total = len(matches)
        start = (page - 1) * page_size
        end = start + page_size
        page_matches = matches[start:end]
        total_pages = (total + page_size - 1) // page_size

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
        page_size = min(page_size, 50)
        data = await make_request("/cases", params={"scope": scope}, api_key=api_key)

        cases = data.get("data", {}).get("cases", [])

        if not cases:
            return f"No cases found for {scope} scope"

        total = len(cases)
        start = (page - 1) * page_size
        end = start + page_size
        page_cases = cases[start:end]
        total_pages = (total + page_size - 1) // page_size

        lines = [f"## {scope.title()} Cases (page {page}/{total_pages}, {total} total)"]
        for case in page_cases:
            lines.append(f"\n**{case.get('title', 'N/A')}**")
            lines.append(f"- ID: {case.get('id')}")
            lines.append(f"- Court: {case.get('court_id')}")
            lines.append(f"- Filed: {case.get('date_filed', 'N/A')}")

        if page < total_pages:
            lines.append(f"\n*Use page={page + 1} to see more cases*")

        return "\n".join(lines)

    except ValueError as e:
        return str(e)
    except Exception as e:
        return handle_api_error(e, f"list {scope} cases")


@mcp.tool(annotations=LOCAL_READ_TOOL)
async def docketbird_list_courts() -> str:
    """Get reference list of available courts and case types.

    When to use:
    - User needs court codes for case lookup
    - Understanding case ID format
    - Reference for valid court identifiers
    """
    try:
        cprint("[MCP] docketbird_list_courts", "green")

        courts_path = SCRIPT_DIR / "courts.json"
        case_types_path = SCRIPT_DIR / "case_types.json"

        with open(courts_path, "r", encoding="utf-8") as f:
            courts_data = json.load(f)

        with open(case_types_path, "r", encoding="utf-8") as f:
            case_types_data = json.load(f)

        lines = ["# Court Reference Data", "", "## Courts (first 20)"]
        for court in courts_data.get("courts", [])[:20]:
            lines.append(f"- **{court['value']}**: {court['court_name']}")

        lines.extend(["", "## Case Types"])
        for ct in case_types_data.get("case_types", []):
            lines.append(f"- **{ct['abbreviature']}**: {ct['name']} (e.g., {ct['example']})")

        return "\n".join(lines)

    except FileNotFoundError as e:
        return f"Error: Reference data file not found: {e}"
    except Exception as e:
        return f"Error loading court data: {e}"


@mcp.tool(annotations=DOWNLOAD_TOOL)
async def docketbird_download_document(document_id: str, save_path: str) -> str:
    """Download a specific document by ID.

    When to use:
    - User wants to retrieve a specific filing
    - After searching for documents
    - Downloading individual documents

    Args:
        document_id: DocketBird document ID
        save_path: Folder path where file should be saved
    """
    try:
        api_key = get_user_api_key()
        cprint(f"[MCP] docketbird_download_document: {document_id}", "green")

        # Validate path (security)
        save_dir = validate_save_path(save_path)

        data = await make_request(f"/documents/{document_id}", api_key=api_key)
        document = data.get("data", {}).get("document", {})

        s3_url = document.get("docketbird_document_url")
        if not s3_url:
            return f"Document {document_id} exists but is not yet available for download"

        # Validate URL domain (SSRF protection)
        validate_download_url(s3_url)

        # Streaming download with size limit (S3 URLs are pre-signed, no API key needed)
        client = get_http_client()
        cprint(f"[MCP] Downloading from S3: {s3_url[:50]}...", "cyan")

        filename = sanitize_filename(s3_url)
        save_dir.mkdir(parents=True, exist_ok=True)
        full_path = save_dir / filename

        async with client.stream("GET", s3_url) as response:
            response.raise_for_status()
            downloaded_bytes = 0
            with open(full_path, "wb") as f:
                async for chunk in response.aiter_bytes(chunk_size=8192):
                    downloaded_bytes += len(chunk)
                    if downloaded_bytes > MAX_DOWNLOAD_SIZE:
                        f.close()
                        full_path.unlink(missing_ok=True)
                        return f"Download aborted: file exceeds {MAX_DOWNLOAD_SIZE // (1024*1024)}MB limit"
                    f.write(chunk)

        cprint(f"[MCP] Downloaded: {full_path} ({downloaded_bytes} bytes)", "green")
        return f"Downloaded: {document.get('title')} -> {full_path}"

    except ValueError as e:
        return f"Security error: {e}"
    except Exception as e:
        return handle_api_error(e, f"download document {document_id}")


@mcp.tool(annotations=DOWNLOAD_TOOL)
async def docketbird_download_files(case_id: str, save_path: str) -> str:
    """Download all available documents for a case.

    When to use:
    - User wants complete case file archive
    - Bulk document retrieval
    - Downloading all available filings at once

    Args:
        case_id: DocketBird case ID
        save_path: Folder path where files should be saved
    """
    try:
        api_key = get_user_api_key()
        cprint(f"[MCP] docketbird_download_files: {case_id}", "green")

        # Validate path (security)
        save_dir = validate_save_path(save_path)

        data = await make_request("/documents", params={"case_id": case_id}, api_key=api_key)
        documents = data.get("data", {}).get("documents", [])

        downloaded = []
        skipped = []
        failed = []

        save_dir.mkdir(parents=True, exist_ok=True)

        client = get_http_client()
        for doc in documents:
            s3_url = doc.get("docketbird_document_url")
            if not s3_url:
                skipped.append(doc.get("id"))
                continue

            try:
                # Validate URL domain (SSRF protection)
                validate_download_url(s3_url)

                cprint(f"[MCP] Downloading: {doc.get('title', 'N/A')[:40]}...", "cyan")
                filename = sanitize_filename(s3_url)
                full_path = save_dir / filename

                async with client.stream("GET", s3_url) as response:
                    response.raise_for_status()
                    downloaded_bytes = 0
                    with open(full_path, "wb") as f:
                        async for chunk in response.aiter_bytes(chunk_size=8192):
                            downloaded_bytes += len(chunk)
                            if downloaded_bytes > MAX_DOWNLOAD_SIZE:
                                f.close()
                                full_path.unlink(missing_ok=True)
                                cprint(f"[MCP] Skipped {doc.get('id')}: exceeds size limit", "yellow")
                                failed.append(f"{doc.get('id')} (too large)")
                                break
                        else:
                            downloaded.append(filename)
                            continue
                    # break from inner loop means size exceeded, continue outer loop
                    continue

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
        if failed:
            lines.append(f"**Failed**: {len(failed)} documents")

        return "\n".join(lines)

    except ValueError as e:
        return f"Security error: {e}"
    except Exception as e:
        return handle_api_error(e, f"download files for case {case_id}")


# =============================================================================
# ASGI App: Rate Limiting + Custom Routes + MCP (with SDK OAuth)
# =============================================================================

mcp_app = mcp.streamable_http_app()


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
            message = await receive()
            if message["type"] == "lifespan.startup":
                cprint("[MCP] Lifespan startup: initializing auth database", "yellow")
                await auth_db.initialize()
            elif message["type"] == "lifespan.shutdown":
                cprint("[MCP] Lifespan shutdown: closing connections", "yellow")
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
