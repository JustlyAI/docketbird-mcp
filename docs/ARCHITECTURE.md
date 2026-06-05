# DocketBird MCP — Architecture

This document explains how the server is put together: the transports it speaks,
how OAuth maps Claude users to per-user DocketBird API keys, the request
lifecycle, the database schema, and the security model.

## Components

| File                 | Responsibility                                                              |
| -------------------- | -------------------------------------------------------------------------- |
| `docketbird_mcp.py`  | MCP server, tools, HTTP client, ASGI app, rate limiting, CLI entry point.  |
| `auth_provider.py`   | OAuth Authorization Server provider, SQLite auth DB, signup/login HTML.     |
| `courts.json`        | Static reference data: court codes → names (300+ courts).                   |
| `case_types.json`    | Static reference data: case-type abbreviations and examples.               |
| `Dockerfile`         | Container image (non-root, HTTP transport, health check).                  |
| `.github/workflows/` | Build/push image and deploy to DigitalOcean on push to `main`.             |

## Transports

The server supports two transports, selected by `--transport`:

- **stdio** (`mcp.run(transport="stdio")`) — for local clients (Claude Desktop,
  Cursor). No OAuth; the API key comes from `DOCKETBIRD_API_KEY`. The FastMCP
  `lifespan` initializes the auth DB and starts the periodic cleanup task.
  **All logging goes to stderr** so it never corrupts the JSON-RPC stream on
  stdout.
- **Streamable HTTP** (`uvicorn.run(app, ...)`) — for the remote deployment.
  A custom ASGI wrapper (`app`) adds health checks, rate limiting, and the
  signup/login pages around the SDK's MCP + OAuth routes. The ASGI `lifespan`
  hook initializes the DB and starts the cleanup task.

## Per-user API keys via OAuth

The remote server holds **no shared DocketBird key**. Each user registers their
own key, and it is attached to the OAuth access token the SDK issues to Claude.

```
Claude.ai                     DocketBird MCP                         DocketBird API
   │                                │                                       │
   │  GET /.well-known/oauth-...    │  (SDK serves OAuth metadata)          │
   │ ─────────────────────────────►│                                       │
   │  POST /register (DCR)          │  register_client → oauth_clients      │
   │ ─────────────────────────────►│                                       │
   │  GET /authorize                │  authorize() stores pending_auth,     │
   │ ─────────────────────────────►│  redirects to /login?auth_session=... │
   │  (user logs in at /login)      │  authenticate_user (bcrypt)           │
   │                                │  → save_auth_code, redirect back      │
   │  POST /token (code + PKCE)     │  exchange_authorization_code():       │
   │ ─────────────────────────────►│  look up user, mint access token with │
   │                                │  user's docketbird_api_key embedded   │
   │  POST /mcp (Bearer token)      │  SDK validates token → tool runs      │
   │ ─────────────────────────────►│  get_user_api_key() reads key ───────►│ Bearer key
```

Key points:

- **PKCE** is enforced by the SDK at the `/token` step; the provider never sees
  the raw `code_verifier`.
- The access token row stores a **copy** of the user's API key. Changing the key
  (`/change-api-key`) therefore clears existing access tokens so the next refresh
  re-reads the current key. Refresh tokens are kept so clients re-sync seamlessly.
- `redirect_uri` is validated against the registered client's allowed URIs before
  an auth code is issued.

## Request lifecycle (HTTP mode)

The ASGI `app` in `docketbird_mcp.py` routes each request:

1. `lifespan` events → initialize/close the DB and start/stop the cleanup task.
2. `GET /health` → `{"status": "ok"}`, **not** rate limited.
3. Per-IP rate limit check (`30 req / 60s`) → `429` if exceeded.
4. `/signup`, `/login`, `/change-password`, `/change-api-key` → custom HTML pages.
5. Everything else → the SDK's MCP app (`/authorize`, `/token`, `/register`,
   `/.well-known/*`, and `/mcp` behind the OAuth middleware).

Client IP for rate limiting is taken from the **last** `X-Forwarded-For` entry,
which the trusted Caddy proxy appends (an attacker can prepend fakes but cannot
control the appended value).

## Database schema (SQLite, `DATA_DIR/auth.db`)

WAL mode, foreign keys on. Tables:

- `users` — `id`, `email` (unique), `password_hash` (bcrypt), `docketbird_api_key`, `created_at`.
- `oauth_clients` — registered DCR clients (`client_id`, serialized client info).
- `pending_auth` — in-flight authorize requests during login (`session_id`, params, expiry).
- `auth_codes` — single-use authorization codes (with PKCE challenge, redirect URI, expiry).
- `access_tokens` — issued access tokens (embed the user's API key + expiry).
- `refresh_tokens` — rotating refresh tokens (expiry).

Expiring rows are removed lazily on read and proactively by the hourly
`cleanup_expired()` task.

## HTTP client & downloads

A single pooled `httpx.AsyncClient` (`get_http_client`) is reused for all
DocketBird API calls and S3 downloads. Downloads stream to disk in 8 KB chunks
through `_stream_to_file`, which:

- validates the URL against the SSRF allowlist (`*.s3.amazonaws.com`,
  `api.docketbird.com`) and requires HTTPS,
- enforces a hard `MAX_DOWNLOAD_SIZE` (50 MB), deleting any partial file and
  raising `DownloadTooLarge` if exceeded,
- sanitizes the destination filename (no traversal, no hidden files).

## Security model (summary)

- OAuth 2.1 + PKCE; no shared server-side API key.
- Per-user keys stored alongside bcrypt-hashed passwords.
- Per-IP sliding-window rate limiting, with periodic pruning of idle IPs.
- SSRF allowlist + HTTPS-only for downloads; path-traversal guards on save paths.
- Security headers (CSP, `X-Frame-Options`, `nosniff`) on all HTML responses.
- Non-root container; pinned dependencies and SHA-pinned GitHub Actions.
- Diagnostics logged to stderr only.
