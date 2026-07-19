# DocketBird MCP Server

An MCP server for searching and downloading court documents via the DocketBird API. Deployed on DigitalOcean with Docker, using OAuth 2.0 so each user brings their own DocketBird API key.

## Tools

Research tools work across DocketBird's full index (all courts, all cases);
account tools act on your firm's own DocketBird data.

| Tool                              | Description                                     |
| --------------------------------- | ----------------------------------------------- |
| `docketbird_search_cases`         | Search ALL cases by name or case number (cursor-paginated) |
| `docketbird_fulltext_search`      | Full-text search of filing bodies across the whole corpus; `my_cases_only` restricts to your firm's cases |
| `docketbird_get_case`             | One case's metadata + complaint pointer (no docket fetch) |
| `docketbird_get_case_details`     | Full docket sheet: case info + paginated document list |
| `docketbird_search_documents`     | Match docket-entry titles/descriptions within one case |
| `docketbird_get_document`         | One document's metadata and download links (no bytes) |
| `docketbird_get_document_text`    | Extracted plain text of a filing (pageable via `offset`) |
| `docketbird_download_document`    | Retrieve a single document's content (or save it locally in stdio) |
| `docketbird_download_files`       | List a case's documents with direct download links (or save them locally in stdio) |
| `docketbird_ask_litigation_graph` | Natural-language questions about parties, attorneys, firms, judges (federal civil, ~30% coverage since July 2025) |
| `docketbird_list_courts`          | Look up courts live from the API (`search`, `court_system`, `court_type`) |
| `docketbird_list_court_systems`   | List every covered court system                 |
| `docketbird_list_cases`           | List cases on your account (company or user scope) |
| `docketbird_get_calendar`         | Calendar entries for a case, or company-wide (`days` window) |
| `docketbird_create_autocalendar`  | Create an autocalendar for a case (queued; court fees may apply) |
| `docketbird_follow_case`          | Follow a case so DocketBird monitors new filings |

> **Using these tools from an agent:** a ready-to-install Claude skill lives in
> [`skills/docketbird-mcp/`](skills/docketbird-mcp/SKILL.md), covering the case-ID
> format, each tool, and common research workflows.

## Requirements

- Python 3.11
- uv package manager

## Setup

1. Install uv:

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
```

2. Create and activate a virtual environment:

```bash
uv venv
source .venv/bin/activate
```

3. Install dependencies:

```bash
uv pip install -r requirements.txt
```

## Running the Server

```bash
# stdio transport (uses DOCKETBIRD_API_KEY env var, no OAuth)
DOCKETBIRD_API_KEY="your-key" python docketbird_mcp.py --transport stdio

# HTTP transport with OAuth (Streamable HTTP at /mcp)
python docketbird_mcp.py --transport http
# Then visit http://localhost:8080/signup to create an account
```

> **Note:** All diagnostic logging goes to **stderr**, never stdout. This keeps
> the stdio JSON-RPC stream clean — writing logs to stdout would corrupt it and
> break the client.

## Environment Variables

| Variable             | Mode  | Default                 | Description                                                                 |
| -------------------- | ----- | ----------------------- | --------------------------------------------------------------------------- |
| `DOCKETBIRD_API_KEY` | stdio | _(none)_                | API key used for all requests in stdio mode (no OAuth). Required for stdio.  |
| `SERVER_URL`         | http  | `http://localhost:8080` | Public base URL. Used as the OAuth issuer/resource URL and for redirects. Must match the URL clients connect to. |
| `DATA_DIR`           | http  | `./data`                | Directory holding the SQLite auth database. Mounted as a volume in Docker.   |

See [`.env.example`](.env.example) for a template.

## Connecting to the Deployed Server

See [docs/CONNECTING.md](docs/CONNECTING.md) for the full walkthrough, or
[DocketBird_MCP_Installation_Guide.pdf](DocketBird_MCP_Installation_Guide.pdf) for the same guide with screenshots.

### Quick version

1. Register at [https://app.docketbird-mcp.com/signup](https://app.docketbird-mcp.com/signup) with your email, password, and DocketBird API key
2. In Claude.ai or Claude Desktop, add a remote MCP server with URL `https://app.docketbird-mcp.com/mcp`
3. Claude auto-discovers OAuth, redirects you to log in, and connects

### Stdio (local development)

For Claude Desktop (`~/Library/Application Support/Claude/claude_desktop_config.json`) or Cursor (`~/.cursor/mcp.json`):

```json
{
  "mcpServers": {
    "docketbird-mcp": {
      "command": "uv",
      "args": [
        "run",
        "--directory",
        "/path/to/docketbird-mcp-plus",
        "python",
        "docketbird_mcp.py"
      ],
      "env": {
        "DOCKETBIRD_API_KEY": "YOUR_KEY"
      }
    }
  }
}
```

## Authentication

The server uses OAuth 2.0 with PKCE for HTTP mode. Each user registers with their own DocketBird API key, which is stored server-side and attached to OAuth tokens. The SDK handles the protocol endpoints automatically:

- `/.well-known/oauth-authorization-server` - OAuth metadata discovery
- `/register` - Dynamic Client Registration
- `/authorize` - Authorization endpoint (redirects to `/login`)
- `/token` - Token exchange and refresh

In stdio mode, the `DOCKETBIRD_API_KEY` env var is used directly (no OAuth).

## Security

- OAuth 2.0 with PKCE (no shared API key on the server)
- Per-user DocketBird API keys stored in SQLite with bcrypt-hashed passwords
- Rate limiting: 30 requests per 60 seconds per IP
- HTTPS-only downloads with SSRF domain allowlist
- Path traversal protection on file downloads
- Container runs as non-root `mcpuser`
- GitHub Actions pinned to commit SHAs
- Dependencies pinned to exact versions
- Expired tokens, auth codes, and pending sessions are purged hourly (in both stdio and HTTP modes)

> **Downloads — where files go:** over a remote (HTTP) connection the download
> tools return document content and links to your client; a `save_path` is ignored
> (it would write to the server, not your machine). In local stdio mode, pass a
> `save_path` to save to your own machine.

## Development & Testing

Install the dev extras and run the test suite:

```bash
uv pip install -e ".[dev]"   # or: pip install -e ".[dev]"
pytest
```

The suite (`tests/`) runs fully offline — network calls are faked — and covers
the security helpers (path/URL validation, filename sanitization), pagination
math, the rate limiter, error formatting, the streaming download size cap, and
the remote-vs-local download behavior (inline content / links vs save-to-disk).

For a deeper look at how the server is wired together (OAuth flow, request
lifecycle, database schema, security model), see
[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

## Troubleshooting

- **stdio client shows JSON parse errors:** ensure nothing in your environment
  writes to stdout. This server logs to stderr by design; custom forks should
  keep it that way.
- **`No DocketBird API key available`:** in stdio mode set `DOCKETBIRD_API_KEY`;
  in HTTP mode complete the OAuth login at `/signup` → connect from Claude.
- **OAuth login loops or "Invalid redirect URI":** confirm `SERVER_URL` exactly
  matches the public URL clients use (scheme + host, no trailing slash).
- **Changed your DocketBird API key but tools still fail:** use `/change-api-key`.
  It validates the new key against DocketBird and clears stale access tokens so
  the new key takes effect immediately.

## Deployment

Deployed via Docker and GitHub Actions. Pushes to `main` trigger automatic deployment.

- Domain: `app.docketbird-mcp.com`
- Docker volume: `docketbird-data` at `/app/data` (SQLite auth database)
- Health check: `https://app.docketbird-mcp.com/health` — returns
  `{"status":"ok","service":"docketbird-mcp","version":"<git-sha>"}`, where
  `version` is the deployed commit (set by the deploy workflow via `GIT_SHA`), so
  a single `curl` confirms exactly which build is live.
- Caddy reverse proxy handles HTTPS (Let's Encrypt)

### Local Docker Build

```bash
docker build -t docketbird-mcp:latest .

docker run -d \
  --name docketbird-mcp \
  --restart=always \
  -e SERVER_URL="http://localhost:8040" \
  -v docketbird-data:/app/data \
  -p 8040:8080 \
  docketbird-mcp:latest
```

## Reference Data

- `case_types.json` - Case type abbreviations and examples (no API endpoint exists for these)
- `courts.json` - Historical snapshot of court codes, frozen 2026-05-31. **No longer read by any tool** — `docketbird_list_courts` serves the live `GET /courts` endpoint.

## Acknowledgment

This project is built upon the original [docketbird-mcp](https://github.com/gravix-db/docketbird-mcp) developed in conjunction with @federicoburman and the Gravix.AI team.
