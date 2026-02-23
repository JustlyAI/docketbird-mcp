# DocketBird MCP Server

An MCP server for searching and downloading court documents via the DocketBird API. Deployed on DigitalOcean with Docker, using OAuth 2.0 so each user brings their own DocketBird API key.

## Tools

| Tool                           | Description                                     |
| ------------------------------ | ----------------------------------------------- |
| `docketbird_get_case_details`  | Get case info, parties, and paginated documents |
| `docketbird_search_documents`  | Search documents within a case by keyword       |
| `docketbird_list_cases`        | List cases for company or user scope            |
| `docketbird_list_courts`       | Get court codes and case types                  |
| `docketbird_download_document` | Download a single document by ID                |
| `docketbird_download_files`    | Download all available documents for a case     |

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
uv pip install .
```

## Running the Server

```bash
# stdio transport (uses DOCKETBIRD_API_KEY env var, no OAuth)
DOCKETBIRD_API_KEY="your-key" python docketbird_mcp.py --transport stdio

# HTTP transport with OAuth (Streamable HTTP at /mcp)
python docketbird_mcp.py --transport http
# Then visit http://localhost:8080/signup to create an account
```

## Connecting to the Deployed Server

See [installation.pdf](installation.pdf) for the full walkthrough with screenshots.

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

## Deployment

Deployed via Docker and GitHub Actions. Pushes to `main` trigger automatic deployment.

- Domain: `app.docketbird-mcp.com`
- Docker volume: `docketbird-data` at `/app/data` (SQLite auth database)
- Health check: `https://app.docketbird-mcp.com/health`
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

- `courts.json` - Court codes and names
- `case_types.json` - Case type abbreviations and examples

## Acknowledgment

This project is built upon the original [docketbird-mcp](https://github.com/gravix-db/docketbird-mcp) developed in conjunction with @federicoburman and the Gravix.AI team.
