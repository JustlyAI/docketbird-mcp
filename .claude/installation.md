# Connecting DocketBird MCP to Claude

This guide walks you through connecting the DocketBird MCP server to your Claude account so you can search and download federal court documents directly from Claude.

## Prerequisites

- A [DocketBird](https://www.docketbird.com) account with an API key
- A Claude account (Claude.ai or Claude Desktop)

## Step 1: Create Your MCP Server Account

Before Claude can connect, you need to register your DocketBird API key with the MCP server.

1. Go to **[https://docketbird-mcp.com/signup](https://docketbird-mcp.com/signup)**
2. Fill in the three fields:
   - **DocketBird Email** - The email you use to log into DocketBird
   - **MCP Server Password** - Create a new password (8+ characters). This is separate from your DocketBird password.
   - **DocketBird API Key** - Your API key from DocketBird account settings
3. Click **Create Account**

![Signup page](docs/screenshots/signup.png)

You should see a green confirmation message: "Account created. You can now connect DocketBird in Claude."

## Step 2: Add the MCP Server in Claude

### Claude.ai (Web)

1. Open [claude.ai](https://claude.ai)
2. Click the **Settings** icon (gear icon at the bottom-left)
3. Go to **Integrations** (or **Connected MCP Servers**)
4. Click **Add Integration** (or **Add MCP Server**)
5. Enter the server URL: `https://docketbird-mcp.com/mcp`
6. Click **Connect** (or **Add**)

### Claude Desktop

1. Open Claude Desktop
2. Open **Settings** > **Developer** > **MCP Servers**
3. Click **Add Remote MCP Server**
4. Enter a name (e.g., "DocketBird") and the URL: `https://docketbird-mcp.com/mcp`
5. Click **Add**

## Step 3: Authenticate via OAuth

After adding the server, Claude will prompt you to log in. Here's what happens behind the scenes:

1. **Discovery** - Claude fetches `/.well-known/oauth-authorization-server` from the server to discover OAuth endpoints
2. **Client Registration** - Claude registers itself as an OAuth client via `/register` (one-time, using Dynamic Client Registration)
3. **Login Redirect** - Claude opens a browser window to the DocketBird MCP login page

When the login page appears:

1. Enter your **DocketBird Email** and **MCP Server Password** (the password you created in Step 1, not your DocketBird password)
2. Click **Log In**

![Login page](docs/screenshots/login.png)

4. **Token Exchange** - After login, the server generates an authorization code and redirects back to Claude. Claude exchanges this code for an access token.
5. **Connected** - Claude now has a token linked to your DocketBird API key. All tool calls will use your personal key.

## Step 4: Start Using the Tools

Once connected, you can ask Claude to work with court documents. Try these:

- "List my tracked cases"
- "Get details for case txnd-3:2007-cv-01697"
- "Search for motions to dismiss in that case"
- "Download the complaint filing"
- "What courts are available?"

Claude has access to six tools:

| Tool | What it does |
|------|-------------|
| `docketbird_get_case_details` | Get case info, parties, and documents |
| `docketbird_search_documents` | Search documents within a case by keyword |
| `docketbird_list_cases` | List your tracked cases |
| `docketbird_list_courts` | Look up court codes and case types |
| `docketbird_download_document` | Download a single document |
| `docketbird_download_files` | Download all documents for a case |

## How Authentication Works

The DocketBird MCP server uses **OAuth 2.0 with PKCE** to securely connect your DocketBird API key to Claude without exposing it.

```
┌─────────┐         ┌──────────────────┐         ┌──────────────┐
│  Claude  │         │  DocketBird MCP  │         │ DocketBird   │
│  (User)  │         │  Server          │         │ API          │
└────┬─────┘         └────────┬─────────┘         └──────┬───────┘
     │  1. Add server URL      │                          │
     │────────────────────────>│                          │
     │  2. Discover OAuth      │                          │
     │────────────────────────>│                          │
     │  3. Login page          │                          │
     │<────────────────────────│                          │
     │  4. Email + password    │                          │
     │────────────────────────>│                          │
     │  5. Access token        │                          │
     │<────────────────────────│                          │
     │  6. Tool call + token   │                          │
     │────────────────────────>│  7. API call with        │
     │                         │     user's API key       │
     │                         │─────────────────────────>│
     │                         │  8. Results              │
     │                         │<─────────────────────────│
     │  9. Results to user     │                          │
     │<────────────────────────│                          │
```

Key points:

- **Your API key never leaves the server.** Claude only receives an OAuth token. The server maps that token to your API key on each request.
- **Tokens expire.** Access tokens last 1 hour. Claude automatically refreshes them using a refresh token (valid for 30 days).
- **Your password is hashed.** Stored with bcrypt, never in plain text.
- **Each user has their own key.** There is no shared API key on the server.

## Troubleshooting

### "Invalid email or password" on login

You need to use the password you created during signup (Step 1), not your DocketBird account password. These are separate credentials.

### "Auth session expired"

The OAuth session timed out (10-minute window). Go back to Claude and re-initiate the connection. Claude will redirect you to a fresh login page.

### "Rate limit exceeded"

The server limits requests to 30 per minute per IP. Wait a minute and try again.

### Token expired / "Not authenticated"

Access tokens expire after 1 hour. Claude should refresh them automatically. If you're stuck, disconnect and reconnect the MCP server in Claude settings.

### Connection issues

Check that the server is healthy: visit [https://docketbird-mcp.com/health](https://docketbird-mcp.com/health). You should see `{"status": "ok", "service": "docketbird-mcp"}`.

## Adding Screenshots

To add the referenced screenshots, capture the signup and login pages and save them to:

```
docs/screenshots/signup.png
docs/screenshots/login.png
```
