"""OAuth Authorization Server Provider for DocketBird MCP.

Provides per-user DocketBird API keys via OAuth flow.
Users register at /signup with their DocketBird API key,
then authenticate via OAuth when connecting from Claude.ai.

Flow:
1. Claude.ai discovers OAuth via /.well-known/oauth-authorization-server
2. Claude.ai registers as a client via /register (Dynamic Client Registration)
3. Claude.ai redirects user to /authorize
4. Our provider redirects to /login?auth_session=<id>
5. User logs in, we generate auth code, redirect back to Claude.ai
6. Claude.ai exchanges code for tokens at /token
7. All subsequent MCP requests include Bearer token with user's API key
"""

import json
import os
import secrets
import time
from html import escape
from pathlib import Path
from urllib.parse import urlencode

import aiosqlite
import bcrypt
from mcp.server.auth.provider import (
    AccessToken,
    AuthorizationCode,
    AuthorizationParams,
    OAuthAuthorizationServerProvider,
    RefreshToken,
    TokenError,
)
from mcp.shared.auth import OAuthClientInformationFull, OAuthToken
from starlette.requests import Request
from starlette.responses import HTMLResponse, RedirectResponse
from termcolor import cprint

# Security headers for all HTML responses
SECURITY_HEADERS = {
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'",
    "Referrer-Policy": "strict-origin-when-cross-origin",
}

# =============================================================================
# Configuration
# =============================================================================

DATA_DIR = Path(os.getenv("DATA_DIR", "./data"))
DB_PATH = DATA_DIR / "auth.db"
SERVER_URL = os.getenv("SERVER_URL", "http://localhost:8080")

AUTH_CODE_EXPIRY = 600  # 10 minutes
ACCESS_TOKEN_EXPIRY = 3600  # 1 hour
REFRESH_TOKEN_EXPIRY = 86400 * 30  # 30 days
PENDING_AUTH_EXPIRY = 600  # 10 minutes


# =============================================================================
# Token Models (subclasses add user-specific fields)
# =============================================================================


class DocketBirdAccessToken(AccessToken):
    """Access token that carries the user's DocketBird API key.

    The SDK explicitly supports adding fields to AccessToken subclasses
    (provider.py: "OK to add fields to subclasses which should not be exposed externally").
    """

    docketbird_api_key: str
    user_id: int


class DocketBirdAuthCode(AuthorizationCode):
    """Authorization code linked to a specific user."""

    user_id: int


class DocketBirdRefreshToken(RefreshToken):
    """Refresh token linked to a specific user."""

    user_id: int


# =============================================================================
# SQLite Database Layer
# =============================================================================


class AuthDB:
    """SQLite database for OAuth users, clients, and tokens."""

    def __init__(self, db_path: Path = DB_PATH):
        self.db_path = db_path
        self._db: aiosqlite.Connection | None = None

    async def initialize(self) -> None:
        """Create database and tables."""
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        cprint(f"[AUTH] Initializing database at {self.db_path}", "yellow")
        self._db = await aiosqlite.connect(str(self.db_path))
        self._db.row_factory = aiosqlite.Row
        await self._db.execute("PRAGMA foreign_keys = ON")
        await self._db.execute("PRAGMA journal_mode = WAL")
        await self._db.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                docketbird_api_key TEXT NOT NULL,
                created_at REAL NOT NULL
            );
            CREATE TABLE IF NOT EXISTS oauth_clients (
                client_id TEXT PRIMARY KEY,
                client_info_json TEXT NOT NULL,
                created_at REAL NOT NULL
            );
            CREATE TABLE IF NOT EXISTS pending_auth (
                session_id TEXT PRIMARY KEY,
                client_id TEXT NOT NULL,
                params_json TEXT NOT NULL,
                created_at REAL NOT NULL,
                expires_at REAL NOT NULL
            );
            CREATE TABLE IF NOT EXISTS auth_codes (
                code TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL,
                client_id TEXT NOT NULL,
                scopes_json TEXT NOT NULL,
                code_challenge TEXT NOT NULL,
                redirect_uri TEXT NOT NULL,
                redirect_uri_provided_explicitly INTEGER NOT NULL,
                resource TEXT,
                expires_at REAL NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id)
            );
            CREATE TABLE IF NOT EXISTS access_tokens (
                token TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL,
                client_id TEXT NOT NULL,
                scopes_json TEXT NOT NULL,
                docketbird_api_key TEXT NOT NULL,
                resource TEXT,
                expires_at REAL,
                FOREIGN KEY (user_id) REFERENCES users(id)
            );
            CREATE TABLE IF NOT EXISTS refresh_tokens (
                token TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL,
                client_id TEXT NOT NULL,
                scopes_json TEXT NOT NULL,
                expires_at REAL,
                FOREIGN KEY (user_id) REFERENCES users(id)
            );
            """
        )
        await self._db.commit()
        cprint("[AUTH] Database initialized", "green")

    async def close(self) -> None:
        if self._db:
            await self._db.close()
            self._db = None

    # ---- Users ----

    async def create_user(self, email: str, password: str, api_key: str) -> int:
        """Create a new user. Returns user ID."""
        hashed = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
        cursor = await self._db.execute(
            "INSERT INTO users (email, password_hash, docketbird_api_key, created_at) VALUES (?, ?, ?, ?)",
            (email.lower().strip(), hashed, api_key, time.time()),
        )
        await self._db.commit()
        cprint(f"[AUTH] Created user: {email}", "green")
        return cursor.lastrowid

    async def authenticate_user(self, email: str, password: str) -> dict | None:
        """Validate email/password. Returns user dict or None."""
        cursor = await self._db.execute(
            "SELECT * FROM users WHERE email = ?",
            (email.lower().strip(),),
        )
        row = await cursor.fetchone()
        if not row:
            return None
        if not bcrypt.checkpw(password.encode("utf-8"), row["password_hash"].encode("utf-8")):
            return None
        return dict(row)

    async def get_user(self, user_id: int) -> dict | None:
        cursor = await self._db.execute("SELECT * FROM users WHERE id = ?", (user_id,))
        row = await cursor.fetchone()
        return dict(row) if row else None

    async def email_exists(self, email: str) -> bool:
        cursor = await self._db.execute(
            "SELECT 1 FROM users WHERE email = ?",
            (email.lower().strip(),),
        )
        return await cursor.fetchone() is not None

    # ---- OAuth Clients (Dynamic Client Registration) ----

    async def save_client(self, client_info: OAuthClientInformationFull) -> None:
        await self._db.execute(
            "INSERT OR REPLACE INTO oauth_clients (client_id, client_info_json, created_at) VALUES (?, ?, ?)",
            (client_info.client_id, client_info.model_dump_json(), time.time()),
        )
        await self._db.commit()
        cprint(f"[AUTH] Registered OAuth client: {client_info.client_id}", "cyan")

    async def get_client(self, client_id: str) -> OAuthClientInformationFull | None:
        cursor = await self._db.execute(
            "SELECT client_info_json FROM oauth_clients WHERE client_id = ?",
            (client_id,),
        )
        row = await cursor.fetchone()
        if not row:
            return None
        return OAuthClientInformationFull.model_validate_json(row["client_info_json"])

    # ---- Pending Auth Sessions ----

    async def create_pending_auth(self, client_id: str, params: AuthorizationParams) -> str:
        """Store OAuth authorize params while user logs in. Returns session ID."""
        session_id = secrets.token_urlsafe(32)
        now = time.time()
        await self._db.execute(
            "INSERT INTO pending_auth (session_id, client_id, params_json, created_at, expires_at) VALUES (?, ?, ?, ?, ?)",
            (session_id, client_id, params.model_dump_json(), now, now + PENDING_AUTH_EXPIRY),
        )
        await self._db.commit()
        return session_id

    async def get_pending_auth(self, session_id: str) -> dict | None:
        cursor = await self._db.execute(
            "SELECT * FROM pending_auth WHERE session_id = ? AND expires_at > ?",
            (session_id, time.time()),
        )
        row = await cursor.fetchone()
        return dict(row) if row else None

    async def delete_pending_auth(self, session_id: str) -> None:
        await self._db.execute("DELETE FROM pending_auth WHERE session_id = ?", (session_id,))
        await self._db.commit()

    # ---- Auth Codes ----

    async def save_auth_code(self, auth_code: DocketBirdAuthCode) -> None:
        await self._db.execute(
            """INSERT INTO auth_codes
            (code, user_id, client_id, scopes_json, code_challenge, redirect_uri,
             redirect_uri_provided_explicitly, resource, expires_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                auth_code.code,
                auth_code.user_id,
                auth_code.client_id,
                json.dumps(auth_code.scopes),
                auth_code.code_challenge,
                str(auth_code.redirect_uri),
                int(auth_code.redirect_uri_provided_explicitly),
                auth_code.resource,
                auth_code.expires_at,
            ),
        )
        await self._db.commit()

    async def get_auth_code(self, code: str) -> DocketBirdAuthCode | None:
        cursor = await self._db.execute(
            "SELECT * FROM auth_codes WHERE code = ? AND expires_at > ?",
            (code, time.time()),
        )
        row = await cursor.fetchone()
        if not row:
            return None
        return DocketBirdAuthCode(
            code=row["code"],
            user_id=row["user_id"],
            client_id=row["client_id"],
            scopes=json.loads(row["scopes_json"]),
            code_challenge=row["code_challenge"],
            redirect_uri=row["redirect_uri"],
            redirect_uri_provided_explicitly=bool(row["redirect_uri_provided_explicitly"]),
            resource=row["resource"],
            expires_at=row["expires_at"],
        )

    async def delete_auth_code(self, code: str) -> None:
        await self._db.execute("DELETE FROM auth_codes WHERE code = ?", (code,))
        await self._db.commit()

    # ---- Access Tokens ----

    async def save_access_token(self, token: DocketBirdAccessToken) -> None:
        await self._db.execute(
            """INSERT INTO access_tokens
            (token, user_id, client_id, scopes_json, docketbird_api_key, resource, expires_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (
                token.token,
                token.user_id,
                token.client_id,
                json.dumps(token.scopes),
                token.docketbird_api_key,
                token.resource,
                token.expires_at,
            ),
        )
        await self._db.commit()

    async def get_access_token(self, token: str) -> DocketBirdAccessToken | None:
        cursor = await self._db.execute(
            "SELECT * FROM access_tokens WHERE token = ?",
            (token,),
        )
        row = await cursor.fetchone()
        if not row:
            return None
        # Check expiry
        if row["expires_at"] and row["expires_at"] < time.time():
            await self._db.execute("DELETE FROM access_tokens WHERE token = ?", (token,))
            await self._db.commit()
            return None
        return DocketBirdAccessToken(
            token=row["token"],
            user_id=row["user_id"],
            client_id=row["client_id"],
            scopes=json.loads(row["scopes_json"]),
            docketbird_api_key=row["docketbird_api_key"],
            resource=row["resource"],
            expires_at=row["expires_at"],
        )

    # ---- Refresh Tokens ----

    async def save_refresh_token(self, token: DocketBirdRefreshToken) -> None:
        await self._db.execute(
            """INSERT INTO refresh_tokens
            (token, user_id, client_id, scopes_json, expires_at)
            VALUES (?, ?, ?, ?, ?)""",
            (
                token.token,
                token.user_id,
                token.client_id,
                json.dumps(token.scopes),
                token.expires_at,
            ),
        )
        await self._db.commit()

    async def get_refresh_token(self, token: str) -> DocketBirdRefreshToken | None:
        cursor = await self._db.execute(
            "SELECT * FROM refresh_tokens WHERE token = ?",
            (token,),
        )
        row = await cursor.fetchone()
        if not row:
            return None
        if row["expires_at"] and row["expires_at"] < time.time():
            await self._db.execute("DELETE FROM refresh_tokens WHERE token = ?", (token,))
            await self._db.commit()
            return None
        return DocketBirdRefreshToken(
            token=row["token"],
            user_id=row["user_id"],
            client_id=row["client_id"],
            scopes=json.loads(row["scopes_json"]),
            expires_at=row["expires_at"],
        )

    async def delete_refresh_token(self, token: str) -> None:
        await self._db.execute("DELETE FROM refresh_tokens WHERE token = ?", (token,))
        await self._db.commit()

    async def delete_access_token(self, token: str) -> None:
        await self._db.execute("DELETE FROM access_tokens WHERE token = ?", (token,))
        await self._db.commit()

    # ---- Cleanup ----

    async def cleanup_expired(self) -> None:
        """Remove expired records."""
        now = time.time()
        await self._db.execute("DELETE FROM pending_auth WHERE expires_at < ?", (now,))
        await self._db.execute("DELETE FROM auth_codes WHERE expires_at < ?", (now,))
        await self._db.execute("DELETE FROM access_tokens WHERE expires_at IS NOT NULL AND expires_at < ?", (now,))
        await self._db.execute("DELETE FROM refresh_tokens WHERE expires_at IS NOT NULL AND expires_at < ?", (now,))
        await self._db.commit()


# =============================================================================
# OAuth Authorization Server Provider
# =============================================================================


class DocketBirdAuthProvider:
    """Implements OAuthAuthorizationServerProvider for per-user DocketBird API keys.

    The SDK calls these methods automatically from its OAuth route handlers.
    """

    def __init__(self, db: AuthDB, server_url: str = SERVER_URL):
        self.db = db
        self.server_url = server_url.rstrip("/")

    async def get_client(self, client_id: str) -> OAuthClientInformationFull | None:
        """Look up a registered OAuth client (e.g., Claude.ai)."""
        cprint(f"[AUTH] get_client: {client_id}", "cyan")
        return await self.db.get_client(client_id)

    async def register_client(self, client_info: OAuthClientInformationFull) -> None:
        """Register a new OAuth client via Dynamic Client Registration."""
        cprint(f"[AUTH] register_client: {client_info.client_id}", "cyan")
        await self.db.save_client(client_info)

    async def authorize(
        self, client: OAuthClientInformationFull, params: AuthorizationParams
    ) -> str:
        """Handle /authorize: store params, redirect user to login page.

        Returns a URL to redirect the user-agent to (our login page).
        """
        cprint(f"[AUTH] authorize: client={client.client_id}, scopes={params.scopes}", "cyan")
        session_id = await self.db.create_pending_auth(client.client_id, params)
        login_url = f"{self.server_url}/login?auth_session={session_id}"
        cprint(f"[AUTH] Redirecting to login: {login_url}", "yellow")
        return login_url

    async def load_authorization_code(
        self, client: OAuthClientInformationFull, authorization_code: str
    ) -> DocketBirdAuthCode | None:
        """Load an auth code by its string value."""
        cprint(f"[AUTH] load_authorization_code: {authorization_code[:8]}...", "cyan")
        code = await self.db.get_auth_code(authorization_code)
        if code and code.client_id != client.client_id:
            cprint("[AUTH] Auth code client_id mismatch", "red")
            return None
        return code

    async def exchange_authorization_code(
        self, client: OAuthClientInformationFull, authorization_code: DocketBirdAuthCode
    ) -> OAuthToken:
        """Exchange auth code for access + refresh tokens.

        This is where we attach the user's DocketBird API key to the access token.
        """
        cprint(f"[AUTH] exchange_authorization_code: user_id={authorization_code.user_id}", "cyan")

        # Look up the user to get their API key
        user = await self.db.get_user(authorization_code.user_id)
        if not user:
            raise TokenError(error="invalid_grant", error_description="User not found")

        now = time.time()
        scopes = authorization_code.scopes

        # Create access token with user's DocketBird API key
        access_token = DocketBirdAccessToken(
            token=secrets.token_urlsafe(32),
            client_id=client.client_id,
            scopes=scopes,
            expires_at=int(now + ACCESS_TOKEN_EXPIRY),
            resource=authorization_code.resource,
            docketbird_api_key=user["docketbird_api_key"],
            user_id=user["id"],
        )
        await self.db.save_access_token(access_token)

        # Create refresh token
        refresh_token = DocketBirdRefreshToken(
            token=secrets.token_urlsafe(32),
            client_id=client.client_id,
            scopes=scopes,
            expires_at=int(now + REFRESH_TOKEN_EXPIRY),
            user_id=user["id"],
        )
        await self.db.save_refresh_token(refresh_token)

        # Delete the used auth code (single-use)
        await self.db.delete_auth_code(authorization_code.code)

        cprint(f"[AUTH] Issued tokens for user {user['email']}", "green")
        return OAuthToken(
            access_token=access_token.token,
            token_type="bearer",
            expires_in=ACCESS_TOKEN_EXPIRY,
            scope=" ".join(scopes),
            refresh_token=refresh_token.token,
        )

    async def load_access_token(self, token: str) -> DocketBirdAccessToken | None:
        """Load and validate an access token. Called on every authenticated request."""
        result = await self.db.get_access_token(token)
        if result:
            cprint(f"[AUTH] Valid access token for user_id={result.user_id}", "cyan")
        return result

    async def load_refresh_token(
        self, client: OAuthClientInformationFull, refresh_token: str
    ) -> DocketBirdRefreshToken | None:
        """Load a refresh token by its string value."""
        cprint(f"[AUTH] load_refresh_token: {refresh_token[:8]}...", "cyan")
        token = await self.db.get_refresh_token(refresh_token)
        if token and token.client_id != client.client_id:
            cprint("[AUTH] Refresh token client_id mismatch", "red")
            return None
        return token

    async def exchange_refresh_token(
        self,
        client: OAuthClientInformationFull,
        refresh_token: DocketBirdRefreshToken,
        scopes: list[str],
    ) -> OAuthToken:
        """Rotate refresh token: issue new access + refresh tokens."""
        cprint(f"[AUTH] exchange_refresh_token: user_id={refresh_token.user_id}", "cyan")

        user = await self.db.get_user(refresh_token.user_id)
        if not user:
            raise TokenError(error="invalid_grant", error_description="User not found")

        now = time.time()
        use_scopes = scopes if scopes else refresh_token.scopes

        # New access token
        new_access = DocketBirdAccessToken(
            token=secrets.token_urlsafe(32),
            client_id=client.client_id,
            scopes=use_scopes,
            expires_at=int(now + ACCESS_TOKEN_EXPIRY),
            docketbird_api_key=user["docketbird_api_key"],
            user_id=user["id"],
        )
        await self.db.save_access_token(new_access)

        # New refresh token (rotation)
        new_refresh = DocketBirdRefreshToken(
            token=secrets.token_urlsafe(32),
            client_id=client.client_id,
            scopes=use_scopes,
            expires_at=int(now + REFRESH_TOKEN_EXPIRY),
            user_id=user["id"],
        )
        await self.db.save_refresh_token(new_refresh)

        # Revoke old refresh token
        await self.db.delete_refresh_token(refresh_token.token)

        cprint(f"[AUTH] Rotated tokens for user {user['email']}", "green")
        return OAuthToken(
            access_token=new_access.token,
            token_type="bearer",
            expires_in=ACCESS_TOKEN_EXPIRY,
            scope=" ".join(use_scopes),
            refresh_token=new_refresh.token,
        )

    async def revoke_token(
        self,
        token: DocketBirdAccessToken | DocketBirdRefreshToken,
    ) -> None:
        """Revoke an access or refresh token."""
        cprint(f"[AUTH] revoke_token: {token.token[:8]}...", "cyan")
        if isinstance(token, DocketBirdAccessToken):
            await self.db.delete_access_token(token.token)
        else:
            await self.db.delete_refresh_token(token.token)


# =============================================================================
# HTML Templates
# =============================================================================

SIGNUP_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>DocketBird MCP - Sign Up</title>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
               background: #f5f5f5; display: flex; justify-content: center; align-items: center;
               min-height: 100vh; padding: 20px; }
        .card { background: white; border-radius: 12px; padding: 40px; max-width: 420px;
                width: 100%; box-shadow: 0 2px 8px rgba(0,0,0,0.08); }
        h1 { font-size: 24px; margin-bottom: 8px; color: #1a1a1a; }
        p.subtitle { color: #666; margin-bottom: 24px; font-size: 14px; }
        label { display: block; font-size: 14px; font-weight: 500; margin-bottom: 4px; color: #333; }
        input { width: 100%; padding: 10px 12px; border: 1px solid #ddd; border-radius: 8px;
                font-size: 14px; margin-bottom: 16px; }
        input:focus { outline: none; border-color: #4a90d9; box-shadow: 0 0 0 2px rgba(74,144,217,0.2); }
        button { width: 100%; padding: 12px; background: #1a73e8; color: white; border: none;
                 border-radius: 8px; font-size: 16px; font-weight: 500; cursor: pointer; }
        button:hover { background: #1557b0; }
        .error { background: #fef2f2; color: #dc2626; padding: 10px; border-radius: 8px;
                 margin-bottom: 16px; font-size: 14px; }
        .success { background: #f0fdf4; color: #16a34a; padding: 10px; border-radius: 8px;
                   margin-bottom: 16px; font-size: 14px; }
        .login-link { text-align: center; margin-top: 16px; font-size: 14px; color: #666; }
        .login-link a { color: #1a73e8; text-decoration: none; }
        .help { font-size: 12px; color: #999; margin-top: -12px; margin-bottom: 16px; }
    </style>
</head>
<body>
    <div class="card">
        <h1>DocketBird MCP</h1>
        <p class="subtitle">Connect your DocketBird account to use court document tools in Claude.</p>
        {message}
        <form method="POST" action="/signup">
            <label for="email">DocketBird Email</label>
            <input type="email" id="email" name="email" required placeholder="The email you use to log into DocketBird">
            <p class="help">Use the same email as your DocketBird account.</p>

            <label for="password">MCP Server Password</label>
            <input type="password" id="password" name="password" required minlength="8"
                   placeholder="Min 8 characters">
            <p class="help">Create a new password for this MCP server. This is not your DocketBird password.</p>

            <label for="api_key">DocketBird API Key</label>
            <input type="text" id="api_key" name="api_key" required placeholder="Your DocketBird API key">
            <p class="help">Find this in your DocketBird account settings.</p>

            <button type="submit">Create Account</button>
        </form>
        <p class="login-link">Already have an account? <a href="/login">Log in</a></p>
    </div>
</body>
</html>"""


def _login_html(auth_session: str = "", error: str = "") -> str:
    """Generate login page HTML with optional auth_session and error."""
    message = f'<div class="error">{escape(error)}</div>' if error else ""
    safe_session = escape(auth_session, quote=True)
    hidden = (
        f'<input type="hidden" name="auth_session" value="{safe_session}">'
        if auth_session
        else ""
    )
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>DocketBird MCP - Log In</title>
    <style>
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
               background: #f5f5f5; display: flex; justify-content: center; align-items: center;
               min-height: 100vh; padding: 20px; }}
        .card {{ background: white; border-radius: 12px; padding: 40px; max-width: 420px;
                width: 100%; box-shadow: 0 2px 8px rgba(0,0,0,0.08); }}
        h1 {{ font-size: 24px; margin-bottom: 8px; color: #1a1a1a; }}
        p.subtitle {{ color: #666; margin-bottom: 24px; font-size: 14px; }}
        label {{ display: block; font-size: 14px; font-weight: 500; margin-bottom: 4px; color: #333; }}
        input[type="email"], input[type="password"] {{
            width: 100%; padding: 10px 12px; border: 1px solid #ddd; border-radius: 8px;
            font-size: 14px; margin-bottom: 16px; }}
        input:focus {{ outline: none; border-color: #4a90d9; box-shadow: 0 0 0 2px rgba(74,144,217,0.2); }}
        button {{ width: 100%; padding: 12px; background: #1a73e8; color: white; border: none;
                 border-radius: 8px; font-size: 16px; font-weight: 500; cursor: pointer; }}
        button:hover {{ background: #1557b0; }}
        .error {{ background: #fef2f2; color: #dc2626; padding: 10px; border-radius: 8px;
                 margin-bottom: 16px; font-size: 14px; }}
        .signup-link {{ text-align: center; margin-top: 16px; font-size: 14px; color: #666; }}
        .signup-link a {{ color: #1a73e8; text-decoration: none; }}
    </style>
</head>
<body>
    <div class="card">
        <h1>DocketBird MCP</h1>
        <p class="subtitle">Log in with your MCP server credentials to connect to Claude.</p>
        {message}
        <form method="POST" action="/login">
            {hidden}
            <label for="email">DocketBird Email</label>
            <input type="email" id="email" name="email" required placeholder="The email you registered with">

            <label for="password">MCP Server Password</label>
            <input type="password" id="password" name="password" required
                   placeholder="The password you created during signup">

            <button type="submit">Log In</button>
        </form>
        <p class="signup-link">No account? <a href="/signup">Sign up</a></p>
    </div>
</body>
</html>"""


# =============================================================================
# HTTP Route Handlers (called from ASGI wrapper in docketbird_mcp.py)
# =============================================================================


def _signup_response(message: str = "", status_code: int = 200) -> HTMLResponse:
    """Create a signup HTML response with security headers."""
    return HTMLResponse(
        SIGNUP_HTML.replace("{message}", message),
        status_code=status_code,
        headers=SECURITY_HEADERS,
    )


async def handle_signup(request: Request, db: AuthDB) -> HTMLResponse | RedirectResponse:
    """Handle GET /signup (show form) and POST /signup (create user)."""
    if request.method == "GET":
        return _signup_response()

    # POST: process form
    form = await request.form()
    email = str(form.get("email", "")).strip()
    password = str(form.get("password", ""))
    api_key = str(form.get("api_key", "")).strip()

    # Validate (all error messages are hardcoded strings, no user input interpolated)
    if not email or not password or not api_key:
        return _signup_response('<div class="error">All fields are required.</div>', 400)
    if len(password) < 8:
        return _signup_response('<div class="error">Password must be at least 8 characters.</div>', 400)
    if await db.email_exists(email):
        return _signup_response('<div class="error">An account with this email already exists.</div>', 409)

    try:
        await db.create_user(email, password, api_key)
        return _signup_response('<div class="success">Account created. You can now connect DocketBird in Claude.</div>')
    except Exception as e:
        cprint(f"[AUTH] Signup error: {e}", "red")
        return _signup_response('<div class="error">Something went wrong. Please try again.</div>', 500)


async def handle_login(request: Request, db: AuthDB) -> HTMLResponse | RedirectResponse:
    """Handle GET /login (show form) and POST /login (authenticate + redirect).

    During OAuth flow, auth_session param links back to the pending authorize request.
    """
    if request.method == "GET":
        auth_session = request.query_params.get("auth_session", "")
        return HTMLResponse(_login_html(auth_session=auth_session), headers=SECURITY_HEADERS)

    # POST: authenticate
    form = await request.form()
    email = str(form.get("email", "")).strip()
    password = str(form.get("password", ""))
    auth_session = str(form.get("auth_session", ""))

    user = await db.authenticate_user(email, password)
    if not user:
        return HTMLResponse(
            _login_html(auth_session=auth_session, error="Invalid email or password."),
            status_code=401,
            headers=SECURITY_HEADERS,
        )

    # If no auth_session, this is a standalone login (not OAuth flow)
    if not auth_session:
        return HTMLResponse(
            _login_html(error="Login successful, but no OAuth session. Please connect via Claude."),
            headers=SECURITY_HEADERS,
        )

    # Load the pending auth session
    pending = await db.get_pending_auth(auth_session)
    if not pending:
        return HTMLResponse(
            _login_html(error="Auth session expired or invalid. Please try connecting from Claude again."),
            status_code=400,
            headers=SECURITY_HEADERS,
        )

    # Parse the original authorization params
    params = AuthorizationParams.model_validate_json(pending["params_json"])

    # Validate redirect_uri against registered client's allowed URIs
    client = await db.get_client(pending["client_id"])
    if not client:
        return HTMLResponse(
            _login_html(error="OAuth client not found. Please try connecting from Claude again."),
            status_code=400,
            headers=SECURITY_HEADERS,
        )
    if client.redirect_uris and str(params.redirect_uri) not in [str(u) for u in client.redirect_uris]:
        cprint(f"[AUTH] Redirect URI mismatch: {params.redirect_uri}", "red")
        return HTMLResponse(
            _login_html(error="Invalid redirect URI. Please try connecting from Claude again."),
            status_code=400,
            headers=SECURITY_HEADERS,
        )

    # Generate authorization code linked to this user
    auth_code = DocketBirdAuthCode(
        code=secrets.token_urlsafe(32),
        user_id=user["id"],
        client_id=pending["client_id"],
        scopes=params.scopes or ["docketbird"],
        code_challenge=params.code_challenge,
        redirect_uri=params.redirect_uri,
        redirect_uri_provided_explicitly=params.redirect_uri_provided_explicitly,
        resource=params.resource,
        expires_at=time.time() + AUTH_CODE_EXPIRY,
    )
    await db.save_auth_code(auth_code)

    # Clean up the pending auth
    await db.delete_pending_auth(auth_session)

    # Redirect back to the OAuth client (Claude.ai) with the auth code
    redirect_params = {"code": auth_code.code}
    if params.state:
        redirect_params["state"] = params.state

    redirect_url = f"{params.redirect_uri}?{urlencode(redirect_params)}"
    cprint(f"[AUTH] Login success for {email}, redirecting to OAuth client", "green")
    return RedirectResponse(url=redirect_url, status_code=302)
