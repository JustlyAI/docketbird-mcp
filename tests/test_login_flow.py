"""Tests for the OAuth login flow (`handle_login`) and the duplicate-signup
race in `handle_signup`.

This is the most security-critical path in the repo: redirect-URI allowlist
enforcement, single-use pending sessions, and code issuance. It previously had
zero test coverage. Also covers the atomic code/refresh-token consumption
added alongside it (replay must raise TokenError, not mint a second pair).
"""

import time
from urllib.parse import urlencode

import pytest
from mcp.server.auth.provider import AuthorizationParams, TokenError
from mcp.shared.auth import OAuthClientInformationFull
from starlette.requests import Request

from auth_provider import DocketBirdAuthProvider, handle_login, handle_signup

pytestmark = pytest.mark.asyncio

REDIRECT_URI = "https://claude.ai/cb"


def _post_request(path: str, form: dict) -> Request:
    body = urlencode(form).encode("utf-8")
    scope = {
        "type": "http",
        "method": "POST",
        "path": path,
        "headers": [
            (b"content-type", b"application/x-www-form-urlencoded"),
            (b"content-length", str(len(body)).encode("utf-8")),
        ],
        "query_string": b"",
    }

    async def receive():
        return {"type": "http.request", "body": body, "more_body": False}

    return Request(scope, receive)


def _body(response) -> str:
    return response.body.decode("utf-8")


async def _seed(auth_db, redirect_uri=REDIRECT_URI):
    await auth_db.create_user("u@x.com", "password123", "key")
    client = OAuthClientInformationFull(
        client_id="c1",
        redirect_uris=[redirect_uri],
        token_endpoint_auth_method="none",
    )
    await auth_db.save_client(client)
    params = AuthorizationParams(
        state="xyz",
        scopes=["docketbird"],
        code_challenge="challenge123",
        redirect_uri=redirect_uri,
        redirect_uri_provided_explicitly=True,
        resource="https://app.docketbird-mcp.com/mcp",
    )
    session_id = await auth_db.create_pending_auth("c1", params)
    return session_id


async def _code_count(auth_db) -> int:
    cursor = await auth_db._db.execute("SELECT COUNT(*) as n FROM auth_codes")
    row = await cursor.fetchone()
    return row["n"]


# ---------------------------------------------------------------------------
# handle_login
# ---------------------------------------------------------------------------


async def test_happy_path_redirects_with_code(auth_db):
    session_id = await _seed(auth_db)
    resp = await handle_login(
        _post_request("/login", {"email": "u@x.com", "password": "password123", "auth_session": session_id}),
        auth_db,
    )
    assert resp.status_code == 302
    location = resp.headers["location"]
    assert "code=" in location
    assert location.startswith(REDIRECT_URI)


async def test_wrong_password_401_no_code_created(auth_db):
    session_id = await _seed(auth_db)
    resp = await handle_login(
        _post_request("/login", {"email": "u@x.com", "password": "wrong", "auth_session": session_id}),
        auth_db,
    )
    assert resp.status_code == 401
    assert await _code_count(auth_db) == 0


async def test_redirect_uri_mismatch_400_no_code_created(auth_db):
    """The single most important test here: a pending session whose params
    carry a redirect_uri NOT in the client's registered list must be rejected
    rather than redirected to (open-redirect regression lock)."""
    # Seed with a pending session pointing to an unregistered redirect_uri.
    await auth_db.create_user("u@x.com", "password123", "key")
    client = OAuthClientInformationFull(
        client_id="c1",
        redirect_uris=[REDIRECT_URI],
        token_endpoint_auth_method="none",
    )
    await auth_db.save_client(client)
    params = AuthorizationParams(
        state="xyz",
        scopes=["docketbird"],
        code_challenge="challenge123",
        redirect_uri="https://evil.example.com/steal",
        redirect_uri_provided_explicitly=True,
        resource=None,
    )
    session_id = await auth_db.create_pending_auth("c1", params)

    resp = await handle_login(
        _post_request("/login", {"email": "u@x.com", "password": "password123", "auth_session": session_id}),
        auth_db,
    )
    assert resp.status_code == 400
    assert "Invalid redirect URI" in _body(resp)
    assert await _code_count(auth_db) == 0


async def test_session_is_single_use(auth_db):
    session_id = await _seed(auth_db)
    resp1 = await handle_login(
        _post_request("/login", {"email": "u@x.com", "password": "password123", "auth_session": session_id}),
        auth_db,
    )
    assert resp1.status_code == 302
    assert await _code_count(auth_db) == 1

    resp2 = await handle_login(
        _post_request("/login", {"email": "u@x.com", "password": "password123", "auth_session": session_id}),
        auth_db,
    )
    assert "already completed" in _body(resp2)
    assert await _code_count(auth_db) == 1


# ---------------------------------------------------------------------------
# handle_signup: duplicate-signup race
# ---------------------------------------------------------------------------


async def test_duplicate_signup_race_returns_409_not_500(auth_db, monkeypatch):
    """Bypass the fast-path email_exists pre-check so the second POST hits the
    UNIQUE constraint directly, exercising the IntegrityError -> 409 path."""
    monkeypatch.setattr(auth_db, "email_exists", lambda email: _false())

    resp1 = await handle_signup(
        _post_request("/signup", {"email": "dup@x.com", "password": "password123", "api_key": "k"}), auth_db
    )
    assert resp1.status_code == 200

    resp2 = await handle_signup(
        _post_request("/signup", {"email": "dup@x.com", "password": "password123", "api_key": "k"}), auth_db
    )
    assert resp2.status_code == 409
    assert "already exists" in _body(resp2)


async def _false():
    return False


# ---------------------------------------------------------------------------
# Atomic consume: replay must fail closed
# ---------------------------------------------------------------------------


async def test_replayed_auth_code_raises_token_error(auth_db):
    provider = DocketBirdAuthProvider(auth_db, server_url="https://app.docketbird-mcp.com")
    from auth_provider import DocketBirdAuthCode

    uid = await auth_db.create_user("r@x.com", "password123", "key")
    client = OAuthClientInformationFull(
        client_id="c1", redirect_uris=[REDIRECT_URI], token_endpoint_auth_method="none"
    )
    auth_code = DocketBirdAuthCode(
        code="code-1",
        user_id=uid,
        client_id="c1",
        scopes=["docketbird"],
        code_challenge="challenge123",
        redirect_uri=REDIRECT_URI,
        redirect_uri_provided_explicitly=True,
        resource=None,
        expires_at=time.time() + 600,
    )
    await auth_db.save_auth_code(auth_code)

    await provider.exchange_authorization_code(client, auth_code)
    with pytest.raises(TokenError):
        await provider.exchange_authorization_code(client, auth_code)


async def test_replayed_refresh_token_raises_token_error(auth_db):
    from auth_provider import DocketBirdRefreshToken

    provider = DocketBirdAuthProvider(auth_db, server_url="https://app.docketbird-mcp.com")
    uid = await auth_db.create_user("r2@x.com", "password123", "key")
    client = OAuthClientInformationFull(
        client_id="c1", redirect_uris=[REDIRECT_URI], token_endpoint_auth_method="none"
    )
    refresh_token = DocketBirdRefreshToken(
        token="ref-1",
        client_id="c1",
        scopes=["docketbird"],
        expires_at=int(time.time() + 86400),
        user_id=uid,
    )
    await auth_db.save_refresh_token(refresh_token)

    await provider.exchange_refresh_token(client, refresh_token, scopes=[])
    with pytest.raises(TokenError):
        await provider.exchange_refresh_token(client, refresh_token, scopes=[])
