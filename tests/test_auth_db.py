"""Tests for the AuthDB SQLite layer in auth_provider.py.

Covers user CRUD + bcrypt password handling, OAuth client persistence,
pending-auth sessions, auth codes, access/refresh tokens, expiry handling,
and the cleanup sweep. Uses an isolated temp DB per test (auth_db fixture).
"""

import time

import pytest

from auth_provider import (
    AUTH_CODE_EXPIRY,
    DocketBirdAccessToken,
    DocketBirdAuthCode,
    DocketBirdRefreshToken,
)
from mcp.server.auth.provider import AuthorizationParams
from mcp.shared.auth import OAuthClientInformationFull

pytestmark = pytest.mark.asyncio


# ---------------------------------------------------------------------------
# Users + password hashing
# ---------------------------------------------------------------------------


async def test_create_and_authenticate_user(auth_db):
    uid = await auth_db.create_user("Test@Example.com", "password123", "db-key-1")
    assert isinstance(uid, int)

    user = await auth_db.authenticate_user("test@example.com", "password123")
    assert user is not None
    assert user["id"] == uid
    assert user["docketbird_api_key"] == "db-key-1"


async def test_password_is_hashed_not_plaintext(auth_db):
    await auth_db.create_user("h@example.com", "supersecret", "k")
    user = await auth_db.get_user(1)
    assert user["password_hash"] != "supersecret"
    assert user["password_hash"].startswith("$2")  # bcrypt prefix


async def test_authenticate_wrong_password_returns_none(auth_db):
    await auth_db.create_user("w@example.com", "rightpass", "k")
    assert await auth_db.authenticate_user("w@example.com", "wrongpass") is None


async def test_authenticate_unknown_email_returns_none(auth_db):
    assert await auth_db.authenticate_user("nobody@example.com", "x") is None


async def test_email_is_normalized_lowercase(auth_db):
    await auth_db.create_user("MixedCase@Example.COM", "password123", "k")
    # Lookup with different casing/whitespace still matches
    assert await auth_db.email_exists("  mixedcase@example.com ") is True


async def test_email_exists_false_for_unknown(auth_db):
    assert await auth_db.email_exists("ghost@example.com") is False


async def test_update_password(auth_db):
    uid = await auth_db.create_user("p@example.com", "oldpassword", "k")
    await auth_db.update_password(uid, "newpassword123")
    assert await auth_db.authenticate_user("p@example.com", "oldpassword") is None
    assert await auth_db.authenticate_user("p@example.com", "newpassword123") is not None


async def test_update_api_key(auth_db):
    uid = await auth_db.create_user("k@example.com", "password123", "old-key")
    await auth_db.update_api_key(uid, "new-key")
    user = await auth_db.get_user(uid)
    assert user["docketbird_api_key"] == "new-key"


# ---------------------------------------------------------------------------
# OAuth clients
# ---------------------------------------------------------------------------


def _client(client_id="client-abc"):
    return OAuthClientInformationFull(
        client_id=client_id,
        redirect_uris=["https://claude.ai/api/mcp/auth_callback"],
        token_endpoint_auth_method="none",
    )


async def test_save_and_get_client(auth_db):
    client = _client()
    await auth_db.save_client(client)
    loaded = await auth_db.get_client("client-abc")
    assert loaded is not None
    assert loaded.client_id == "client-abc"
    assert str(loaded.redirect_uris[0]) == "https://claude.ai/api/mcp/auth_callback"


async def test_get_unknown_client_returns_none(auth_db):
    assert await auth_db.get_client("does-not-exist") is None


# ---------------------------------------------------------------------------
# Pending auth sessions
# ---------------------------------------------------------------------------


def _auth_params():
    return AuthorizationParams(
        state="xyz",
        scopes=["docketbird"],
        code_challenge="challenge123",
        redirect_uri="https://claude.ai/api/mcp/auth_callback",
        redirect_uri_provided_explicitly=True,
        resource="https://app.docketbird-mcp.com/mcp",
    )


async def test_pending_auth_roundtrip(auth_db):
    session_id = await auth_db.create_pending_auth("client-abc", _auth_params())
    assert session_id
    pending = await auth_db.get_pending_auth(session_id)
    assert pending is not None
    assert pending["client_id"] == "client-abc"


async def test_pending_auth_delete(auth_db):
    session_id = await auth_db.create_pending_auth("client-abc", _auth_params())
    await auth_db.delete_pending_auth(session_id)
    assert await auth_db.get_pending_auth(session_id) is None


# ---------------------------------------------------------------------------
# Auth codes
# ---------------------------------------------------------------------------


def _auth_code(code="code-1", user_id=1, expires_at=None):
    return DocketBirdAuthCode(
        code=code,
        user_id=user_id,
        client_id="client-abc",
        scopes=["docketbird"],
        code_challenge="challenge123",
        redirect_uri="https://claude.ai/api/mcp/auth_callback",
        redirect_uri_provided_explicitly=True,
        resource="https://app.docketbird-mcp.com/mcp",
        expires_at=expires_at if expires_at is not None else time.time() + AUTH_CODE_EXPIRY,
    )


async def test_auth_code_roundtrip(auth_db):
    await auth_db.create_user("a@example.com", "password123", "k")
    await auth_db.save_auth_code(_auth_code())
    loaded = await auth_db.get_auth_code("code-1")
    assert loaded is not None
    assert loaded.user_id == 1
    assert loaded.scopes == ["docketbird"]


async def test_expired_auth_code_not_returned(auth_db):
    await auth_db.create_user("a@example.com", "password123", "k")
    await auth_db.save_auth_code(_auth_code(expires_at=time.time() - 1))
    assert await auth_db.get_auth_code("code-1") is None


async def test_auth_code_single_use_delete(auth_db):
    await auth_db.create_user("a@example.com", "password123", "k")
    await auth_db.save_auth_code(_auth_code())
    await auth_db.delete_auth_code("code-1")
    assert await auth_db.get_auth_code("code-1") is None


# ---------------------------------------------------------------------------
# Access + refresh tokens
# ---------------------------------------------------------------------------


def _access_token(token="acc-1", expires_at=None):
    return DocketBirdAccessToken(
        token=token,
        client_id="client-abc",
        scopes=["docketbird"],
        expires_at=int(expires_at if expires_at is not None else time.time() + 3600),
        resource="https://app.docketbird-mcp.com/mcp",
        docketbird_api_key="user-db-key",
        user_id=1,
    )


async def test_access_token_carries_api_key(auth_db):
    await auth_db.create_user("a@example.com", "password123", "k")  # satisfy FK
    await auth_db.save_access_token(_access_token())
    loaded = await auth_db.get_access_token("acc-1")
    assert loaded is not None
    assert loaded.docketbird_api_key == "user-db-key"
    assert loaded.user_id == 1


async def test_expired_access_token_purged_on_read(auth_db):
    await auth_db.create_user("a@example.com", "password123", "k")  # satisfy FK
    await auth_db.save_access_token(_access_token(expires_at=time.time() - 1))
    assert await auth_db.get_access_token("acc-1") is None
    # Confirm it was actually deleted, not just filtered
    cursor = await auth_db._db.execute("SELECT 1 FROM access_tokens WHERE token = ?", ("acc-1",))
    assert await cursor.fetchone() is None


async def test_refresh_token_roundtrip_and_delete(auth_db):
    await auth_db.create_user("a@example.com", "password123", "k")  # satisfy FK
    rt = DocketBirdRefreshToken(
        token="ref-1",
        client_id="client-abc",
        scopes=["docketbird"],
        expires_at=int(time.time() + 86400),
        user_id=1,
    )
    await auth_db.save_refresh_token(rt)
    assert (await auth_db.get_refresh_token("ref-1")) is not None
    await auth_db.delete_refresh_token("ref-1")
    assert await auth_db.get_refresh_token("ref-1") is None


async def test_delete_access_tokens_for_user_keeps_refresh(auth_db):
    await auth_db.create_user("a@example.com", "password123", "k")  # user_id=1
    await auth_db.save_access_token(_access_token(token="acc-1"))
    await auth_db.save_access_token(_access_token(token="acc-2"))
    rt = DocketBirdRefreshToken(
        token="ref-1",
        client_id="client-abc",
        scopes=["docketbird"],
        expires_at=int(time.time() + 86400),
        user_id=1,
    )
    await auth_db.save_refresh_token(rt)

    removed = await auth_db.delete_access_tokens_for_user(1)
    assert removed == 2
    assert await auth_db.get_access_token("acc-1") is None
    assert await auth_db.get_access_token("acc-2") is None
    # Refresh token is intentionally kept so the client re-syncs seamlessly
    assert await auth_db.get_refresh_token("ref-1") is not None


# ---------------------------------------------------------------------------
# Cleanup sweep
# ---------------------------------------------------------------------------


async def test_cleanup_expired_removes_only_stale(auth_db):
    await auth_db.create_user("a@example.com", "password123", "k")
    await auth_db.save_auth_code(_auth_code(code="fresh", expires_at=time.time() + 600))
    await auth_db.save_auth_code(_auth_code(code="stale", expires_at=time.time() - 600))

    await auth_db.cleanup_expired()

    assert await auth_db.get_auth_code("fresh") is not None
    # get_auth_code already filters by expiry, so query the row directly
    cursor = await auth_db._db.execute("SELECT 1 FROM auth_codes WHERE code = ?", ("stale",))
    assert await cursor.fetchone() is None
