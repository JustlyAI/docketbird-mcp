"""Tests for DocketBirdAuthProvider - the OAuth server provider logic.

Covers client registration, the authorize->login redirect, auth-code exchange
(which attaches the user's DocketBird key to the access token), refresh-token
rotation, cross-client guards, and revocation.
"""

import time

import pytest

from auth_provider import (
    ACCESS_TOKEN_EXPIRY,
    DocketBirdAccessToken,
    DocketBirdAuthCode,
    DocketBirdAuthProvider,
    DocketBirdRefreshToken,
)
from mcp.server.auth.provider import AuthorizationParams, TokenError
from mcp.shared.auth import OAuthClientInformationFull

pytestmark = pytest.mark.asyncio


def _client(client_id="client-abc"):
    return OAuthClientInformationFull(
        client_id=client_id,
        redirect_uris=["https://claude.ai/api/mcp/auth_callback"],
        token_endpoint_auth_method="none",
    )


def _params():
    return AuthorizationParams(
        state="xyz",
        scopes=["docketbird"],
        code_challenge="challenge123",
        redirect_uri="https://claude.ai/api/mcp/auth_callback",
        redirect_uri_provided_explicitly=True,
        resource="https://app.docketbird-mcp.com/mcp",
    )


@pytest.fixture
def provider(auth_db):
    return DocketBirdAuthProvider(auth_db, server_url="https://app.docketbird-mcp.com")


# ---------------------------------------------------------------------------
# Client registration + authorize
# ---------------------------------------------------------------------------


async def test_register_and_get_client(provider):
    await provider.register_client(_client())
    loaded = await provider.get_client("client-abc")
    assert loaded is not None
    assert loaded.client_id == "client-abc"


async def test_authorize_returns_login_url_with_session(provider, auth_db):
    url = await provider.authorize(_client(), _params())
    assert url.startswith("https://app.docketbird-mcp.com/login?auth_session=")
    session_id = url.split("auth_session=")[1]
    # The pending auth must have been persisted under that session id
    assert await auth_db.get_pending_auth(session_id) is not None


# ---------------------------------------------------------------------------
# Authorization code loading + client guard
# ---------------------------------------------------------------------------


async def _seed_user_and_code(auth_db, code="code-1", client_id="client-abc"):
    uid = await auth_db.create_user("u@example.com", "password123", "user-db-key")
    auth_code = DocketBirdAuthCode(
        code=code,
        user_id=uid,
        client_id=client_id,
        scopes=["docketbird"],
        code_challenge="challenge123",
        redirect_uri="https://claude.ai/api/mcp/auth_callback",
        redirect_uri_provided_explicitly=True,
        resource="https://app.docketbird-mcp.com/mcp",
        expires_at=time.time() + 600,
    )
    await auth_db.save_auth_code(auth_code)
    return uid, auth_code


async def test_load_authorization_code_rejects_wrong_client(provider, auth_db):
    await _seed_user_and_code(auth_db, client_id="client-abc")
    # A different client must not be able to load someone else's code
    other = _client(client_id="client-evil")
    assert await provider.load_authorization_code(other, "code-1") is None


async def test_load_authorization_code_ok_for_matching_client(provider, auth_db):
    await _seed_user_and_code(auth_db)
    loaded = await provider.load_authorization_code(_client(), "code-1")
    assert loaded is not None
    assert loaded.code == "code-1"


# ---------------------------------------------------------------------------
# exchange_authorization_code: the key-attaching step
# ---------------------------------------------------------------------------


async def test_exchange_code_attaches_user_api_key(provider, auth_db):
    _, auth_code = await _seed_user_and_code(auth_db)
    token = await provider.exchange_authorization_code(_client(), auth_code)

    assert token.access_token
    assert token.refresh_token
    assert token.expires_in == ACCESS_TOKEN_EXPIRY

    # The issued access token must carry this user's DocketBird key
    stored = await auth_db.get_access_token(token.access_token)
    assert stored.docketbird_api_key == "user-db-key"


async def test_exchange_code_is_single_use(provider, auth_db):
    _, auth_code = await _seed_user_and_code(auth_db)
    await provider.exchange_authorization_code(_client(), auth_code)
    # Code must be consumed after exchange
    assert await auth_db.get_auth_code("code-1") is None


async def test_exchange_code_unknown_user_raises(provider, auth_db):
    # Auth code referencing a non-existent user id
    orphan = DocketBirdAuthCode(
        code="orphan",
        user_id=99999,
        client_id="client-abc",
        scopes=["docketbird"],
        code_challenge="c",
        redirect_uri="https://claude.ai/api/mcp/auth_callback",
        redirect_uri_provided_explicitly=True,
        resource=None,
        expires_at=time.time() + 600,
    )
    with pytest.raises(TokenError):
        await provider.exchange_authorization_code(_client(), orphan)


# ---------------------------------------------------------------------------
# Refresh token rotation
# ---------------------------------------------------------------------------


async def test_exchange_refresh_token_rotates(provider, auth_db):
    uid = await auth_db.create_user("r@example.com", "password123", "user-db-key")
    old_refresh = DocketBirdRefreshToken(
        token="old-refresh",
        client_id="client-abc",
        scopes=["docketbird"],
        expires_at=int(time.time() + 86400),
        user_id=uid,
    )
    await auth_db.save_refresh_token(old_refresh)

    new_token = await provider.exchange_refresh_token(_client(), old_refresh, scopes=[])

    # New tokens issued
    assert new_token.access_token
    assert new_token.refresh_token != "old-refresh"
    # Old refresh token revoked (rotation)
    assert await auth_db.get_refresh_token("old-refresh") is None
    # New access token carries the user's key
    stored = await auth_db.get_access_token(new_token.access_token)
    assert stored.docketbird_api_key == "user-db-key"


async def test_load_refresh_token_rejects_wrong_client(provider, auth_db):
    uid = await auth_db.create_user("r@example.com", "password123", "k")
    await auth_db.save_refresh_token(
        DocketBirdRefreshToken(
            token="ref-x",
            client_id="client-abc",
            scopes=["docketbird"],
            expires_at=int(time.time() + 86400),
            user_id=uid,
        )
    )
    other = _client(client_id="client-evil")
    assert await provider.load_refresh_token(other, "ref-x") is None


# ---------------------------------------------------------------------------
# Revocation
# ---------------------------------------------------------------------------


async def test_revoke_access_token(provider, auth_db):
    await auth_db.create_user("u@example.com", "password123", "k")  # satisfy FK
    token = DocketBirdAccessToken(
        token="acc-x",
        client_id="client-abc",
        scopes=["docketbird"],
        expires_at=int(time.time() + 3600),
        resource=None,
        docketbird_api_key="k",
        user_id=1,
    )
    await auth_db.save_access_token(token)
    await provider.revoke_token(token)
    assert await auth_db.get_access_token("acc-x") is None


async def test_revoke_refresh_token(provider, auth_db):
    await auth_db.create_user("u@example.com", "password123", "k")  # satisfy FK
    token = DocketBirdRefreshToken(
        token="ref-revoke",
        client_id="client-abc",
        scopes=["docketbird"],
        expires_at=int(time.time() + 86400),
        user_id=1,
    )
    await auth_db.save_refresh_token(token)
    await provider.revoke_token(token)
    assert await auth_db.get_refresh_token("ref-revoke") is None
