"""Tests for the /change-password route handler in auth_provider.py.

Covers the security-relevant behavior added alongside token hashing: a
password change must revoke existing sessions (both access and refresh
tokens), matching the existing handle_change_api_key behavior. Drives
handle_change_password directly with a synthetic Starlette Request, mirroring
the pattern in test_change_api_key.py. Uses the isolated temp DB (auth_db
fixture from conftest).
"""

import time
from urllib.parse import urlencode

import pytest
from starlette.requests import Request

from auth_provider import DocketBirdAccessToken, DocketBirdRefreshToken, handle_change_password

pytestmark = pytest.mark.asyncio


# ---- Request builders (mirrors test_change_api_key.py) ----


def _get_request() -> Request:
    scope = {
        "type": "http",
        "method": "GET",
        "path": "/change-password",
        "headers": [],
        "query_string": b"",
    }

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    return Request(scope, receive)


def _post_request(form: dict) -> Request:
    body = urlencode(form).encode("utf-8")
    scope = {
        "type": "http",
        "method": "POST",
        "path": "/change-password",
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


# ---- Tests ----


async def test_get_shows_form(auth_db):
    resp = await handle_change_password(_get_request(), auth_db)
    assert resp.status_code == 200
    html = _body(resp)
    assert "Change Password" in html
    assert 'action="/change-password"' in html


async def test_valid_change_revokes_access_and_refresh_tokens(auth_db):
    uid = await auth_db.create_user("u@example.com", "password123", "k")  # user_id=1
    await auth_db.save_access_token(
        DocketBirdAccessToken(
            token="acc-1",
            client_id="client-abc",
            scopes=["docketbird"],
            expires_at=int(time.time() + 3600),
            resource="https://app.docketbird-mcp.com/mcp",
            docketbird_api_key="k",
            user_id=uid,
        )
    )
    await auth_db.save_refresh_token(
        DocketBirdRefreshToken(
            token="ref-1",
            client_id="client-abc",
            scopes=["docketbird"],
            expires_at=int(time.time() + 86400),
            user_id=uid,
        )
    )

    resp = await handle_change_password(
        _post_request(
            {
                "email": "u@example.com",
                "current_password": "password123",
                "new_password": "newpassword123",
                "confirm_password": "newpassword123",
            }
        ),
        auth_db,
    )

    assert resp.status_code == 200
    assert "Password changed successfully" in _body(resp)
    # New password authenticates, old one no longer does
    assert await auth_db.authenticate_user("u@example.com", "password123") is None
    assert await auth_db.authenticate_user("u@example.com", "newpassword123") is not None
    # Both token tables are cleared for this user (session revocation)
    assert await auth_db.get_access_token("acc-1") is None
    assert await auth_db.get_refresh_token("ref-1") is None


async def test_wrong_current_password_401_keeps_tokens(auth_db):
    uid = await auth_db.create_user("u@example.com", "password123", "k")
    await auth_db.save_access_token(
        DocketBirdAccessToken(
            token="acc-1",
            client_id="client-abc",
            scopes=["docketbird"],
            expires_at=int(time.time() + 3600),
            resource=None,
            docketbird_api_key="k",
            user_id=uid,
        )
    )

    resp = await handle_change_password(
        _post_request(
            {
                "email": "u@example.com",
                "current_password": "wrong",
                "new_password": "newpassword123",
                "confirm_password": "newpassword123",
            }
        ),
        auth_db,
    )

    assert resp.status_code == 401
    # Tokens untouched since auth failed before revocation
    assert await auth_db.get_access_token("acc-1") is not None


async def test_mismatched_confirmation_400(auth_db):
    await auth_db.create_user("u@example.com", "password123", "k")
    resp = await handle_change_password(
        _post_request(
            {
                "email": "u@example.com",
                "current_password": "password123",
                "new_password": "newpassword123",
                "confirm_password": "different123",
            }
        ),
        auth_db,
    )
    assert resp.status_code == 400
    assert "do not match" in _body(resp)


async def test_missing_fields_400(auth_db):
    await auth_db.create_user("u@example.com", "password123", "k")
    resp = await handle_change_password(
        _post_request(
            {
                "email": "u@example.com",
                "current_password": "password123",
                "new_password": "",
                "confirm_password": "",
            }
        ),
        auth_db,
    )
    assert resp.status_code == 400
