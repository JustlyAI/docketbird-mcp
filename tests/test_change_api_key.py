"""Tests for the /change-api-key route handler in auth_provider.py.

Drives handle_change_api_key directly with a synthetic Starlette Request and a
STUB validator (async callable) so no real DocketBird HTTP call is made. Covers:
valid key, DocketBird-rejected key, wrong password, unreachable DocketBird, and
missing fields. Uses the isolated temp DB (auth_db fixture from conftest).
"""

import time
from urllib.parse import urlencode

import pytest
from starlette.requests import Request

from auth_provider import DocketBirdAccessToken, handle_change_api_key

pytestmark = pytest.mark.asyncio


# ---- Stub validators (injected in place of validate_docketbird_api_key) ----


async def _valid(api_key):
    return True


async def _rejected(api_key):
    return False


async def _unreachable(api_key):
    raise RuntimeError("DocketBird unreachable")


# ---- Request builders ----


def _get_request() -> Request:
    scope = {
        "type": "http",
        "method": "GET",
        "path": "/change-api-key",
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
        "path": "/change-api-key",
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
    resp = await handle_change_api_key(_get_request(), auth_db, _valid)
    assert resp.status_code == 200
    html = _body(resp)
    assert "Change API Key" in html
    assert 'action="/change-api-key"' in html


async def test_valid_key_updates_and_clears_access_tokens(auth_db):
    await auth_db.create_user("u@example.com", "password123", "old-key")  # user_id=1
    await auth_db.save_access_token(
        DocketBirdAccessToken(
            token="acc-1",
            client_id="client-abc",
            scopes=["docketbird"],
            expires_at=int(time.time() + 3600),
            resource="https://app.docketbird-mcp.com/mcp",
            docketbird_api_key="old-key",
            user_id=1,
        )
    )

    resp = await handle_change_api_key(
        _post_request(
            {"email": "u@example.com", "current_password": "password123", "new_api_key": "new-key"}
        ),
        auth_db,
        _valid,
    )

    assert resp.status_code == 200
    assert "API key updated" in _body(resp)
    assert (await auth_db.get_user(1))["docketbird_api_key"] == "new-key"
    # Stale access token (carrying the old key) is cleared
    assert await auth_db.get_access_token("acc-1") is None


async def test_rejected_key_keeps_old(auth_db):
    await auth_db.create_user("u@example.com", "password123", "old-key")
    resp = await handle_change_api_key(
        _post_request(
            {"email": "u@example.com", "current_password": "password123", "new_api_key": "bad-key"}
        ),
        auth_db,
        _rejected,
    )
    assert resp.status_code == 400
    assert "rejected by DocketBird" in _body(resp)
    assert (await auth_db.get_user(1))["docketbird_api_key"] == "old-key"


async def test_wrong_password_401_keeps_old(auth_db):
    await auth_db.create_user("u@example.com", "password123", "old-key")
    resp = await handle_change_api_key(
        _post_request(
            {"email": "u@example.com", "current_password": "wrong", "new_api_key": "new-key"}
        ),
        auth_db,
        _valid,
    )
    assert resp.status_code == 401
    assert (await auth_db.get_user(1))["docketbird_api_key"] == "old-key"


async def test_unreachable_does_not_save(auth_db):
    await auth_db.create_user("u@example.com", "password123", "old-key")
    resp = await handle_change_api_key(
        _post_request(
            {"email": "u@example.com", "current_password": "password123", "new_api_key": "new-key"}
        ),
        auth_db,
        _unreachable,
    )
    assert resp.status_code == 502
    assert (await auth_db.get_user(1))["docketbird_api_key"] == "old-key"


async def test_missing_fields_400(auth_db):
    await auth_db.create_user("u@example.com", "password123", "old-key")
    resp = await handle_change_api_key(
        _post_request(
            {"email": "u@example.com", "current_password": "password123", "new_api_key": ""}
        ),
        auth_db,
        _valid,
    )
    assert resp.status_code == 400
