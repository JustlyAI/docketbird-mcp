"""Tests for AuthDB.ensure_service_token — non-expiring S2S access token seeding."""

import pytest
from auth_provider import AuthDB, DocketBirdAuthProvider

SERVICE_EMAIL = "service@aifintel.internal"
TOKEN = "svc-test-token-123"
KEY = "aif-docketbird-key"


@pytest.fixture
async def db(tmp_path):
    d = AuthDB(tmp_path / "auth.db")
    await d.initialize()
    yield d
    await d.close()


async def test_seeds_nonexpiring_token(db):
    await db.ensure_service_token(TOKEN, KEY)
    tok = await db.get_access_token(TOKEN)
    assert tok is not None
    assert tok.docketbird_api_key == KEY
    assert tok.scopes == ["docketbird"]
    assert tok.expires_at is None


async def test_idempotent(db):
    await db.ensure_service_token(TOKEN, KEY)
    await db.ensure_service_token(TOKEN, KEY)
    cur = await db._db.execute("SELECT COUNT(*) c FROM users WHERE email = ?", (SERVICE_EMAIL,))
    assert (await cur.fetchone())["c"] == 1
    cur = await db._db.execute("SELECT COUNT(*) c FROM access_tokens WHERE token = ?", (TOKEN,))
    assert (await cur.fetchone())["c"] == 1


async def test_survives_cleanup(db):
    await db.ensure_service_token(TOKEN, KEY)
    await db.cleanup_expired()
    assert await db.get_access_token(TOKEN) is not None


async def test_rotates_key_on_reseed(db):
    await db.ensure_service_token(TOKEN, "old-key")
    await db.ensure_service_token(TOKEN, "new-key")
    tok = await db.get_access_token(TOKEN)
    assert tok.docketbird_api_key == "new-key"


async def test_provider_verifies_service_token(db):
    await db.ensure_service_token(TOKEN, KEY)
    provider = DocketBirdAuthProvider(db)
    tok = await provider.load_access_token(TOKEN)
    assert tok is not None and tok.docketbird_api_key == KEY
