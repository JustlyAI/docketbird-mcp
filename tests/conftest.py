"""Shared pytest fixtures for the DocketBird MCP test suite.

Adds the project root to sys.path so `docketbird_mcp` and `auth_provider`
import cleanly when tests run from anywhere.
"""

import sys
from pathlib import Path

import pytest_asyncio

PROJECT_ROOT = Path(__file__).parent.parent.resolve()
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from auth_provider import AuthDB  # noqa: E402


@pytest_asyncio.fixture
async def auth_db(tmp_path):
    """A fresh, isolated AuthDB backed by a temp SQLite file."""
    db = AuthDB(db_path=tmp_path / "test_auth.db")
    await db.initialize()
    try:
        yield db
    finally:
        await db.close()
