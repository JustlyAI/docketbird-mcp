"""Tests for the /health payload, including the deployed-commit version field."""

import os

os.environ.setdefault("DATA_DIR", "/tmp/docketbird-test-data")

import docketbird_mcp as d


def test_health_payload_has_status_and_service():
    payload = d._health_payload()
    assert payload["status"] == "ok"
    assert payload["service"] == "docketbird-mcp"


def test_health_payload_reports_git_sha(monkeypatch):
    monkeypatch.setattr(d, "GIT_SHA", "abc1234")
    assert d._health_payload()["version"] == "abc1234"
