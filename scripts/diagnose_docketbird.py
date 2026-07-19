"""DocketBird connectivity diagnostic — isolates API faults from MCP-server faults.

Every DocketBird endpoint is exercised at TWO layers and compared:

  Layer 1  RAW API   - a direct httpx GET to api.docketbird.com, using NONE of
                       our MCP code. This is the ground truth for "is the API ok?"
  Layer 2  MCP TOOL  - the actual @mcp.tool function from docketbird_mcp.py,
                       which wraps the same call with our pagination/formatting.

Reading the verdict:
  - Fails the SAME way at both layers  -> the fault is DocketBird's API.
  - Works RAW but fails as an MCP TOOL -> the fault is our MCP server.

The raw layer uses a timeout deliberately ABOVE DocketBird's 29s API-gateway
limit so a server-side 504 is observed as a 504 (not masked as a client timeout).

Loads DOCKETBIRD_API_KEY from .env in-process; it never reads or writes the
real environment. No files are written and no write endpoints are called.

Run:
    .venv/bin/python tests/diagnose_docketbird.py
    .venv/bin/python tests/diagnose_docketbird.py cand-5:2025-cv-07105 txnd-3:2007-cv-01697
"""

import asyncio
import sys
import time
from pathlib import Path

import httpx
from termcolor import cprint

sys.path.insert(0, str(Path(__file__).parent.parent))

import docketbird_mcp
from docketbird_mcp import (
    BASE_URL,
    docketbird_get_calendar,
    docketbird_get_case_details,
    docketbird_list_cases,
    docketbird_search_documents,
)

# =============================================================================
# Configuration (edit these, not the body)
# =============================================================================

DEFAULT_CASES = ["cand-5:2025-cv-07105", "txnd-3:2007-cv-01697"]

# Above DocketBird's ~29s API-gateway hard limit so we see the 504 it emits,
# rather than cutting the connection off early on our side.
RAW_TIMEOUT_SECONDS = 35.0

# Error sentinels the MCP tools put in their returned strings (they return text,
# never raise) so we can classify a tool result as failure without a status code.
TOOL_FAILURE_MARKERS = (
    "Gateway timeout",
    "timed out",
    "Authentication failed",
    "Access forbidden",
    "not found",
    "Connection failed",
    "Rate limited",
    "Error for",
)


def load_api_key() -> str:
    """Read DOCKETBIRD_API_KEY from .env without touching the environment."""
    env_path = Path(__file__).parent.parent / ".env"
    for line in env_path.read_text(encoding="utf-8").splitlines():
        if line.startswith("DOCKETBIRD_API_KEY="):
            return line.split("=", 1)[1].strip().strip('"').strip("'")
    raise SystemExit("DOCKETBIRD_API_KEY not found in .env")


def banner(text: str) -> None:
    cprint("\n" + "=" * 74, "blue")
    cprint(text, "blue", attrs=["bold"])
    cprint("=" * 74, "blue")


# =============================================================================
# Layer 1: RAW API (no MCP code at all)
# =============================================================================


async def raw_get(client: httpx.AsyncClient, path: str, params: dict, key: str) -> dict:
    """Time a direct GET against the DocketBird API and classify the outcome."""
    headers = {"Authorization": f"Bearer {key}"}
    start = time.monotonic()
    try:
        resp = await client.get(path, params=params, headers=headers, timeout=RAW_TIMEOUT_SECONDS)
        elapsed = time.monotonic() - start
        status = resp.status_code
        if status == 504:
            verdict = f"API GATEWAY TIMEOUT (504 after {elapsed:.1f}s) — DocketBird-side"
            color = "red"
        elif status == 200:
            verdict = f"OK ({elapsed:.2f}s)"
            color = "green"
        else:
            body = (resp.text or "")[:120].replace("\n", " ")
            verdict = f"HTTP {status} ({elapsed:.2f}s): {body}"
            color = "yellow"
        return {"ok": status == 200, "status": status, "elapsed": elapsed,
                "verdict": verdict, "color": color}
    except httpx.TimeoutException:
        elapsed = time.monotonic() - start
        return {"ok": False, "status": "TIMEOUT", "elapsed": elapsed,
                "verdict": f"CLIENT TIMEOUT (no response in {elapsed:.1f}s)", "color": "red"}
    except Exception as e:  # noqa: BLE001 - diagnostic wants every failure surfaced
        elapsed = time.monotonic() - start
        return {"ok": False, "status": type(e).__name__, "elapsed": elapsed,
                "verdict": f"{type(e).__name__}: {e}", "color": "red"}


# =============================================================================
# Layer 2: MCP TOOL (the real @mcp.tool functions)
# =============================================================================


async def run_tool(coro) -> dict:
    """Time an MCP tool call and classify its returned text as ok/failure."""
    start = time.monotonic()
    try:
        result = await coro
    except Exception as e:  # noqa: BLE001
        elapsed = time.monotonic() - start
        return {"ok": False, "elapsed": elapsed,
                "verdict": f"RAISED {type(e).__name__}: {e}", "color": "red",
                "sample": ""}
    elapsed = time.monotonic() - start
    failed = any(m.lower() in result.lower() for m in TOOL_FAILURE_MARKERS)
    sample = result.replace("\n", " ")[:140]
    if failed:
        return {"ok": False, "elapsed": elapsed,
                "verdict": f"TOOL ERROR ({elapsed:.1f}s): {sample}", "color": "red",
                "sample": sample}
    return {"ok": True, "elapsed": elapsed,
            "verdict": f"OK ({elapsed:.2f}s)", "color": "green", "sample": sample}


def diagnose(endpoint: str, raw: dict, tool: dict) -> None:
    """Print the side-by-side verdict and the conclusion for one endpoint."""
    cprint(f"\n• {endpoint}", attrs=["bold"])
    cprint(f"    RAW API : {raw['verdict']}", raw["color"])
    cprint(f"    MCP TOOL: {tool['verdict']}", tool["color"])
    if raw["ok"] and tool["ok"]:
        cprint("    -> Both layers healthy.", "green")
    elif not raw["ok"] and not tool["ok"]:
        cprint("    -> FAULT IS THE DOCKETBIRD API (fails raw and via MCP identically).", "red", attrs=["bold"])
    elif raw["ok"] and not tool["ok"]:
        cprint("    -> FAULT IS OUR MCP SERVER (raw API works, tool does not).", "magenta", attrs=["bold"])
    else:
        cprint("    -> Raw failed but tool reported ok — inspect manually.", "yellow")


async def main() -> None:
    cases = sys.argv[1:] or DEFAULT_CASES
    key = load_api_key()
    docketbird_mcp.FALLBACK_API_KEY = key  # in-process only; stdio fallback path
    cprint(f"Loaded API key from .env (len={len(key)}, ...{key[-4:]})", "cyan")
    cprint(f"Cases under test: {', '.join(cases)}", "cyan")

    async with httpx.AsyncClient(base_url=BASE_URL) as client:
        # --- Account-level endpoint (the one the user reports as 'working') ---
        banner("ACCOUNT: GET /cases?scope=user")
        raw = await raw_get(client, "/cases", {"scope": "user"}, key)
        tool = await run_tool(docketbird_list_cases("user"))
        diagnose("/cases?scope=user  ↔  docketbird_list_cases('user')", raw, tool)

        # --- Per-case document endpoints (the ones the user reports failing) ---
        for case_id in cases:
            banner(f"CASE: {case_id}")

            raw_docs = await raw_get(client, "/documents", {"case_id": case_id}, key)
            tool_details = await run_tool(docketbird_get_case_details(case_id))
            diagnose(
                f"/documents?case_id={case_id}  ↔  docketbird_get_case_details()",
                raw_docs, tool_details,
            )

            # search_documents hits the SAME /documents call, so it shares the fate.
            tool_search = await run_tool(docketbird_search_documents(case_id, "order"))
            diagnose(
                f"/documents?case_id={case_id}  ↔  docketbird_search_documents()",
                raw_docs, tool_search,
            )

            # Single-case metadata endpoint — fast even when /documents times out.
            raw_case = await raw_get(client, f"/cases/{case_id}", {}, key)
            cprint(f"\n• /cases/{case_id} (single-case metadata)", attrs=["bold"])
            cprint(f"    RAW API : {raw_case['verdict']}", raw_case["color"])

            # Calendar endpoint (independent of /documents).
            raw_cal = await raw_get(client, "/calendar_entries", {"case_id": case_id}, key)
            tool_cal = await run_tool(docketbird_get_calendar(case_id))
            diagnose(
                f"/calendar_entries?case_id={case_id}  ↔  docketbird_get_calendar()",
                raw_cal, tool_cal,
            )

    banner("SUMMARY")
    cprint(
        "The /documents endpoint is the shared dependency of get_case_details,\n"
        "search_documents, and download_files. If it returns 504 at the RAW layer,\n"
        "no MCP-server change can fix it — the timeout is inside DocketBird's API.",
        "cyan",
    )
    await docketbird_mcp.cleanup_http_client()


if __name__ == "__main__":
    asyncio.run(main())
