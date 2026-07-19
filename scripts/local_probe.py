"""Manual local probe against the REAL DocketBird API (not a unit test).

Loads DOCKETBIRD_API_KEY from .env in-process (does not touch the environment),
sets it as the stdio fallback key, and exercises the read-only tools end to end.
Write tools (follow_case) are intentionally NOT called here.

Run: .venv/bin/python tests/_local_probe.py
"""

import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

import docketbird_mcp
from docketbird_mcp import (
    docketbird_get_calendar,
    docketbird_get_case_details,
    docketbird_list_cases,
    docketbird_list_courts,
    docketbird_search_documents,
    make_request,
)


def load_api_key() -> str:
    """Read DOCKETBIRD_API_KEY from .env without printing it."""
    env_path = Path(__file__).parent.parent / ".env"
    for line in env_path.read_text(encoding="utf-8").splitlines():
        if line.startswith("DOCKETBIRD_API_KEY="):
            return line.split("=", 1)[1].strip().strip('"').strip("'")
    raise SystemExit("DOCKETBIRD_API_KEY not found in .env")


def banner(text: str) -> None:
    print("\n" + "=" * 70)
    print(text)
    print("=" * 70)


async def main() -> None:
    key = load_api_key()
    docketbird_mcp.FALLBACK_API_KEY = key  # in-process only
    print(f"Loaded API key from .env (len={len(key)}, ...{key[-4:]})")

    banner("1. docketbird_list_courts (local JSON)")
    print((await docketbird_list_courts())[:600])

    banner("2. docketbird_list_cases(scope='user')")
    print(await docketbird_list_cases("user"))

    banner("3. docketbird_list_cases(scope='company')")
    print(await docketbird_list_cases("company"))

    # Discover all case_ids, then find one this key can actually read documents for
    # (some listed cases return 403 on /documents).
    all_ids = []
    for scope in ("user", "company"):
        try:
            raw = await make_request("/cases", params={"scope": scope}, api_key=key)
            for c in raw.get("data", {}).get("cases", []):
                if c.get("id"):
                    all_ids.append(c["id"])
        except Exception as e:
            print(f"[probe] could not list {scope} cases: {e}")

    case_id = None
    for cid in all_ids:
        try:
            await make_request("/documents", params={"case_id": cid}, api_key=key)
            case_id = cid
            print(f"\n[probe] accessible case_id={case_id}")
            break
        except Exception as e:
            print(f"[probe] no document access for {cid}: {type(e).__name__}")

    if not case_id:
        print("\nNo document-accessible cases on this account; skipping case probes.")
        return

    banner(f"4. docketbird_get_case_details({case_id})  [+ PACER/client enrichment]")
    print(await docketbird_get_case_details(case_id))

    banner(f"5. docketbird_get_calendar({case_id})  [NEW]")
    print(await docketbird_get_calendar(case_id))

    banner(f"6. docketbird_search_documents({case_id}, 'order')")
    print(await docketbird_search_documents(case_id, "order"))

    await docketbird_mcp.cleanup_http_client()


if __name__ == "__main__":
    asyncio.run(main())
