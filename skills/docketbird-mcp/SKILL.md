---
name: docketbird-mcp
description: Research U.S. federal and state court cases and retrieve docket documents through the DocketBird MCP server. Use whenever working with DocketBird tools (docketbird_search_cases, docketbird_fulltext_search, docketbird_get_case, docketbird_get_case_details, docketbird_search_documents, docketbird_get_document, docketbird_get_document_text, docketbird_download_document, docketbird_download_files, docketbird_ask_litigation_graph, docketbird_list_courts, docketbird_list_court_systems, docketbird_list_cases, docketbird_get_calendar, docketbird_create_autocalendar, docketbird_follow_case) — e.g. finding cases by name or full text, reading a filing's text, profiling parties/attorneys/firms/judges, downloading documents, checking firm-wide deadlines, or interpreting DocketBird case IDs and court codes.
---

# DocketBird MCP

Search and retrieve U.S. court docket data (cases, filings, calendars, documents)
through the DocketBird MCP server. Each user authenticates with their own
DocketBird API key, so account-scoped results reflect what that account can access.

## Two scopes — don't mix them up

- **Research scope** (whole corpus: all courts, all cases, regardless of your
  account): `search_cases`, `fulltext_search` (default), `get_case`,
  `get_case_details`, `search_documents`, document tools, `ask_litigation_graph`,
  `list_courts`, `list_court_systems`.
- **Account scope** (your firm's own DocketBird data): `list_cases`,
  `get_calendar`, `create_autocalendar`, `follow_case`, and
  `fulltext_search(my_cases_only=True)`.

## Tool catalog

| Tool | Purpose |
|---|---|
| `docketbird_search_cases` | Search ALL cases by name or case number. Cursor-paginated. Start here for any case not on the account. |
| `docketbird_fulltext_search` | Full-text search of filing BODIES across the whole corpus (operators: `or`, `-term`, `term*`, `"..."`, `/n`, `/s`, `/p`). `my_cases_only=True` restricts to the firm's cases. |
| `docketbird_get_case` | One case's metadata + complaint pointer. No docket fetch — fast and timeout-safe. |
| `docketbird_get_case_details` | Full docket sheet: case header + paginated document list. |
| `docketbird_search_documents` | Match docket-entry TITLES/descriptions within one case (metadata only — not the filings' text). |
| `docketbird_get_document` | One document's metadata + download links (no bytes). |
| `docketbird_get_document_text` | Extracted plain text of a filing; page long texts with `offset`. |
| `docketbird_download_document` | Retrieve one document's content (see "Downloads"). |
| `docketbird_download_files` | Get every available document for a case (see "Downloads"). |
| `docketbird_ask_litigation_graph` | Natural-language questions about parties, attorneys, firms, judges and their connections. **The only source of party/attorney data.** Slow (10–25 s). |
| `docketbird_list_courts` | Look up courts live (name/abbreviation/court_id → `court_id`); also case-type reference. |
| `docketbird_list_court_systems` | Every covered court system, for browsing state coverage. |
| `docketbird_list_cases` | List cases on the account (`scope` = `user` or `company`). |
| `docketbird_get_calendar` | Deadlines/hearings for a case, or company-wide with a `days` window when `case_id` is omitted. |
| `docketbird_create_autocalendar` | **Write.** Queue autocalendar creation for a case (court fees may apply). |
| `docketbird_follow_case` | **Write.** Start monitoring a case for new filings. |

Full parameters, return shapes, and error meanings are in
[references/tools-reference.md](references/tools-reference.md) — read it when you
need exact argument or output details.

## Case IDs

Most tools take a DocketBird `case_id` shaped like:

```
{court}-{office}:{year}-{type}-{number}
e.g.  txnd-3:2007-cv-01697   (N.D. Tex., office 3, 2007, civil case 1697)
      cand-5:2025-cv-07105   (N.D. Cal., office 5, 2025, civil case 7105)
```

- `court` is a DocketBird court code (`txnd`, `cand`, `nysd`, …) — resolve with `docketbird_list_courts`.
- `type` is a case-type abbreviation (`cv` civil, `cr` criminal, …) — also from `docketbird_list_courts`.

Document IDs are **not** guessable. Get them from `docketbird_get_case_details`,
`docketbird_search_documents`, `docketbird_fulltext_search`, or a case's
complaint pointer.

## Core workflows

**Find a case anywhere, then read its complaint**
1. `docketbird_search_cases("Immedia Semiconductor")` → case ID + complaint document ID.
2. `docketbird_get_document_text(complaint_document_id)` to read it, or
   `docketbird_download_document` for the PDF.

**Scan recent filings for a topic or company (research/marketing)**
1. `docketbird_fulltext_search('"Acme Corp"', sort="recency", filed_after="2026-06-01")` —
   optionally narrow with `court_id`.
2. Follow `next_cursor` from the footer until it's gone (`_End of results._`).
3. Profile who's involved: `docketbird_ask_litigation_graph("Who represented Acme Corp?")`.

**Profile litigation relationships**
- `docketbird_ask_litigation_graph` for parties/attorneys/firms/judges. Mind the
  coverage ceiling: federal civil cases in DocketBird's flows since July 2025
  (~30% of federal civil). **Zero records ≠ no such cases.** Never invent
  contact details the tool didn't return.

**Research a case's filings (account or public)**
1. `docketbird_list_cases(scope="user")` (account) or `docketbird_search_cases` (anywhere) for the `case_id`.
2. `docketbird_get_case_details(case_id)` for the docket sheet; page with `page`/`page_size` (max 50).
3. `docketbird_search_documents(case_id, "motion to dismiss")` to match docket-entry titles, or `docketbird_fulltext_search(query, case_id=...)` to search the filings' text.

**Track deadlines / monitor a docket (account)**
- `docketbird_get_calendar(case_id)` for one case; `docketbird_get_calendar(days=30)` for the whole firm.
- No entries because there's no autocalendar? `docketbird_create_autocalendar(case_id)` (fees may apply), then re-check.
- `docketbird_follow_case(case_id)` to enable new-filing monitoring (federal ~2×/week, state ~1×/week).

## Downloads

Over the hosted server (remote/HTTP — the common case), don't assume a file
landed on disk:

- `docketbird_download_document` returns the document content to the client (base64, up to 10 MB; larger documents come back as a short-lived download URL).
- `docketbird_download_files` returns per-document download URLs, not the files (a case can be many large PDFs).
- A `save_path` is ignored remotely — it would write to the server, not the user's machine.

In local stdio mode, pass `save_path` to stream files to the user's own machine.
Restricted (sealed) and not-yet-processed documents are reported, not downloaded.

## Notes

- The whole-docket tools (`docketbird_get_case_details`, `docketbird_search_documents`, `docketbird_download_files`) fetch the entire docket upstream (no pagination there) and can 504 on unusually large dockets — a DocketBird-side ~29 s limit, so don't retry blindly. The cursor-paginated search tools and single-ID fetches are unaffected.
- `docketbird_fulltext_search` pagination: `next_cursor` is the ONLY end signal. A page can be empty while more results remain (restricted documents are removed after matching) — keep following the cursor.
- Parties and attorneys never appear on docket sheets — only `docketbird_ask_litigation_graph` has them.

## Errors

Tools return a plain-text message instead of raising. Most common:

- **Authentication failed (401)** — the account's DocketBird API key is missing or invalid.
- **Access forbidden (403)** — the account can't access that case; it may need to be followed first (DocketBird may note "charges may apply").
- **not found (404)** — check the `case_id` format.
- **Rate limited (429)** — 30 requests / 60 s per client; wait and retry.

See [references/tools-reference.md](references/tools-reference.md) for the full
per-tool detail and error table.
