# DocketBird MCP — Tool Reference

Exact parameters, return shapes, and behavior for each tool. For workflows and
the big picture, see [SKILL.md](../SKILL.md).

## Contents
- [Conventions](#conventions)
- Research (whole corpus):
  [docketbird_search_cases](#docketbird_search_cases) ·
  [docketbird_fulltext_search](#docketbird_fulltext_search) ·
  [docketbird_get_case](#docketbird_get_case) ·
  [docketbird_get_case_details](#docketbird_get_case_details) ·
  [docketbird_search_documents](#docketbird_search_documents) ·
  [docketbird_get_document](#docketbird_get_document) ·
  [docketbird_get_document_text](#docketbird_get_document_text) ·
  [docketbird_download_document](#docketbird_download_document) ·
  [docketbird_download_files](#docketbird_download_files) ·
  [docketbird_ask_litigation_graph](#docketbird_ask_litigation_graph) ·
  [docketbird_list_courts](#docketbird_list_courts) ·
  [docketbird_list_court_systems](#docketbird_list_court_systems)
- Account (your firm's data):
  [docketbird_list_cases](#docketbird_list_cases) ·
  [docketbird_get_calendar](#docketbird_get_calendar) ·
  [docketbird_create_autocalendar](#docketbird_create_autocalendar) ·
  [docketbird_follow_case](#docketbird_follow_case)
- [Case ID anatomy](#case-id-anatomy)
- [Cursor pagination contract](#cursor-pagination-contract)
- [Error reference](#error-reference)

## Conventions

- Every tool is read-only **except** `docketbird_download_files`/`docketbird_download_document`
  (which may write to local disk in stdio mode), `docketbird_follow_case`, and
  `docketbird_create_autocalendar` (which mutate DocketBird state via POST).
- Tools return a single text string, **except** `docketbird_download_document`,
  which may return content blocks (a text summary plus an embedded document
  resource) when it returns a document's bytes.
- In-memory pagination (`page`/`page_size`): `page` starts at 1; `page_size`
  defaults to 20, max 50; out-of-range values are clamped, never an error. The
  cursor endpoints use the [cursor contract](#cursor-pagination-contract) instead.
- `case_id` format: see [Case ID anatomy](#case-id-anatomy).
- Tools surface failures as readable text rather than raising. See
  [Error reference](#error-reference).

## docketbird_search_cases

`docketbird_search_cases(query, court_id="", filed_after="", filed_before="", exclude_unknown_dates=False, size=25, cursor="")`

- `query` (required): a case name (matched against case titles) or a
  case-number-shaped string like `2:2017-bk-00112` / `17-bk-112` (matched on
  filing year, case type, terminating digits). Max 500 chars.
- `court_id`: comma-separated; each entry a slug (`nysd`), abbreviation
  (`S.D.N.Y.`), or full court name.
- Date filters match in tiers: exact-date cases at day precision, year-only
  cases at year granularity, unknown-date cases included unless
  `exclude_unknown_dates=True`.
- Returns: markdown per case — title, ID, court, type, case number, filed date,
  complaint pointer (`complaint_document_id` + status) when known, and the
  DocketBird page URL — plus a cursor footer.
- Scope: **the full DocketBird index**, not just the account's cases.

## docketbird_fulltext_search

`docketbird_fulltext_search(query, court_id="", case_id="", filed_after="", filed_before="", my_cases_only=False, sort="relevance", size=25, cursor="")`

- `query` (required, max 500 chars). Operators: space/`and` (all terms), `or`,
  `-term` (exclude; the word `not` is unsupported), `term*`/`term!` (endings),
  `/n` `/s` `/p` (proximity), `"..."` (phrase). Emails and `§`/`¶` are searchable.
- `court_id`: comma-separated; each entry a slug (`nysd`), abbreviation
  (`S.D.N.Y.`), or full court name. Multiple courts are fanned out one request per
  court and merged — smaller per-court queries are less likely to hit the backend's
  ~15 s internal limit.
- `my_cases_only`: `False` (default) = whole corpus (research scope);
  `True` = only cases associated with the firm's account (account scope).
- `sort`: `relevance` (default) or `recency`.
- Returns: markdown per document — title, document ID, case, court, filed date,
  up to 3 highlighted snippets, page URL — plus a cursor footer.
- Searches the **full text of filing bodies** — not docket-entry titles (that's
  `docketbird_search_documents`). Result window: first 10,000 matches.
- Transient failures (a raw 500 or timeout when a query crosses DocketBird's
  internal ~15 s limit) are retried once automatically; no action needed.

## docketbird_get_case

`docketbird_get_case(case_id)`

- `case_id` (required).
- Returns: markdown — title, ID, court, filed date, PACER URL, PACER case ID /
  client code when present, and the complaint pointer with fetch hint.
- Notes: single `GET /cases/{id}` — no docket fetch, so it cannot hit the
  large-docket timeout. Works for cases outside the account.

## docketbird_get_case_details

`docketbird_get_case_details(case_id, page=1, page_size=20)`

- `case_id` (required).
- Returns: markdown — case header (court, filed/closed dates, URL, and when
  available PACER case ID, client code, complaint pointer) and a paginated
  document list. Each document line is `[id] Title (Filed: …) [Download: yes|no]`.
- Notes: backed by DocketBird `GET /documents`, which has **no upstream
  pagination** — the whole docket is fetched every call, and `page`/`page_size`
  only shape the response; very large dockets can 504 (see SKILL.md).
  **Parties/attorneys are never included** — the API doesn't return them here;
  use `docketbird_ask_litigation_graph`.

## docketbird_search_documents

`docketbird_search_documents(case_id, search_term, page=1, page_size=20)`

- `case_id` (required), `search_term` (required): matched case-insensitively
  against docket-entry **title and description only** (not filing text).
- Returns: markdown list of matching documents (title, ID, filed date, availability).
- Notes: same unpaginated `GET /documents` dependency as `get_case_details`
  (filtering happens after the full fetch, so the large-docket 504 applies).
  For the text of filings, use `docketbird_fulltext_search` with `case_id`.

## docketbird_get_document

`docketbird_get_document(document_id)`

- `document_id` (required).
- Returns: markdown — title, ID, filed date, docket number, restricted flag,
  short-lived direct PDF link (when retrieved), court/PACER link, filename.
- Notes: metadata only — no bytes, no text. Use it to check availability or get
  a link without pulling content.

## docketbird_get_document_text

`docketbird_get_document_text(document_id, offset=0, max_chars=50000)`

- `document_id` (required); `offset`/`max_chars` page through long texts
  (`max_chars` capped at 200,000). The footer says what `offset` to pass next.
- Returns: the extracted plain text with a `Characters a-b of n` header.
- Notes: availability varies — scans without a text layer, not-yet-downloaded
  documents, and text-only docket stubs have no text; the tool then returns a
  clear "no extracted text" message (the PDF may still exist via
  `docketbird_get_document`). If DocketBird truncated text server-side, a note
  says so. A missing document comes back as the same friendly message (the API
  answers 400/404 there), not an error.

## docketbird_download_document

`docketbird_download_document(document_id, save_path=None)`

- `document_id` (required): from any of the document-listing/search tools.
- `save_path` (optional): only honored in **local stdio** mode; ignored remotely.
- Returns, by mode:
  - **Remote (or local with no `save_path`):** content blocks — a text summary
    plus an embedded resource holding the document bytes (base64), up to 10 MB.
    Over that cap, returns a text message with a short-lived direct download URL
    instead of inlining.
  - **Local stdio with `save_path`:** a text confirmation of the saved file path.
  - Restricted document: a text message (cannot be downloaded).
  - Not yet available: a text message (no download URL yet).

## docketbird_download_files

`docketbird_download_files(case_id, save_path=None)`

- `case_id` (required), `save_path` (optional, local-stdio only).
- Returns, by mode:
  - **Remote (or local with no `save_path`):** markdown listing each available
    document's title, ID, and a short-lived direct download URL, plus counts of
    restricted and not-yet-available filings. It does **not** inline file bytes.
  - **Local stdio with `save_path`:** a summary of how many files were saved to
    that folder, plus any skipped / restricted / failed.
- Notes: backed by `GET /documents` (large-docket 504 applies). Surfaced URLs pass
  the same SSRF/HTTPS allowlist as the streaming path.

## docketbird_ask_litigation_graph

`docketbird_ask_litigation_graph(question)`

- `question` (required, max 1000 chars): natural language, e.g. "What judges has
  Quinn Emanuel appeared before?", "Every case where Firm A opposed Firm B".
- Returns: markdown — DocketBird's interpretation of the question, the record
  count, one line per record (`field: value; …` — shape varies by question),
  truncation notice at the 200-record cap, and the coverage note.
- **Coverage ceiling**: federal civil cases in DocketBird's flows since July
  2025 (~30% of federal civil). No criminal, bankruptcy, or state matters.
  Zero records = "not in the graph", never "no such cases exist".
- Notes: slow (10–25 s — an AI interprets the question upstream). The **only**
  source of parties/attorneys/firms/judges. Attorney emails are never returned;
  do not fabricate contact data around its results. Out-of-scope or unsupported
  questions come back as a normal answer with a DocketBird message and 0 records.

## docketbird_list_courts

`docketbird_list_courts(search="", court_system="", court_type="")`

- No arguments: the curated set (~300 rows: all federal courts + named state
  courts) followed by the case-type reference table.
- `search`: free-text lookup (court name, abbreviation like `S.D.N.Y.`, or
  court_id) → up to 25 ranked matches from the FULL set, including thousands of
  unlisted state courts. The fastest way to resolve a court to its `court_id`.
- `court_system`: browse all courts in one system (ID from
  `docketbird_list_court_systems`), including unlisted ones.
- `court_type`: `federal` or `state`.
- Notes: **live** from `GET /courts` (requires auth). Safe to cache — the list
  changes rarely.

## docketbird_list_court_systems

`docketbird_list_court_systems()`

- Returns: markdown — every enabled court system (`court_system_id`, name,
  state, court count). Use an ID with `docketbird_list_courts(court_system=…)`.

## docketbird_list_cases

`docketbird_list_cases(scope, page=1, page_size=20)`

- `scope` (required): `"user"` (your personal cases) or `"company"` (all company cases).
- Returns: markdown list — each case's title, ID, court, case number, and filed date, with page info.
- Notes: **account scope** — the firm's tracked caseload only. For any other
  case, use `docketbird_search_cases`.

## docketbird_get_calendar

`docketbird_get_calendar(case_id="", days=7)`

- With `case_id`: every calendar entry for that case (title, ISO datetime,
  entry ID/uuid, linked document). No autocalendar → friendly "no calendar
  entries" message.
- Without `case_id`: **company-wide** — entries across all cases the company
  has active autocalendars for, within the next `days` days (1–90, clamped
  upstream), each tagged with case name/ID, plus the window and rollup
  freshness. First-ever call may say the rollup is being built — retry in a
  minute or two. No active autocalendars → message pointing to
  `docketbird_create_autocalendar`.

## docketbird_create_autocalendar

`docketbird_create_autocalendar(case_id)`

- `case_id` (required). **Write operation** (POST) — queues autocalendar
  creation; the docket sheet is updated first, and **court (PACER) fees may
  apply**.
- Returns: confirmation that creation is queued; entries then appear via
  `docketbird_get_calendar` (allow a minute or two).

## docketbird_follow_case

`docketbird_follow_case(case_id)`

- `case_id` (required). **Write operation** (POST) — starts DocketBird monitoring.
- Returns: confirmation text. Followed federal cases are checked ~2×/week, state
  cases ~1×/week; new filings trigger DocketBird's notifications.
- Notes: following a case is also how an account may gain access to a docket it
  doesn't yet have (a 403 with "charges may apply" suggests this).

## Case ID anatomy

```
{court}-{office}:{year}-{type}-{number}
```

- `court` — DocketBird court code (`txnd`, `cand`, `nysd`, …); from `docketbird_list_courts`.
- `office` — PACER division/office number.
- `year` — 4-digit filing year.
- `type` — case-type abbreviation (`cv` civil, `cr` criminal, `bk` bankruptcy, …); from `docketbird_list_courts`.
- `number` — docket number.

Example: `txnd-3:2007-cv-01697`.

Document IDs append the docket-entry number: `txwd-1:2022-cv-00398-00177`.

## Cursor pagination contract

Applies to `docketbird_search_cases` and `docketbird_fulltext_search`:

- Each result page ends with either `_End of results._` or a footer naming the
  `cursor` value to pass for the next page. **That footer is the only end
  signal.**
- A page may contain fewer than `size` items — even zero — while more results
  remain (restricted documents are removed after matching). Keep following the
  cursor.
- The "matched" count can include items that will never be returned, for the
  same reason.

## Error reference

Returned as readable text inside the tool result:

| Signal | Meaning | What to do |
|---|---|---|
| Authentication failed (401) | API key missing/invalid | stdio: set `DOCKETBIRD_API_KEY`; remote: re-authenticate / update the key |
| Access forbidden (403) | Account lacks access to the case | Follow the case first; "charges may apply" |
| not found (404) | Bad `case_id` format or unknown ID | Re-check the ID against the case-ID anatomy |
| Rate limited (429) | 30 requests / 60 s per client exceeded | Wait ~60 s and retry |
| Gateway timeout (504) | DocketBird-side ~29 s timeout assembling a large `/documents` list | Server-side limit; don't retry blindly (see SKILL.md) |
| HTTP 400 with DocketBird message | Invalid query syntax (search tools) or unknown document (text tool) | Fix the query per the message; the text tool already translates this to "no extracted text" |
