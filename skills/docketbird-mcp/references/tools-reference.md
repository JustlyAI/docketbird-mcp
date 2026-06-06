# DocketBird MCP — Tool Reference

Exact parameters, return shapes, and behavior for each tool. For workflows and
the big picture, see [SKILL.md](../SKILL.md).

## Contents
- [Conventions](#conventions)
- [docketbird_list_cases](#docketbird_list_cases)
- [docketbird_get_case_details](#docketbird_get_case_details)
- [docketbird_search_documents](#docketbird_search_documents)
- [docketbird_list_courts](#docketbird_list_courts)
- [docketbird_download_document](#docketbird_download_document)
- [docketbird_download_files](#docketbird_download_files)
- [docketbird_get_calendar](#docketbird_get_calendar)
- [docketbird_follow_case](#docketbird_follow_case)
- [Case ID anatomy](#case-id-anatomy)
- [Error reference](#error-reference)

## Conventions

- Every tool is read-only **except** `docketbird_download_files`/`docketbird_download_document`
  (which may write to local disk in stdio mode) and `docketbird_follow_case` (which
  mutates DocketBird state via POST).
- Tools return a single text string, **except** `docketbird_download_document`,
  which may return content blocks (a text summary plus an embedded document
  resource) when it returns a document's bytes.
- Pagination (where present): `page` starts at 1; `page_size` defaults to 20, max
  50. Out-of-range values are clamped, never an error.
- `case_id` format: see [Case ID anatomy](#case-id-anatomy).
- Tools surface failures as readable text rather than raising. See
  [Error reference](#error-reference).

## docketbird_list_cases

`docketbird_list_cases(scope, page=1, page_size=20)`

- `scope` (required): `"user"` (your personal cases) or `"company"` (all company cases).
- Returns: markdown list — each case's title, ID, court, case number, and filed date, with page info.
- Notes: lightweight; the best first call to discover `case_id` values.

## docketbird_get_case_details

`docketbird_get_case_details(case_id, page=1, page_size=20)`

- `case_id` (required).
- Returns: markdown — case header (court, filed/closed dates, URL, and when
  available PACER case ID and client code), parties, and a paginated document
  list. Each document line is `[id] Title (Filed: …) [Download: yes|no]`.
- Notes: backed by DocketBird `GET /documents`, so it can 504 on very large
  dockets (see SKILL.md). The `[id]` values are what `docketbird_download_document`
  needs. `[Download: no]` means the document isn't yet retrievable.

## docketbird_search_documents

`docketbird_search_documents(case_id, search_term, page=1, page_size=20)`

- `case_id` (required), `search_term` (required): matched case-insensitively against document title and description.
- Returns: markdown list of matching documents (title, ID, filed date, availability).
- Notes: same `GET /documents` dependency as `get_case_details`. Filtering happens
  after fetch, so it does not avoid the large-docket timeout.

## docketbird_list_courts

`docketbird_list_courts(search="")`

- `search` (optional): case-insensitive filter over court code and court name (e.g. `"california"`, `"nysd"`). Empty returns all courts.
- Returns: markdown — matching courts (`code: name`) plus the case-type table (abbreviation, name, example).
- Notes: served from static bundled data, so it is fast and never hits the API.
  Use it to resolve court codes and case-type abbreviations when building a `case_id`.

## docketbird_download_document

`docketbird_download_document(document_id, save_path=None)`

- `document_id` (required): from `get_case_details` / `search_documents`.
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

## docketbird_get_calendar

`docketbird_get_calendar(case_id)`

- `case_id` (required).
- Returns: markdown list of calendar entries (title, ISO datetime, entry ID/uuid,
  linked document ID when present). If the case has no autocalendar, returns a
  friendly "no calendar entries" message (not an error).

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

## Error reference

Returned as readable text inside the tool result:

| Signal | Meaning | What to do |
|---|---|---|
| Authentication failed (401) | API key missing/invalid | stdio: set `DOCKETBIRD_API_KEY`; remote: re-authenticate / update the key |
| Access forbidden (403) | Account lacks access to the case | Follow the case first; "charges may apply" |
| not found (404) | Bad `case_id` format or unknown ID | Re-check the ID against the case-ID anatomy |
| Rate limited (429) | 30 requests / 60 s per client exceeded | Wait ~60 s and retry |
| Gateway timeout (504) | DocketBird-side timeout assembling a large `/documents` list | Server-side limit; don't retry blindly (see SKILL.md) |
