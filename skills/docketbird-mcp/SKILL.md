---
name: docketbird-mcp
description: Research U.S. federal and state court cases and retrieve docket documents through the DocketBird MCP server. Use whenever working with DocketBird tools (docketbird_list_cases, docketbird_get_case_details, docketbird_search_documents, docketbird_download_document, docketbird_download_files, docketbird_get_calendar, docketbird_follow_case, docketbird_list_courts) — e.g. finding a case and its filings, searching a docket by keyword, downloading a document's content or pre-signed links, checking hearing and deadline calendars, following a case for new filings, or interpreting DocketBird case IDs and court codes.
---

# DocketBird MCP

Search and retrieve U.S. court docket data (cases, filings, calendars, documents)
through the DocketBird MCP server. Each user authenticates with their own
DocketBird API key, so every result is scoped to what that account can access.

## Tool catalog

| Tool | Purpose |
|---|---|
| `docketbird_list_cases` | List cases on the account (`scope` = `user` or `company`). Start here to find case IDs. |
| `docketbird_get_case_details` | Case header, parties, and a paginated document list (with document IDs and download availability). |
| `docketbird_search_documents` | Filter a case's documents by keyword in title/description. |
| `docketbird_list_courts` | Reference list of court codes and case types (static, fast). Use to read or build case IDs. |
| `docketbird_download_document` | Retrieve one document by ID (see "Downloads"). |
| `docketbird_download_files` | Get every available document for a case (see "Downloads"). |
| `docketbird_get_calendar` | Hearings and deadlines for a case. |
| `docketbird_follow_case` | Start monitoring a case so DocketBird tracks new filings. |

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

- `court` is a DocketBird court code (`txnd`, `cand`, `nysd`, …) — look up with `docketbird_list_courts`.
- `type` is a case-type abbreviation (`cv` civil, `cr` criminal, …) — also from `docketbird_list_courts`.

Document IDs are **not** guessable. Get them from `docketbird_get_case_details`
or `docketbird_search_documents`, which list each document as `[id] Title …`.

## Core workflows

**Research a case's filings**
1. `docketbird_list_cases(scope="user")` (or `"company"`) to find the `case_id`.
2. `docketbird_get_case_details(case_id)` for parties and the document list; page with `page` / `page_size` (max 50 per page).
3. `docketbird_search_documents(case_id, "motion to dismiss")` to narrow by keyword.

**Get a document's content**
- `docketbird_download_document(document_id)` using an ID from step 2 or 3.

**Archive a whole case**
- `docketbird_download_files(case_id)` — returns download links (remote) or saves all files (local; see below).

**Track deadlines / monitor a docket**
- `docketbird_get_calendar(case_id)` for hearings and deadlines.
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

- The document-list tools (`docketbird_get_case_details`, `docketbird_search_documents`, `docketbird_download_files`) can time out (504) on unusually large dockets — a DocketBird-side limit, so don't retry blindly. Calendar and single-document-by-ID fetches are unaffected.
- The calendar is read-only here: `docketbird_get_calendar` returns "no calendar entries" when a case has no autocalendar, and there is no MCP tool to create one.

## Errors

Tools return a plain-text message instead of raising. Most common:

- **Authentication failed (401)** — the account's DocketBird API key is missing or invalid.
- **Access forbidden (403)** — the account can't access that case; it may need to be followed first (DocketBird may note "charges may apply").
- **not found (404)** — check the `case_id` format.
- **Rate limited (429)** — 30 requests / 60 s per client; wait and retry.

See [references/tools-reference.md](references/tools-reference.md) for the full
per-tool detail and error table.
