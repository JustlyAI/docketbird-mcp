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

## Downloads: what you get back depends on the connection

The download tools adapt to the transport. Do not assume a file landed on the
user's disk — over the hosted server it usually did not.

- **Remote (the hosted server over HTTP — the common case):**
  - `docketbird_download_document` returns the document **content to the client** as an embedded resource (base64), up to 10 MB. Larger documents come back as a **direct, short-lived download URL** instead of inline bytes.
  - `docketbird_download_files` returns a **list of per-document download URLs**, not the files themselves (a case can be many large PDFs). Fetch the ones you need, or call `docketbird_download_document` per ID.
  - A `save_path` argument is **ignored** remotely — it would write to the server, not the user's machine.
- **Local (stdio) mode:** pass `save_path` and files stream to that folder on the user's own machine. Omit it and content is returned to the client as above.

Restricted (sealed / PACER-limited) documents cannot be downloaded; not-yet-processed
documents have no download URL yet. Both are reported in the result, not errors.

## Known limitation: large dockets can time out

`docketbird_get_case_details`, `docketbird_search_documents`, and
`docketbird_download_files` all depend on DocketBird's `GET /documents`, which can
return a **504 "Gateway timeout"** (~29 s) for unusually large dockets. This is a
**DocketBird server-side limit** — no MCP-side change or retry fixes it, and there
is currently no working pagination parameter to shrink the request. When it happens:

- The case is not fully inaccessible: `docketbird_get_calendar`, single-document
  fetch by a known ID, and case metadata still work. A `get_case_details` timeout
  only means the document *list* couldn't be assembled.
- Treat it as a DocketBird issue to report, not something to retry indefinitely.

## Errors

Tools return a plain-text message instead of raising. Most common:

- **Authentication failed (401)** — the account's DocketBird API key is missing or invalid.
- **Access forbidden (403)** — the account can't access that case; it may need to be followed first (DocketBird may note "charges may apply").
- **not found (404)** — check the `case_id` format.
- **Rate limited (429)** — 30 requests / 60 s per client; wait and retry.

See [references/tools-reference.md](references/tools-reference.md) for the full
per-tool detail and error table.
