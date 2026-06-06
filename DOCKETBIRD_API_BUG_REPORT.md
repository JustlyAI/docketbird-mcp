# Bug Report: `GET /documents` returns 504 (gateway timeout) for an accessible case

**To:** DocketBird API Support
**Date observed:** 2026-06-04 (re-confirmed still failing 2026-06-06)
**Severity:** High — the case's document list cannot be retrieved at all
**API base:** `https://api.docketbird.com`

---

## Summary

`GET /documents?case_id=cand-5:2025-cv-07105` consistently returns **HTTP 504**
with body `{"message": "Endpoint request timed out"}` after **~29.2 seconds**, for
a case our account can otherwise access. Every other endpoint for the same case
and the same API key responds normally in under one second. The ~29s ceiling and
the response body match an AWS API Gateway integration timeout, which suggests the
backend that assembles this case's document list does not complete within the
gateway's limit.

The failure is fully server-side: it reproduces with a plain `curl` against the
API, independent of any client. We verified the same 504 at two layers with
identical ~29s timing — a raw `curl`/`httpx` request (no application framework)
and our own application client — which isolates the fault to the API rather than
to any client code. All read parameters we tried (`page`, `page_size`, `limit`,
`per_page`, `offset`, `sort`, `fields`, date filters) produce the same 504, so we
have no client-side way to reduce the result size and work around it.

---

## Affected account / case

- **API key:** withheld (available privately on request)
- **Case ID:** `cand-5:2025-cv-07105`
- **Title:** Apple Inc. v. Shi et al
- **Court:** `cand`
- **Filed:** 2025-08-21
- **PACER case ID:** 455023
- **PACER URL:** https://ecf.cand.uscourts.gov/cgi-bin/DktRpt.pl?455023

This is the only case on the account (confirmed in both `scope=user` and
`scope=company`), so we cannot compare against another docket on the same key.

---

## Reproduction

```bash
# Failing call (set DOCKETBIRD_API_KEY to the affected account's key):
curl -s -o /dev/null \
  -w "HTTP %{http_code} | %{time_total}s | %{size_download} bytes\n" \
  --max-time 60 \
  -H "Authorization: Bearer $DOCKETBIRD_API_KEY" \
  "https://api.docketbird.com/documents?case_id=cand-5:2025-cv-07105"
```

**Observed output (consistent across 6+ attempts):**

```
HTTP 504 | 29.28s | 41 bytes
```

Response body:

```json
{"message": "Endpoint request timed out"}
```

---

## Observed vs. expected

| Behavior | |
|---|---|
| **Expected** | `200` with `data.documents[]` for the case (as documented for `/documents`). |
| **Observed** | `504 {"message": "Endpoint request timed out"}` at ~29.2s, every time. |

---

## Evidence: same key, same case, only `/documents` fails

All calls below used the same API key on 2026-06-04:

| Request | Result | Time |
|---|---|---|
| `GET /cases?scope=user` | `200` ✅ | 0.60 s |
| `GET /cases?scope=company` | `200` ✅ | 0.6 s |
| `GET /cases/cand-5:2025-cv-07105` | `200` ✅ (returns case metadata, PACER ID 455023) | 0.94 s |
| `GET /calendar_entries?case_id=cand-5:2025-cv-07105` | `404` ("no autocalendar for this case") | 0.5 s |
| **`GET /documents?case_id=cand-5:2025-cv-07105`** | **`504` "Endpoint request timed out"** ❌ | **29.28 s** |

Authentication and account access are clearly fine. Only the document-list
assembly for this case fails.

---

## Parameter variations attempted (all return the same 504 at ~29s)

We tried these to reduce the payload and avoid the timeout. None changed the
outcome, which indicates the parameters are ignored and the full set is always
assembled before the gateway times out:

```
GET /documents?case_id=cand-5:2025-cv-07105&page=1&page_size=10     -> 504 @ 29.3s
GET /documents?case_id=cand-5:2025-cv-07105&limit=10                -> 504 @ 29.4s
GET /documents?case_id=cand-5:2025-cv-07105&per_page=10             -> 504 @ 29.3s
GET /documents?case_id=cand-5:2025-cv-07105&offset=0&limit=10       -> 504 @ 29.5s
GET /documents?case_id=cand-5:2025-cv-07105&sort=-filing_date       -> 504 @ 29.3s
GET /documents?case_id=cand-5:2025-cv-07105&filing_date_after=...   -> 504 @ 29.3s
GET /documents?case_id=cand-5:2025-cv-07105&fields=id,title         -> 504 @ 29.3s
GET /cases/cand-5:2025-cv-07105/documents (nested)                  -> 400 @ 0.5s
```

Per the published API spec (SwaggerHub `DocketBird/DocketBird/0.3`), `GET
/documents` documents only `case_id` and no pagination parameters — yet its
**response schema includes a `has_more` boolean**, which implies the result set
is meant to be paged. We could not find a documented or working parameter to
fetch subsequent pages, so every request appears to assemble the full set in one
synchronous call and times out.

---

## Impact

Every document-facing operation for this case is blocked, because they all depend
on `GET /documents`:

- Retrieving the case's document list / docket
- Searching within the case's documents
- Downloading individual documents (the document IDs needed for a per-document
  fetch are only available from `/documents`)
- Bulk-downloading the case file

---

## Questions / requested resolution

1. Can the `/documents` query for `cand-5:2025-cv-07105` be optimized so it
   completes within the gateway timeout? (e.g., this docket may be unusually
   large or hitting a slow code path.)
2. The `/documents` response schema includes `has_more`, which implies
   pagination — but the spec documents no pagination parameter and the ones we
   tried are ignored. What is the correct parameter (or endpoint) to page through
   a large case's documents so the full set isn't assembled in one synchronous
   request that exceeds the gateway timeout?
3. Is this specific to this case, or a known issue with large/recent dockets?

Happy to provide the full API key, additional timing logs, or run further tests
on request.
