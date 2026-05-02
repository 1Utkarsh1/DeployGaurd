# DeployGuard

## Overview

DeployGuard is a launch-readiness dashboard that scans any public URL and returns a scored security, SEO, and performance report. It is aimed at developers and founders who want to run a final checklist before going live.

## Stack

- **Monorepo tool**: pnpm workspaces
- **Node.js version**: 24
- **Package manager**: pnpm
- **Frontend**: React + Vite + Tailwind CSS (dark devtool theme)
- **Backend**: Node.js + Express 5
- **Database**: PostgreSQL + Drizzle ORM
- **Validation**: Zod (`zod/v4`), `drizzle-zod`
- **API codegen**: Orval (contract-first, from OpenAPI spec)
- **HTML parsing**: `node-html-parser`
- **Rate limiting**: `express-rate-limit`
- **Testing**: Vitest (117 unit tests in `artifacts/api-server/src/lib/scanner.test.ts`)

## Architecture

```
artifacts/
  api-server/     — Express 5 API server (port 8080, proxied at /api)
  deployguard/    — React + Vite frontend (port varies, proxied at /)
lib/
  api-spec/       — OpenAPI 3.1 contract (source of truth)
  api-client-react/ — Generated React Query hooks (do not edit manually)
  api-zod/        — Generated Zod schemas for server validation (do not edit manually)
  db/             — Drizzle ORM schema + migrations
```

## Scoring Rubric (v3 — 100 pts total)

| Category | Max | Key Checks |
|---|---|---|
| HTTPS & Redirects | 10 | HTTPS usage (8), clean redirect chain ≤2 hops (2) |
| Security Headers | 30 | CSP quality (12), HSTS quality (9), X-Frame-Options (4), Referrer-Policy (2), Permissions-Policy (2), COOP/COEP/CORP (1) |
| Cookies & Session | 15 | Per-cookie: Secure (-6), HttpOnly (-3), SameSite (-2), SameSite=None without Secure (-5), overly-broad domain (-2), very long Max-Age (-1); privacy posture: >3 cookies on first load (-1 per extra, max -3) |
| **CORS** | **10** | No CORS headers = 10/10; ACAO: * = 6/10 (warn); ACAO: * + credentials = 2/10 (critical); permissive methods w/ wildcard (-2); sensitive headers w/ wildcard (-1); specific origin = 10/10 |
| Cache & Exposure | 7 | Server header version leak (-1), X-Powered-By (-1), cache hygiene for cookie-bearing pages (-1), API docs exposed (-2) |
| Performance | 15 | penaltyCurve curves: response time (free <300ms, max 5pts at 2s), HTML size (free <250KB, max 5pts at 2MB), script count (free <10, max 5pts at 60) |
| SEO | 7 | Title quality (3), meta description (1.5), viewport (0.5), canonical (0.5), noindex penalty (−0.5), robots.txt (0.5), sitemap (0.5) |
| Accessibility | 6 | Inputs with accessible labels (2), images with alt (2), main landmark + headings (1), html lang attribute (1) |

**Total: 10+30+15+10+7+15+7+6 = 100**

Grades: **Excellent** (≥85) / **Good** (≥70) / **Needs Work** (≥50) / **Risky** (<50)

## Deep Analyzer Functions (exported for testing)

- `parseCspDirectives(csp)` — parses CSP string into directive→tokens Map
- `analyzeCsp(csp)` — quality-scores CSP 0-12 with per-weakness penalties
- `analyzeHsts(hsts, usesHttps)` — quality-scores HSTS 0-9 (max-age, includeSubDomains, preload)
- `analyzeCors(allowOrigin, allowCreds, allowMethods?, allowHeaders?)` — scores CORS posture 0-10 (10 = no CORS or properly scoped)
- `parseSetCookieHeaders(lines[])` — parses Set-Cookie header lines into ParsedCookie objects
- `penaltyCurve(value, freeThreshold, maxPenalty, fullPenaltyAt)` — linear penalty interpolation
- `headlessScan(url)` — feature-gated headless browser scan stub (returns null unless HEADLESS_SCAN=true)
- `normalizeUrl`, `isPrivateIp`, `validateSsrfSync` — SSRF protection primitives

## ML Overlay (`artifacts/api-server/src/lib/ml-overlay.ts`)

Deterministic rule-based "expert grade" overlay — a stub for future model training:
- `buildFeatureVector(params)` — builds a FeatureVector from scan result fields
- `computeMlOverlay(features)` — returns MlOverlayResult with adjustedGrade, confidence (0-1), rationale, featureImportance[]
- Hard downgrades: no HTTPS → Risky (0.97 confidence); critical CORS + otherwise Good → Needs Work
- No external API calls; fully offline and deterministic

## Score Killers

Every scan returns `scoreKillers[]` — top 3 findings sorted by `pointsLost` descending. Displayed prominently in the UI between the score card and the category breakdown.

## Security & Production Hardening

### SSRF Protection (layered)
- Protocol allowlist: only `http://` and `https://` accepted; ftp://, file://, gopher://, etc. explicitly blocked
- Hostname blocklist: localhost, 0.0.0.0, metadata.google.internal, 169.254.169.254, instance-data
- IPv4 private range blocking (regex): loopback 127/8, RFC1918 10/8 + 172.16-31/12 + 192.168/16, link-local 169.254/16, CGNAT 100.64-127/10, TEST-NET ranges, broadcast
- IPv6 private range blocking: loopback ::1, ULA fc00::/7 + fd00::/8, link-local fe80::/10, IPv4-mapped ::ffff:, 6to4 2002::
- **IPv6 bracket stripping**: `[::1]` in URLs is correctly stripped to `::1` before IP validation (prevents bypass)
- **DNS resolution check**: hostname is resolved to an IP via `dns.promises.lookup()`, and the resolved IP is validated against all private ranges (prevents DNS-based SSRF bypasses)
- SSRF check applied on **every redirect hop** (not just the initial URL)

### Request Hardening
- Manual redirect following: max 5 redirects with SSRF validation per hop
- Per-hop timeout: 8 seconds
- Absolute scan timeout: 30 seconds (AbortController propagated through all fetch calls)
- Body size cap: 2 MB (streamed read, excess discarded, connection closed)
- Compressed content: handled automatically by fetch (gzip, deflate, br via Accept-Encoding)
- Request is read-only (GET/HEAD only — never POST, PUT, DELETE to target)

### Rate Limiting
- Per-IP scan limit: 10 scans / minute on POST /scan (returns 429 + Retry-After: 60)
- Global API limit: 120 requests / minute per IP across all /api routes
- Concurrency backpressure: max 3 concurrent scans; excess immediately returns 429 + Retry-After: 10
- Standard RateLimit headers returned (RFC 9110 draft-7)

## Evidence Fields

Every scan response includes:
- `corsScore`: CORS posture 0-10 (standalone field + in categoryScores)
- `htmlHash`: first 16 hex chars of SHA-256 of the fetched HTML body
- `responseHeadersSnapshot`: subset of response headers actually received (now includes CORS headers)
- `scoreKillers`: top 3 findings by points lost
- `canonicalUrl`: canonical link element value (for SEO evidence)
- `hasStructuredData`: whether JSON-LD was detected
- `hasNoindex`: whether meta robots noindex was found

## Key Commands

- `pnpm run typecheck` — full typecheck across all packages
- `pnpm run build` — typecheck + build all packages
- `pnpm --filter @workspace/api-spec run codegen` — regenerate API hooks and Zod schemas from OpenAPI spec
- `pnpm --filter @workspace/db run push` — push DB schema changes (dev only)
- `pnpm --filter @workspace/api-server run test` — run the 117-test scanner unit test suite

## API Endpoints

| Method | Path | Description |
|---|---|---|
| POST | /api/scan | Scan a URL, return full report + evidence fields, save to DB |
| GET | /api/scans | List recent scans (paginated) |
| GET | /api/scans/stats | Aggregate stats (total, avg score, grade distribution) |
| GET | /api/scans/:id | Full scan result by ID |
| DELETE | /api/scans/:id | Delete a scan |

## Database Schema

Single table: `scans` — stores all scan results including JSONB columns for flexible data.

Columns added in v2: `score_killers JSONB`, `canonical_url TEXT`, `has_structured_data BOOLEAN`, `has_noindex BOOLEAN`.
Columns added in v3: `cors_score REAL` (default 10).
