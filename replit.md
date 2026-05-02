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
- **Testing**: Vitest (50 unit tests in `artifacts/api-server/src/lib/scanner.test.ts`)

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

## What DeployGuard checks

POST /api/scan fetches the target URL and scores it across 7 categories (total 100 pts):

| Category | Weight | Checks |
|---|---|---|
| HTTPS & Redirects | 15 | HTTPS usage, redirect chain length (max 5 hops) |
| Security Headers | 30 | CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, HSTS |
| SEO | 20 | Title tag, meta description, viewport, Open Graph |
| Robots & Sitemap | 10 | robots.txt, sitemap.xml presence |
| Cookies | 10 | HttpOnly, Secure, SameSite flags |
| Performance | 10 | Response time, HTML size, external script count |
| API Exposure | 5 | Publicly accessible /docs, /swagger endpoints |

Grades: **Excellent** (≥85) / **Good** (≥70) / **Needs Work** (≥50) / **Risky** (<50)

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

### Evidence Fields
Every scan response includes:
- `htmlHash`: first 16 hex chars of SHA-256 of the fetched HTML body — proves the page was actually retrieved
- `responseHeadersSnapshot`: subset of response headers actually received (security + diagnostic headers)
These are stored in the database and displayed in the "Scan Evidence" panel in the UI.

## Key Commands

- `pnpm run typecheck` — full typecheck across all packages
- `pnpm run build` — typecheck + build all packages
- `pnpm --filter @workspace/api-spec run codegen` — regenerate API hooks and Zod schemas from OpenAPI spec
- `pnpm --filter @workspace/db run push` — push DB schema changes (dev only)
- `pnpm --filter @workspace/api-server run test` — run the 50-test scanner unit test suite

## API Endpoints

| Method | Path | Description |
|---|---|---|
| POST | /api/scan | Scan a URL, return full report + evidence fields, save to DB |
| GET | /api/scans | List recent scans (paginated) |
| GET | /api/scans/stats | Aggregate stats (total, avg score, grade distribution) |
| GET | /api/scans/:id | Full scan result by ID |
| DELETE | /api/scans/:id | Delete a scan |

## Database Schema

Single table: `scans` — stores all scan results including JSONB columns for flexible data (category scores, issues, cookie issues, redirect chain, security headers, response headers snapshot).

New columns added in production-hardening pass: `html_hash TEXT`, `response_headers_snapshot JSONB`.
