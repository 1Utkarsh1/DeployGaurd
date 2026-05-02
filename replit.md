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

## Architecture

```
artifacts/
  api-server/     — Express 5 API server (port 8080, proxied at /api)
  deployguard/    — React + Vite frontend (port 22577, proxied at /)
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
| HTTPS & Redirects | 15 | HTTPS usage, redirect chain length |
| Security Headers | 30 | CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, HSTS |
| SEO | 20 | Title tag, meta description, viewport, Open Graph |
| Robots & Sitemap | 10 | robots.txt, sitemap.xml presence |
| Cookies | 10 | HttpOnly, Secure, SameSite flags |
| Performance | 10 | Response time, HTML size, external script count |
| API Exposure | 5 | Publicly accessible /docs, /swagger endpoints |

Grades: **Excellent** (≥85) / **Good** (≥70) / **Needs Work** (≥50) / **Risky** (<50)

## Security

- SSRF protection: blocks localhost, 127.x, 10.x, 192.168.x, 172.16-31.x, 169.254.x, IPv6 loopback
- Only http:// and https:// protocols accepted (ftp://, file://, etc. explicitly rejected)
- 8-second fetch timeout, 4-second timeout for auxiliary checks (robots.txt, sitemap, API paths)
- All inputs validated with Zod before processing

## Key Commands

- `pnpm run typecheck` — full typecheck across all packages
- `pnpm run build` — typecheck + build all packages
- `pnpm --filter @workspace/api-spec run codegen` — regenerate API hooks and Zod schemas from OpenAPI spec
- `pnpm --filter @workspace/db run push` — push DB schema changes (dev only)

## API Endpoints

| Method | Path | Description |
|---|---|---|
| POST | /api/scan | Scan a URL, return full report, save to DB |
| GET | /api/scans | List recent scans (paginated) |
| GET | /api/scans/stats | Aggregate stats (total, avg score, grade distribution) |
| GET | /api/scans/:id | Full scan result by ID |
| DELETE | /api/scans/:id | Delete a scan |

## Database Schema

Single table: `scans` — stores all scan results as JSONB for flexible category scores and issues arrays.
