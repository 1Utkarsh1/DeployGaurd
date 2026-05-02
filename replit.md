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
- **Testing**: Vitest (137 unit tests in `artifacts/api-server/src/lib/scanner.test.ts`)
- **Headless browser**: Playwright (Chromium, optional, HEADLESS_SCAN=true gate)
- **AI overlay**: node-llama-cpp (optional, LOCAL_AI=true gate; deterministic fallback always active)

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

## Scoring Rubric (v4 — 100 pts total)

| Category | Max | Key Checks |
|---|---|---|
| HTTPS & Redirects | 10 | HTTPS usage (8), clean redirect chain ≤2 hops (2) |
| Security Headers | 30 | CSP quality (12), HSTS quality (9), X-Frame-Options (4), Referrer-Policy (2), Permissions-Policy (2), COOP/COEP/CORP (1) |
| Cookies & Session | 10 | Per-cookie: Secure (-6), HttpOnly (-3), SameSite (-2), SameSite=None without Secure (-5); overly-broad domain (-2); >3 cookies on first load (-1 per extra, max -3); no cookies = 10/10 |
| CORS | 10 | No CORS headers = 10/10; ACAO: * = 6/10 (warn); ACAO: * + credentials = 2/10 (critical); permissive methods w/ wildcard (-2) |
| Third-party | 10 | No external scripts = 10/10; penalizes unrecognized third-party script domains |
| Cache & Exposure | 5 | Server header version leak (-1), X-Powered-By (-1), cache hygiene (-1), API docs exposed (-2) |
| Performance | 8 | Response time, HTML size, script count penalty curves |
| SEO | 7 | Title quality (3), meta description (1.5), viewport (0.5), canonical (0.5), noindex penalty, robots.txt, sitemap |
| Structured Data | 5 | JSON-LD presence and validity (schema.org @type, @context, expected properties) |
| Accessibility | 5 | Inputs with labels (2), images with alt (2), main landmark + headings (1) |

**Total: 10+30+10+10+10+5+8+7+5+5 = 100**

Grades: **Excellent** (≥85) / **Good** (≥70) / **Needs Work** (≥50) / **Risky** (<50)

## v4 Engine Architecture

All scans run 4 analysis engines in parallel:

| Engine | Key | Always runs | Gate |
|---|---|---|---|
| Structured Data | `structured-data` | ✓ | — |
| Third-party Governance | `third-party` | ✓ | — |
| Headless Browser | `headless` | — | `HEADLESS_SCAN=true` |
| AI Overlay | `local-ai` | — | `LOCAL_AI=true` |

Engine badges appear in the scan result UI. The `enginesRan` array in the API response reflects which engines fired.

### Headless Scan (`artifacts/api-server/src/lib/headless.ts`)
- Launches a Playwright Chromium browser (headless)
- Measures: LCP via PerformanceObserver, render-blocking resources in `<head>`, total resource count + transfer size, axe-core WCAG violation count
- Produces `headlessScore` 0–10 (penalty for slow LCP, render-blocking, violations)
- Requires: `HEADLESS_SCAN=true` + playwright package + Chromium binary + system libs (glib, nspr, nss, X11 stack, mesa, libgbm, etc.)

### AI Overlay (`artifacts/api-server/src/lib/ai-overlay.ts`)
- With `LOCAL_AI=true`: attempts to load a GGUF model via node-llama-cpp (path from `LOCAL_AI_MODEL_PATH`)
- Falls back to deterministic rules when model is unavailable
- Produces `aiScore` 0–100, `confidence`, `rationale`, `riskLabel`, `engineUsed`
- UI shows Core vs AI scores side-by-side when AI overlay is present

### Structured Data (`artifacts/api-server/src/lib/structured-data.ts`)
- Extracts and validates all `<script type="application/ld+json">` blocks
- Checks @context (schema.org), @type, and expected properties for known types
- Score 0–5

### Third-party Governance (`artifacts/api-server/src/lib/third-party.ts`)
- Extracts all `<script src>` attributes and extracts unique domains
- Cross-references against a known-safe CDN/service whitelist
- Penalizes for excess unrecognized third-party script domains
- Score 0–10; domains list returned in `thirdPartyDomains[]`

## Environment Variables (Dev)

Set in `artifacts/api-server/.env` (loaded via `node --env-file=.env` at server start):

| Variable | Default | Purpose |
|---|---|---|
| `HEADLESS_SCAN` | `true` | Enable Playwright headless engine |
| `LOCAL_AI` | `true` | Enable AI overlay engine |
| `LOCAL_AI_MODEL_PATH` | (unset) | Path to GGUF model file for real LLM inference |

`LD_LIBRARY_PATH=$REPLIT_LD_LIBRARY_PATH` is prepended in the start script so Chromium can find NixOS system libraries.

## Deep Analyzer Functions (exported for testing)

- `parseCspDirectives(csp)` — parses CSP string into directive→tokens Map
- `analyzeCsp(csp)` — quality-scores CSP 0-12 with per-weakness penalties
- `analyzeHsts(hsts, usesHttps)` — quality-scores HSTS 0-9 (max-age, includeSubDomains, preload)
- `analyzeCors(allowOrigin, allowCreds, allowMethods?, allowHeaders?)` — scores CORS posture 0-10
- `parseSetCookieHeaders(lines[])` — parses Set-Cookie header lines into ParsedCookie objects
- `penaltyCurve(value, freeThreshold, maxPenalty, fullPenaltyAt)` — linear penalty interpolation
- `headlessScan(url)` — Playwright headless browser scan (HEADLESS_SCAN=true gate)
- `scoreStructuredData(html)` — validates JSON-LD blocks, returns 0-5 score + issues
- `scoreThirdPartyGovernance(html, pageHost)` — scores third-party governance 0-10
- `computeAiOverlay(featureVector, topFindings)` — AI overlay score (LOCAL_AI=true gate)
- `normalizeUrl`, `isPrivateIp`, `validateSsrfSync` — SSRF protection primitives

## ML Overlay (`artifacts/api-server/src/lib/ml-overlay.ts`)

Deterministic rule-based "expert grade" overlay:
- `buildFeatureVector(params)` — builds a FeatureVector from scan result fields
- `computeMlOverlay(features)` — returns MlOverlayResult with adjustedGrade, confidence, rationale, featureImportance[]

## Score Killers

Every scan returns `scoreKillers[]` — top 3 findings sorted by `pointsLost` descending.

## Security & Production Hardening

### SSRF Protection (layered)
- Protocol allowlist: only `http://` and `https://` accepted
- Hostname blocklist: localhost, 0.0.0.0, metadata.google.internal, 169.254.169.254
- IPv4 private range blocking (regex): loopback, RFC1918, link-local, CGNAT, TEST-NET, broadcast
- IPv6 private range blocking: loopback, ULA, link-local, IPv4-mapped, 6to4
- **IPv6 bracket stripping**: `[::1]` correctly stripped before IP validation
- **DNS resolution check**: hostname resolved and validated on every redirect hop

### Request Hardening
- Manual redirect following: max 5 redirects with SSRF validation per hop
- Per-hop timeout: 8 seconds; absolute scan timeout: 30 seconds
- Body size cap: 2 MB; request is read-only (GET/HEAD only)

### Rate Limiting
- Per-IP scan limit: 10 scans / minute on POST /scan
- Global API limit: 120 requests / minute per IP
- Concurrency backpressure: max 3 concurrent scans → 429 + Retry-After: 10

## Evidence Fields

Every scan response includes:
- `corsScore`, `structuredDataScore`, `thirdPartyScore` — standalone score fields
- `thirdPartyDomains[]` — list of detected third-party script domains
- `aiOverlay` — AI overlay result (null if LOCAL_AI=false)
- `headlessScan` — headless browser metrics (null if HEADLESS_SCAN=false)
- `enginesRan[]` — which v4 engines ran for this scan
- `htmlHash`, `responseHeadersSnapshot`, `scoreKillers`, `canonicalUrl`, `hasStructuredData`, `hasNoindex`

## Key Commands

- `pnpm run typecheck` — full typecheck across all packages (0 errors)
- `pnpm --filter @workspace/api-spec run codegen` — regenerate API hooks and Zod schemas from OpenAPI spec
- `pnpm --filter @workspace/db run push` — push DB schema changes (dev only)
- `pnpm --filter @workspace/api-server run test` — run the 137-test scanner unit test suite

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
Columns added in v3: `cors_score REAL`.
Columns added in v4: `structured_data_score REAL`, `third_party_score REAL`, `third_party_domains JSONB`, `ai_overlay JSONB`, `headless_scan JSONB`, `engines_ran JSONB`.
