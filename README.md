<div align="center">

<!-- Logo Banner -->
<img src="https://github.com/user-attachments/assets/dcc5ff62-d811-4a02-9d13-6b6654b538c7" alt="DeployGuard" width="300" />

<br/>

<img src="https://img.shields.io/badge/version-4.0.0-6366f1?style=for-the-badge&logo=semver&logoColor=white" alt="version"/>
<img src="https://img.shields.io/badge/Node.js-24-339933?style=for-the-badge&logo=node.js&logoColor=white" alt="Node.js"/>
<img src="https://img.shields.io/badge/TypeScript-5.9-3178C6?style=for-the-badge&logo=typescript&logoColor=white" alt="TypeScript"/>
<img src="https://img.shields.io/badge/License-MIT-22c55e?style=for-the-badge" alt="MIT License"/>
<img src="https://img.shields.io/badge/Tests-137_passing-22c55e?style=for-the-badge&logo=vitest&logoColor=white" alt="Tests"/>
<img src="https://img.shields.io/badge/pnpm-workspace-f97316?style=for-the-badge&logo=pnpm&logoColor=white" alt="pnpm"/>

<br/><br/>

> **DeployGuard** is a launch-readiness dashboard that scans any public URL and returns a
> fully scored **Security**, **SEO**, and **Performance** report — so you ship with confidence, not anxiety.

<br/>

```
┌──────────────────────────────────────────────────────────────────────┐
│  Enter URL ──▶  4 Parallel Engines  ──▶  100-pt Score  ──▶  Report   │
│                  ┌──────────────┐                                     │
│                  │ Structured   │                                     │
│                  │ Data Engine  │                                     │
│                  ├──────────────┤                                     │
│   🌐 URL  ──▶   │ Third-Party  │  ──▶  🎯 Score  ──▶  📋 Report      │
│                  │ Governance   │                                     │
│                  ├──────────────┤                                     │
│                  │  Headless    │                                     │
│                  │  Browser     │                                     │
│                  ├──────────────┤                                     │
│                  │  AI Overlay  │                                     │
│                  └──────────────┘                                     │
└──────────────────────────────────────────────────────────────────────┘
```

</div>

---

## 📖 Table of Contents

- [✨ Features](#-features)
- [🏗️ Architecture](#️-architecture)
- [📊 Scoring Rubric](#-scoring-rubric)
- [🔬 Analysis Engines](#-analysis-engines)
- [🛡️ Security Hardening](#️-security-hardening)
- [🚀 Getting Started](#-getting-started)
- [⚙️ Environment Variables](#️-environment-variables)
- [📡 API Reference](#-api-reference)
- [🗄️ Database Schema](#️-database-schema)
- [🧪 Testing](#-testing)
- [🛠️ Tech Stack](#️-tech-stack)
- [📜 License](#-license)

---

## ✨ Features

<table>
<tr>
<td width="50%">

### 🔐 Security Analysis
- **30-point** security header deep-scan (CSP, HSTS, X-Frame, COOP/COEP/CORP)
- Cookie hygiene scoring (Secure, HttpOnly, SameSite)
- CORS posture assessment
- Wildcard origin & credentialed-CORS detection
- SSRF protection with IPv4/IPv6 private range blocking

</td>
<td width="50%">

### 🚀 Performance & SEO
- Response time & HTML size scoring
- Script count penalty curves
- Title, meta description & viewport quality
- Canonical URL & noindex detection
- Robots.txt and sitemap validation

</td>
</tr>
<tr>
<td width="50%">

### 🤖 AI Overlay (Optional)
- Local LLM inference via `node-llama-cpp` (GGUF models)
- Deterministic rule-based fallback always active
- Confidence score + human-readable rationale
- Core vs AI scores displayed side-by-side

</td>
<td width="50%">

### 🌐 Headless Browser Engine (Optional)
- Playwright Chromium for real-world metrics
- LCP measurement via PerformanceObserver
- Render-blocking resource detection
- axe-core WCAG accessibility violation scan

</td>
</tr>
</table>

---

## 🏗️ Architecture

```
DeployGuard/
├── 📦 artifacts/
│   ├── 🖥️  api-server/        — Express 5 API server (port 8080)
│   │   └── src/lib/
│   │       ├── scanner.ts       — Core scanning engine
│   │       ├── headless.ts      — Playwright headless engine
│   │       ├── ai-overlay.ts    — LLM / deterministic AI layer
│   │       ├── structured-data.ts — JSON-LD validator
│   │       └── third-party.ts   — Third-party governance
│   │
│   └── 🌐 deployguard/         — React + Vite frontend
│
├── 📚 lib/
│   ├── api-spec/               — OpenAPI 3.1 contract (source of truth)
│   ├── api-client-react/       — Generated React Query hooks
│   ├── api-zod/                — Generated Zod validation schemas
│   └── db/                     — Drizzle ORM schema + migrations
│
└── 🔧 scripts/                 — Post-merge & tooling scripts
```

### Data Flow

```
Client Request
     │
     ▼
┌─────────────┐    Rate Limit     ┌──────────────────┐
│  React UI   │ ──────────────▶  │   Express 5 API  │
│  (Vite)     │ ◀──────────────  │   (Port 8080)    │
└─────────────┘    JSON Report    └────────┬─────────┘
                                           │
                   ┌───────────────────────┤
                   │                       │
          ┌────────▼──────┐      ┌────────▼──────┐
          │  HTTP Scanner  │      │  PostgreSQL   │
          │  (node fetch)  │      │  + Drizzle    │
          └────────┬──────┘      └───────────────┘
                   │
     ┌─────────────┼─────────────┐
     │             │             │
┌────▼────┐  ┌─────▼────┐  ┌────▼──────┐
│Structured│  │ Third-   │  │ Headless  │
│  Data   │  │  Party   │  │ Browser   │
│ Engine  │  │ Engine   │  │(Playwright)│
└─────────┘  └──────────┘  └───────────┘
```

---

## 📊 Scoring Rubric

> **Total: 100 points** across 10 categories

```
┌─────────────────────────────────────────────────────────────────────┐
│                    DeployGuard Score Breakdown                       │
│                                                                     │
│  Security Headers  ████████████████████████████████  30 pts  ████  │
│  HTTPS & Redirects ████████████████████            10 pts  ████   │
│  Cookies & Session ████████████████████            10 pts  ████   │
│  CORS Posture      ████████████████████            10 pts  ████   │
│  Third-party       ████████████████████            10 pts  ████   │
│  Performance       ████████████████                 8 pts  ████   │
│  SEO               ██████████████                   7 pts  ████   │
│  Structured Data   ██████████                       5 pts  ████   │
│  Accessibility     ██████████                       5 pts  ████   │
│  Cache & Exposure  ██████████                       5 pts  ████   │
└─────────────────────────────────────────────────────────────────────┘
```

| Category | Max | Key Checks |
|---|:---:|---|
| 🔐 **Security Headers** | **30** | CSP quality (12), HSTS (9), X-Frame-Options (4), Referrer-Policy (2), Permissions-Policy (2), COOP/COEP/CORP (1) |
| 🌍 **HTTPS & Redirects** | **10** | HTTPS usage (8), clean redirect chain ≤2 hops (2) |
| 🍪 **Cookies & Session** | **10** | Secure, HttpOnly, SameSite flags; domain scope; cookie count |
| 🔀 **CORS** | **10** | No wildcard origins; credentialed CORS detection; method permissiveness |
| 📦 **Third-party** | **10** | Known CDN whitelist; unrecognized domain penalty |
| ⚡ **Performance** | **8** | Response time, HTML size, script count penalty curves |
| 🔍 **SEO** | **7** | Title quality (3), meta description (1.5), viewport (0.5), canonical (0.5), robots/sitemap |
| 🧩 **Structured Data** | **5** | JSON-LD presence, @context, @type, expected properties |
| ♿ **Accessibility** | **5** | Form labels (2), image alt text (2), landmarks + headings (1) |
| 🗃️ **Cache & Exposure** | **5** | Server header leak, X-Powered-By, cache hygiene, API docs exposure |

### 🎯 Grade Thresholds

```
  ≥ 85  ██████████████████████████  🟢 EXCELLENT  — Ship it!
  ≥ 70  ████████████████████        🔵 GOOD       — Minor tweaks
  ≥ 50  ████████████                🟡 NEEDS WORK — Address findings
   < 50  ████                        🔴 RISKY      — Do NOT ship
```

---

## 🔬 Analysis Engines

DeployGuard runs **4 engines in parallel** per scan:

| Engine | Always Runs | Gate | Description |
|---|:---:|---|---|
| 📋 **Structured Data** | ✅ | — | Validates JSON-LD `<script>` blocks against schema.org |
| 🌐 **Third-party Governance** | ✅ | — | Cross-references external scripts against safe-CDN whitelist |
| 🖥️ **Headless Browser** | ❌ | `HEADLESS_SCAN=true` | Playwright Chromium — LCP, render-blocking, WCAG |
| 🤖 **AI Overlay** | ❌ | `LOCAL_AI=true` | node-llama-cpp LLM + deterministic fallback |

Engine badges appear in the scan result UI; `enginesRan[]` field in API responses shows which engines fired.

---

## 🛡️ Security Hardening

### SSRF Protection (Layered Defense)

```
┌──────────────────────────────────────────────────────────────────┐
│                        SSRF Shield                               │
│                                                                  │
│  Layer 1: Protocol Allowlist  (only http:// and https://)       │
│     │                                                            │
│  Layer 2: Hostname Blocklist  (localhost, metadata endpoints...) │
│     │                                                            │
│  Layer 3: IPv4 Private Range  (RFC1918, loopback, link-local...) │
│     │                                                            │
│  Layer 4: IPv6 Private Range  (loopback, ULA, IPv4-mapped...)   │
│     │                                                            │
│  Layer 5: DNS Resolution Check (per redirect hop)               │
└──────────────────────────────────────────────────────────────────┘
```

### Request Hardening

| Protection | Limit |
|---|---|
| 🔄 Max redirects | 5 hops (SSRF-validated per hop) |
| ⏱️ Per-hop timeout | 8 seconds |
| ⏱️ Absolute scan timeout | 30 seconds |
| 📏 Body size cap | 2 MB |
| 🔒 Request methods | GET / HEAD only |

### Rate Limiting

| Endpoint | Limit |
|---|---|
| `POST /api/scan` | 10 scans / minute / IP |
| All API routes | 120 requests / minute / IP |
| Concurrent scans | Max 3 → 429 + `Retry-After: 10` |

---

## 🚀 Getting Started

### Prerequisites

- **Node.js** ≥ 24
- **pnpm** ≥ 9
- **PostgreSQL** (local or hosted)

### Installation

```bash
# Clone the repository
git clone https://github.com/1Utkarsh1/DeployGaurd.git
cd DeployGaurd

# Install all workspace dependencies
pnpm install
```

### Database Setup

```bash
# Push schema to your database
pnpm --filter @workspace/db run push
```

### Development

```bash
# Start API server (port 8080)
pnpm --filter @workspace/api-server run dev

# Start frontend (Vite dev server)
pnpm --filter @workspace/deployguard run dev
```

### Build

```bash
# Full typecheck + build all packages
pnpm run build
```

---

## ⚙️ Environment Variables

Create `artifacts/api-server/.env`:

```env
# ── Database ───────────────────────────────────────────────────────────
DATABASE_URL=postgresql://user:password@localhost:5432/deployguard

# ── Optional Engines ───────────────────────────────────────────────────
HEADLESS_SCAN=true           # Enable Playwright headless engine
LOCAL_AI=true                # Enable AI overlay engine
LOCAL_AI_MODEL_PATH=         # Path to GGUF model file (real LLM inference)
```

> **Note:** `LD_LIBRARY_PATH=$REPLIT_LD_LIBRARY_PATH` is prepended at server start so Chromium can locate NixOS system libraries on Replit.

---

## 📡 API Reference

### Endpoints

| Method | Path | Description |
|:---:|---|---|
| `POST` | `/api/scan` | Scan a URL → full report + evidence fields, persisted to DB |
| `GET` | `/api/scans` | List recent scans (paginated) |
| `GET` | `/api/scans/stats` | Aggregate stats (total, avg score, grade distribution) |
| `GET` | `/api/scans/:id` | Full scan result by ID |
| `DELETE` | `/api/scans/:id` | Delete a scan record |

### `POST /api/scan` — Request

```json
{
  "url": "https://example.com"
}
```

### `POST /api/scan` — Response (abbreviated)

```json
{
  "id": "uuid",
  "url": "https://example.com",
  "score": 87,
  "grade": "Excellent",
  "enginesRan": ["structured-data", "third-party", "headless", "local-ai"],

  "httpsScore": 10,
  "securityHeadersScore": 24,
  "cookieScore": 10,
  "corsScore": 10,
  "thirdPartyScore": 8,
  "performanceScore": 7,
  "seoScore": 6,
  "structuredDataScore": 5,
  "accessibilityScore": 4,

  "scoreKillers": [
    { "category": "Security Headers", "pointsLost": 6, "finding": "No CSP header" }
  ],

  "thirdPartyDomains": ["cdn.example.com"],
  "aiOverlay": { "aiScore": 85, "confidence": 0.92, "riskLabel": "Low", "rationale": "..." },
  "headlessScan": { "lcp": 1200, "renderBlocking": 2, "wcagViolations": 0, "headlessScore": 9 },

  "htmlHash": "sha256:...",
  "canonicalUrl": "https://example.com/",
  "hasStructuredData": true,
  "hasNoindex": false,
  "responseHeadersSnapshot": { ... }
}
```

---

## 🗄️ Database Schema

Single `scans` table with JSONB columns for flexible evidence storage:

```sql
CREATE TABLE scans (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  url             TEXT NOT NULL,
  created_at      TIMESTAMPTZ DEFAULT NOW(),

  -- Core scores
  score           REAL,
  grade           TEXT,
  https_score     REAL,
  security_headers_score REAL,
  cookie_score    REAL,
  performance_score REAL,
  seo_score       REAL,

  -- v2 additions
  score_killers   JSONB,
  canonical_url   TEXT,
  has_structured_data BOOLEAN,
  has_noindex     BOOLEAN,

  -- v3 additions
  cors_score      REAL,

  -- v4 additions
  structured_data_score REAL,
  third_party_score     REAL,
  third_party_domains   JSONB,
  ai_overlay            JSONB,
  headless_scan         JSONB,
  engines_ran           JSONB
);
```

---

## 🧪 Testing

```bash
# Run the 137-test scanner unit suite
pnpm --filter @workspace/api-server run test

# Full typecheck (0 errors target)
pnpm run typecheck

# Regenerate API client & Zod schemas from OpenAPI spec
pnpm --filter @workspace/api-spec run codegen
```

**Test coverage includes:**
- `parseCspDirectives` — CSP string parser
- `analyzeCsp` — CSP quality scoring (0–12)
- `analyzeHsts` — HSTS scoring (0–9)
- `analyzeCors` — CORS posture scoring (0–10)
- `parseSetCookieHeaders` — Cookie attribute parsing
- `penaltyCurve` — Linear interpolation helper
- `scoreStructuredData` — JSON-LD validator (0–5)
- `scoreThirdPartyGovernance` — Third-party domain scoring (0–10)
- `normalizeUrl`, `isPrivateIp`, `validateSsrfSync` — SSRF primitives

---

## 🛠️ Tech Stack

<div align="center">

| Layer | Technology |
|---|---|
| 📦 **Monorepo** | pnpm workspaces |
| 🌐 **Frontend** | React + Vite + Tailwind CSS (dark devtool theme) |
| ⚙️ **Backend** | Node.js 24 + Express 5 |
| 🗄️ **Database** | PostgreSQL + Drizzle ORM |
| ✅ **Validation** | Zod v4 + drizzle-zod |
| 🔄 **API Codegen** | Orval (contract-first, OpenAPI 3.1) |
| 🌍 **HTML Parsing** | node-html-parser |
| 🚦 **Rate Limiting** | express-rate-limit |
| 🧪 **Testing** | Vitest |
| 🖥️ **Headless Browser** | Playwright (Chromium) |
| 🤖 **AI / LLM** | node-llama-cpp (GGUF models) |
| 🔤 **Language** | TypeScript 5.9 |

</div>

<div align="center">

<img src="https://img.shields.io/badge/React-20232A?style=for-the-badge&logo=react&logoColor=61DAFB"/>
<img src="https://img.shields.io/badge/Vite-646CFF?style=for-the-badge&logo=vite&logoColor=white"/>
<img src="https://img.shields.io/badge/Tailwind_CSS-38B2AC?style=for-the-badge&logo=tailwind-css&logoColor=white"/>
<img src="https://img.shields.io/badge/Express.js-404D59?style=for-the-badge&logo=express&logoColor=white"/>
<img src="https://img.shields.io/badge/PostgreSQL-316192?style=for-the-badge&logo=postgresql&logoColor=white"/>
<img src="https://img.shields.io/badge/TypeScript-007ACC?style=for-the-badge&logo=typescript&logoColor=white"/>
<img src="https://img.shields.io/badge/Vitest-6E9F18?style=for-the-badge&logo=vitest&logoColor=white"/>
<img src="https://img.shields.io/badge/Playwright-2EAD33?style=for-the-badge&logo=playwright&logoColor=white"/>
<img src="https://img.shields.io/badge/Zod-3E67B1?style=for-the-badge&logo=zod&logoColor=white"/>
<img src="https://img.shields.io/badge/drizzle-C5F74F?style=for-the-badge&logo=drizzle&logoColor=black"/>
<img src="https://img.shields.io/badge/OpenAPI-6BA539?style=for-the-badge&logo=openapiinitiative&logoColor=white"/>

</div>

---

## 📜 License

```
MIT License — Copyright (c) 2024 DeployGuard Contributors
```

This project is licensed under the **MIT License**. See [`LICENSE`](LICENSE) for details.

---

<div align="center">

**Built with ❤️ for developers who ship with confidence**

<br/>

⭐ **Star this repo** if DeployGuard helped you launch safer!

<br/>

<img src="https://img.shields.io/github/stars/1Utkarsh1/DeployGaurd?style=social" alt="GitHub Stars"/>
&nbsp;
<img src="https://img.shields.io/github/forks/1Utkarsh1/DeployGaurd?style=social" alt="GitHub Forks"/>
&nbsp;
<img src="https://img.shields.io/github/watchers/1Utkarsh1/DeployGaurd?style=social" alt="GitHub Watchers"/>

</div>
