import { parse as parseHtml } from "node-html-parser";
import { createHash } from "crypto";
import { promises as dnsPromises } from "dns";
import { scoreStructuredData } from "./structured-data.js";
import { scoreThirdPartyGovernance } from "./third-party.js";
import { headlessScan as _headlessScan } from "./headless.js";
import { computeAiOverlay, type AiOverlayResult } from "./ai-overlay.js";
import { buildFeatureVector } from "./ml-overlay.js";

export { headlessScan } from "./headless.js";
export type { HeadlessResult } from "./headless.js";

// ================================================================
// Constants
// ================================================================

const MAX_BODY_BYTES = 2 * 1024 * 1024;
const MAX_REDIRECTS = 5;
const PER_HOP_TIMEOUT_MS = 8_000;
const ABSOLUTE_TIMEOUT_MS = 30_000;

const BLOCKED_HOSTNAMES = new Set([
  "localhost",
  "0.0.0.0",
  "metadata.google.internal",
  "169.254.169.254",
  "instance-data",
]);

const PRIVATE_IPV4_RE: RegExp[] = [
  /^127\./,
  /^10\./,
  /^192\.168\./,
  /^172\.(1[6-9]|2[0-9]|3[01])\./,
  /^169\.254\./,
  /^0\./,
  /^100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\./,
  /^192\.0\.2\./,
  /^198\.51\.100\./,
  /^203\.0\.113\./,
  /^255\./,
];

const PRIVATE_IPV6_RE: RegExp[] = [
  /^::1$/i,
  /^::$/,
  /^::ffff:/i,
  /^64:ff9b:/i,
  /^fc[0-9a-f]{2}:/i,
  /^fd[0-9a-f]{2}:/i,
  /^fe[89ab][0-9a-f]:/i,
  /^2002:/i,
];

const EVIDENCE_HEADERS = [
  "content-security-policy",
  "strict-transport-security",
  "x-frame-options",
  "referrer-policy",
  "permissions-policy",
  "cross-origin-opener-policy",
  "cross-origin-embedder-policy",
  "cross-origin-resource-policy",
  "x-content-type-options",
  "access-control-allow-origin",
  "access-control-allow-credentials",
  "access-control-allow-methods",
  "access-control-allow-headers",
  "content-type",
  "server",
  "x-powered-by",
  "cache-control",
  "via",
];

// ================================================================
// Types
// ================================================================

type Severity = "critical" | "warning" | "info" | "passed";

interface Issue {
  category: string;
  severity: Severity;
  message: string;
  explanation: string;
  suggestion: string;
}

interface Penalty {
  category: string;
  message: string;
  pointsLost: number;
}

export interface ParsedCookie {
  name: string;
  hasSecure: boolean;
  hasHttpOnly: boolean;
  sameSite: "strict" | "lax" | "none" | null;
  domain: string | null;
  maxAge: number | null;
  path: string | null;
}

export interface ScanResult {
  url: string;
  finalUrl: string;
  score: number;
  grade: string;
  statusCode: number;
  redirectChain: string[];
  usesHttps: boolean;
  responseTimeMs: number;
  title: string | null;
  metaDescription: string | null;
  hasViewport: boolean;
  hasOpenGraph: boolean;
  hasRobotsTxt: boolean;
  hasSitemapXml: boolean;
  securityHeaders: Record<string, boolean>;
  cookieIssues: string[];
  htmlSizeKb: number;
  scriptTagCount: number;
  categoryScores: Array<{ name: string; score: number; maxScore: number; label: string }>;
  issues: Array<Issue>;
  fixPrompt: string;
  htmlHash: string;
  responseHeadersSnapshot: Record<string, string>;
  corsScore: number;
  scoreKillers: Array<{ category: string; message: string; pointsLost: number }>;
  canonicalUrl: string | null;
  hasStructuredData: boolean;
  hasNoindex: boolean;
  structuredDataScore: number;
  thirdPartyScore: number;
  thirdPartyDomains: string[];
  aiOverlay: AiOverlayResult | null;
  headlessScan: import("./headless.js").HeadlessResult | null;
  enginesRan: string[];
}

// ================================================================
// SSRF Protection — exported for tests
// ================================================================

export function isPrivateIp(address: string): boolean {
  for (const re of PRIVATE_IPV4_RE) {
    if (re.test(address)) return true;
  }
  for (const re of PRIVATE_IPV6_RE) {
    if (re.test(address)) return true;
  }
  return false;
}

export function validateSsrfSync(url: string): void {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    throw new Error("Invalid URL format");
  }
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    throw new Error("Only http and https protocols are allowed");
  }
  const raw = parsed.hostname.toLowerCase();
  const hostname = raw.startsWith("[") && raw.endsWith("]") ? raw.slice(1, -1) : raw;
  if (BLOCKED_HOSTNAMES.has(hostname)) throw new Error(`Blocked hostname: ${hostname}`);
  if (isPrivateIp(hostname)) throw new Error(`Blocked private IP range: ${hostname}`);
}

async function validateSsrfAsync(url: string): Promise<void> {
  validateSsrfSync(url);
  const rawHostname = new URL(url).hostname.toLowerCase();
  const hostname =
    rawHostname.startsWith("[") && rawHostname.endsWith("]")
      ? rawHostname.slice(1, -1)
      : rawHostname;
  if (/^\d+\.\d+\.\d+\.\d+$/.test(hostname) || hostname.includes(":")) return;
  let address: string;
  try {
    const result = await dnsPromises.lookup(hostname, { family: 0 });
    address = result.address;
  } catch {
    throw new Error(`Cannot resolve hostname: ${hostname}`);
  }
  if (isPrivateIp(address)) {
    throw new Error(`Blocked: ${hostname} resolves to private IP ${address}`);
  }
}

// ================================================================
// URL Normalization — exported for tests
// ================================================================

export function normalizeUrl(input: string): string {
  const trimmed = input.trim();
  if (/^https?:\/\//i.test(trimmed)) return trimmed;
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(trimmed)) return trimmed;
  return `https://${trimmed}`;
}

// ================================================================
// HTTP Helpers
// ================================================================

async function fetchWithManualRedirects(
  initialUrl: string,
  maxRedirects: number,
  perHopTimeoutMs: number,
  requestHeaders: Record<string, string>,
  signal: AbortSignal,
): Promise<{ response: Response; redirectChain: string[] }> {
  const chain: string[] = [initialUrl];
  let currentUrl = initialUrl;

  for (let hop = 0; hop <= maxRedirects; hop++) {
    if (signal.aborted) throw new Error("Scan timed out");

    const hopController = new AbortController();
    const hopTimer = setTimeout(() => hopController.abort(), perHopTimeoutMs);
    const onParentAbort = (): void => hopController.abort();
    signal.addEventListener("abort", onParentAbort, { once: true });

    let response: Response;
    try {
      response = await fetch(currentUrl, {
        method: "GET",
        redirect: "manual",
        headers: requestHeaders,
        signal: hopController.signal,
      });
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      throw new Error(`Request failed: ${msg}`);
    } finally {
      clearTimeout(hopTimer);
      signal.removeEventListener("abort", onParentAbort);
    }

    if (response.status < 300 || response.status >= 400) {
      return { response, redirectChain: chain };
    }
    if (hop === maxRedirects) {
      await response.body?.cancel().catch(() => {});
      throw new Error(`Too many redirects (max ${maxRedirects})`);
    }
    const location = response.headers.get("location");
    if (!location) return { response, redirectChain: chain };
    await response.body?.cancel().catch(() => {});
    const nextUrl = new URL(location, currentUrl).toString();
    await validateSsrfAsync(nextUrl);
    chain.push(nextUrl);
    currentUrl = nextUrl;
  }

  throw new Error(`Too many redirects (max ${maxRedirects})`);
}

async function readBodyCapped(
  response: Response,
  maxBytes: number,
): Promise<{ text: string; truncated: boolean }> {
  if (!response.body) {
    const text = await response.text();
    return { text, truncated: false };
  }
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let totalBytes = 0;
  let truncated = false;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done || !value) break;
      const remaining = maxBytes - totalBytes;
      if (value.length >= remaining) {
        if (remaining > 0) chunks.push(value.subarray(0, remaining));
        truncated = true;
        break;
      }
      chunks.push(value);
      totalBytes += value.length;
    }
  } finally {
    await reader.cancel().catch(() => {});
  }
  const combined = Buffer.concat(chunks.map((c) => Buffer.from(c)));
  return { text: combined.toString("utf8"), truncated };
}

// ================================================================
// Exported Analyzers (for unit tests)
// ================================================================

/**
 * Parses a CSP header value into a Map of directive name → token array.
 * Both names and tokens are lowercased.
 */
export function parseCspDirectives(cspValue: string): Map<string, string[]> {
  const map = new Map<string, string[]>();
  for (const part of cspValue.split(";")) {
    const trimmed = part.trim();
    if (!trimmed) continue;
    const tokens = trimmed.split(/\s+/);
    const name = tokens[0]?.toLowerCase();
    if (name) map.set(name, tokens.slice(1).map((t) => t.toLowerCase()));
  }
  return map;
}

export interface CspAnalysis {
  score: number;
  issues: Issue[];
  penalties: Penalty[];
}

/** Scores CSP quality 0-12. Exported for tests. */
export function analyzeCsp(cspValue: string | null): CspAnalysis {
  const issues: Issue[] = [];
  const penalties: Penalty[] = [];
  const CAT = "Security Headers";

  if (!cspValue) {
    penalties.push({ category: CAT, message: "Missing Content-Security-Policy", pointsLost: 12 });
    issues.push({
      category: CAT,
      severity: "critical",
      message: "Missing Content-Security-Policy",
      explanation:
        "CSP prevents XSS by specifying trusted resource sources. Missing CSP is the single most common cause of high-severity XSS vulnerabilities.",
      suggestion:
        "Add CSP: default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none'",
    });
    return { score: 0, issues, penalties };
  }

  let score = 12;
  const directives = parseCspDirectives(cspValue);
  const defaultSrc = directives.get("default-src");
  const scriptSrc = directives.get("script-src") ?? defaultSrc;
  const objectSrc = directives.get("object-src") ?? defaultSrc;
  const frameAncestors = directives.get("frame-ancestors");

  if (!defaultSrc) {
    score -= 3;
    penalties.push({ category: CAT, message: "CSP missing default-src directive", pointsLost: 3 });
    issues.push({
      category: CAT,
      severity: "warning",
      message: "CSP is missing default-src directive",
      explanation:
        "Without default-src, directives not explicitly set fall back to allow-all, weakening CSP.",
      suggestion: "Add default-src 'none' or default-src 'self' as a safe baseline.",
    });
  } else {
    if (defaultSrc.includes("*")) {
      score -= 2;
      penalties.push({ category: CAT, message: "CSP default-src allows wildcard (*)", pointsLost: 2 });
      issues.push({
        category: CAT,
        severity: "warning",
        message: "CSP default-src allows wildcard (*)",
        explanation: "A wildcard allows resources from any origin, defeating the purpose of CSP.",
        suggestion: "Replace * with explicit trusted origins.",
      });
    }
    if (defaultSrc.includes("data:")) {
      score -= 1;
      penalties.push({ category: CAT, message: "CSP default-src allows data: URIs", pointsLost: 1 });
      issues.push({
        category: CAT,
        severity: "warning",
        message: "CSP default-src includes data: URI scheme",
        explanation: "data: URIs can carry malicious payloads in certain contexts.",
        suggestion: "Remove data: from default-src. Use img-src data: only if needed for images.",
      });
    }
  }

  if (scriptSrc) {
    if (scriptSrc.includes("'unsafe-inline'")) {
      score -= 2;
      penalties.push({ category: CAT, message: "CSP script-src allows 'unsafe-inline'", pointsLost: 2 });
      issues.push({
        category: CAT,
        severity: "warning",
        message: "CSP script-src allows 'unsafe-inline'",
        explanation:
          "'unsafe-inline' permits inline scripts — the primary XSS attack vector. This negates most XSS protection.",
        suggestion:
          "Remove 'unsafe-inline'. Use nonces ('nonce-{random}') or hashes per script block instead.",
      });
    }
    if (scriptSrc.includes("'unsafe-eval'")) {
      score -= 2;
      penalties.push({ category: CAT, message: "CSP script-src allows 'unsafe-eval'", pointsLost: 2 });
      issues.push({
        category: CAT,
        severity: "warning",
        message: "CSP script-src allows 'unsafe-eval'",
        explanation:
          "'unsafe-eval' permits eval() and Function() constructor, enabling dynamic code injection.",
        suggestion: "Remove 'unsafe-eval' and refactor any eval() usage.",
      });
    }
  }

  if (!directives.has("object-src") && !defaultSrc) {
    score -= 1;
    penalties.push({ category: CAT, message: "CSP missing object-src restriction", pointsLost: 1 });
    issues.push({
      category: CAT,
      severity: "warning",
      message: "CSP missing object-src restriction",
      explanation: "Without object-src restriction, Flash and other plugins are unrestricted.",
      suggestion: "Add object-src 'none' to block all plugin content.",
    });
  } else if (objectSrc && objectSrc.includes("*") && !objectSrc.includes("'none'")) {
    score -= 1;
    penalties.push({ category: CAT, message: "CSP object-src is permissive", pointsLost: 1 });
    issues.push({
      category: CAT,
      severity: "warning",
      message: "CSP object-src allows wildcard",
      explanation: "Permissive object-src allows Flash and plugin XSS vectors.",
      suggestion: "Set object-src 'none'.",
    });
  }

  if (!frameAncestors) {
    score -= 1;
    penalties.push({ category: CAT, message: "CSP missing frame-ancestors directive", pointsLost: 1 });
    issues.push({
      category: CAT,
      severity: "warning",
      message: "CSP missing frame-ancestors directive",
      explanation:
        "Without frame-ancestors, your page can be embedded in iframes, enabling clickjacking.",
      suggestion: "Add frame-ancestors 'none' or frame-ancestors 'self' to your CSP.",
    });
  } else if (frameAncestors.includes("*") || frameAncestors.includes("http:")) {
    score -= 1;
    penalties.push({ category: CAT, message: "CSP frame-ancestors is permissive", pointsLost: 1 });
    issues.push({
      category: CAT,
      severity: "warning",
      message: "CSP frame-ancestors allows embedding from any origin",
      explanation: "A wildcard frame-ancestors allows any page to embed yours in an iframe.",
      suggestion: "Set frame-ancestors 'none' (most secure) or 'self'.",
    });
  } else {
    issues.push({
      category: CAT,
      severity: "passed",
      message: "CSP frame-ancestors restricts iframe embedding",
      explanation: "frame-ancestors is set, protecting against clickjacking.",
      suggestion: "Keep frame-ancestors restricted to necessary origins only.",
    });
  }

  const hasNonce = scriptSrc?.some((t) => t.startsWith("'nonce-")) ?? false;
  const hasStrictDynamic = scriptSrc?.includes("'strict-dynamic'") ?? false;
  if (hasNonce || hasStrictDynamic) {
    score = Math.min(12, score + 1);
    issues.push({
      category: CAT,
      severity: "passed",
      message: `CSP uses ${hasNonce ? "nonce-based" : "'strict-dynamic'"} script allowlisting`,
      explanation: "Nonce-based CSP or strict-dynamic is the modern, recommended approach for inline scripts.",
      suggestion: "Continue rotating nonces per request and pair with strict-dynamic for robust XSS protection.",
    });
  }

  issues.push({
    category: CAT,
    severity: "passed",
    message: "Content-Security-Policy header is present",
    explanation: "A CSP header was found. Quality issues are listed above.",
    suggestion: "Use CSP violation reports (report-uri/report-to) to continuously audit your policy.",
  });

  return { score: Math.max(0, score), issues, penalties };
}

export interface HstsAnalysis {
  score: number;
  issues: Issue[];
  penalties: Penalty[];
}

/** Scores HSTS quality 0-9. Exported for tests. */
export function analyzeHsts(hstsValue: string | null, usesHttps: boolean): HstsAnalysis {
  const issues: Issue[] = [];
  const penalties: Penalty[] = [];
  const CAT = "Security Headers";

  if (!hstsValue) {
    if (usesHttps) {
      penalties.push({ category: CAT, message: "Missing Strict-Transport-Security (HSTS)", pointsLost: 9 });
      issues.push({
        category: CAT,
        severity: "critical",
        message: "Missing Strict-Transport-Security (HSTS)",
        explanation:
          "Without HSTS, browsers allow HTTP access even after an HTTPS visit, enabling SSL-stripping attacks.",
        suggestion: "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
      });
    } else {
      issues.push({
        category: CAT,
        severity: "info",
        message: "HSTS not applicable (site uses HTTP — fix HTTPS first)",
        explanation: "HSTS can only be delivered over HTTPS.",
        suggestion: "Enable HTTPS first, then add a strong HSTS header.",
      });
    }
    return { score: 0, issues, penalties };
  }

  let score = 9;
  const lower = hstsValue.toLowerCase();
  const maxAgeMatch = lower.match(/max-age=(\d+)/);
  const maxAge = maxAgeMatch ? parseInt(maxAgeMatch[1], 10) : null;

  if (maxAge === null) {
    score -= 3;
    penalties.push({ category: CAT, message: "HSTS max-age is missing or invalid", pointsLost: 3 });
    issues.push({
      category: CAT,
      severity: "warning",
      message: "HSTS max-age directive is missing or invalid",
      explanation: "HSTS without a valid max-age provides no protection.",
      suggestion: "Set max-age=31536000 (1 year) minimum.",
    });
  } else if (maxAge < 15_768_000) {
    score -= 3;
    penalties.push({
      category: CAT,
      message: `HSTS max-age too short (${maxAge}s, need ≥15,768,000s / 6 months)`,
      pointsLost: 3,
    });
    issues.push({
      category: CAT,
      severity: "warning",
      message: `HSTS max-age is too short (${maxAge}s = ${Math.round(maxAge / 86400)} days)`,
      explanation:
        "A max-age below 6 months (15,768,000s) provides weak protection and prevents HSTS preloading.",
      suggestion: "Set max-age=31536000 (1 year). Required for preload list submission.",
    });
  } else {
    issues.push({
      category: CAT,
      severity: "passed",
      message: `HSTS max-age: ${maxAge.toLocaleString()}s (${Math.round(maxAge / 86400)} days)`,
      explanation: "A sufficiently long max-age protects returning visitors.",
      suggestion: "Maintain max-age at 31536000 or higher.",
    });
  }

  if (!lower.includes("includesubdomains")) {
    score -= 2;
    penalties.push({ category: CAT, message: "HSTS missing includeSubDomains", pointsLost: 2 });
    issues.push({
      category: CAT,
      severity: "warning",
      message: "HSTS missing includeSubDomains",
      explanation:
        "Without includeSubDomains, subdomains are not HSTS-protected, allowing cookie theft via subdomain attacks.",
      suggestion: "Add includeSubDomains to your HSTS header.",
    });
  } else {
    issues.push({
      category: CAT,
      severity: "passed",
      message: "HSTS includeSubDomains is set",
      explanation: "All subdomains are protected by HSTS.",
      suggestion: "Keep includeSubDomains.",
    });
  }

  if (!lower.includes("preload")) {
    score -= 1;
    penalties.push({ category: CAT, message: "HSTS missing preload flag", pointsLost: 1 });
    issues.push({
      category: CAT,
      severity: "info",
      message: "HSTS missing preload flag",
      explanation:
        "The preload flag enables HSTS preload list submission, enforcing HTTPS even on first visit.",
      suggestion:
        "Add preload to HSTS, then submit to hstspreload.org (requires max-age ≥ 1 year + includeSubDomains).",
    });
  } else {
    issues.push({
      category: CAT,
      severity: "passed",
      message: "HSTS preload flag is set",
      explanation: "Domain can be submitted to browser HSTS preload lists.",
      suggestion: "Submit to hstspreload.org if not already done.",
    });
  }

  return { score: Math.max(0, score), issues, penalties };
}

export type CorsSeverity = "none" | "info" | "warn" | "critical";

export interface CorsAnalysis {
  score: number;
  severity: CorsSeverity;
  issues: Issue[];
  penalties: Penalty[];
}

/**
 * Scores CORS configuration 0-10. Full 10 when no CORS headers are set.
 * Exported for unit tests.
 *
 * @param allowOrigin   Access-Control-Allow-Origin value
 * @param allowCredentials Access-Control-Allow-Credentials value
 * @param allowMethods  Access-Control-Allow-Methods value (optional)
 * @param allowHeaders  Access-Control-Allow-Headers value (optional)
 */
export function analyzeCors(
  allowOrigin: string | null,
  allowCredentials: string | null,
  allowMethods?: string | null,
  allowHeaders?: string | null,
): CorsAnalysis {
  const issues: Issue[] = [];
  const penalties: Penalty[] = [];
  const CAT = "CORS";
  let score = 10;
  let severity: CorsSeverity = "none";

  if (!allowOrigin) {
    issues.push({
      category: CAT,
      severity: "passed",
      message: "No CORS headers — cross-origin access not enabled",
      explanation: "This endpoint does not serve CORS headers. Cross-origin access is restricted by default.",
      suggestion: "If a public API, add explicit CORS headers. If HTML page, this is expected.",
    });
    return { score: 10, severity: "none", issues, penalties };
  }

  const credentialsEnabled = allowCredentials?.toLowerCase() === "true";
  const isWildcard = allowOrigin.trim() === "*";

  if (isWildcard && credentialsEnabled) {
    score -= 8;
    severity = "critical";
    penalties.push({ category: CAT, message: "CORS wildcard origin combined with credentials=true (critical misconfiguration)", pointsLost: 8 });
    issues.push({
      category: CAT,
      severity: "critical",
      message: "CORS: Access-Control-Allow-Origin: * combined with Allow-Credentials: true",
      explanation:
        "Browsers block ACAO: * with credentials, but this config shows the server is permissively misconfigured. Non-browser HTTP clients can exploit this to read authenticated responses from any origin.",
      suggestion:
        "Never combine ACAO: * with credentials. Set an explicit trusted origin list when using Allow-Credentials: true.",
    });
  } else if (isWildcard) {
    score -= 4;
    severity = "warn";
    penalties.push({ category: CAT, message: "CORS Access-Control-Allow-Origin: * (any origin can read responses)", pointsLost: 4 });
    issues.push({
      category: CAT,
      severity: "warning",
      message: "CORS allows all origins (Access-Control-Allow-Origin: *)",
      explanation:
        "Any website can read this endpoint's responses. Acceptable for fully public read-only APIs, but dangerous if this endpoint serves sensitive data or is behind authentication.",
      suggestion: "Restrict CORS to specific trusted origins unless this endpoint intentionally serves public data.",
    });
  } else if (credentialsEnabled) {
    issues.push({
      category: CAT,
      severity: "passed",
      message: `CORS credentials scoped to specific origin: ${allowOrigin}`,
      explanation: "Credentialed CORS is correctly restricted to a specific trusted origin.",
      suggestion: "Ensure the allowed origin is intentionally trusted and review periodically.",
    });
  } else {
    issues.push({
      category: CAT,
      severity: "passed",
      message: `CORS restricted to specific origin: ${allowOrigin}`,
      explanation: "CORS is appropriately scoped to a specific origin.",
      suggestion: "Verify the origin list is minimal — include only what you need.",
    });
  }

  if (isWildcard && allowMethods) {
    const upper = allowMethods.toUpperCase();
    const dangerousMethods = ["DELETE", "PUT", "PATCH"];
    const found = dangerousMethods.filter((m) => upper.includes(m));
    if (found.length > 0) {
      score -= 2;
      if (severity === "none") severity = "warn";
      penalties.push({ category: CAT, message: `CORS allows ${found.join("/")} from wildcard origin`, pointsLost: 2 });
      issues.push({
        category: CAT,
        severity: "warning",
        message: `CORS wildcard origin allows state-changing methods: ${found.join(", ")}`,
        explanation: `Allowing ${found.join("/")} cross-origin from any origin (ACAO: *) enables any website to modify your resources.`,
        suggestion: "Restrict mutating HTTP methods (DELETE, PUT, PATCH) to specific trusted origins.",
      });
    }
  }

  if (isWildcard && allowHeaders) {
    const lower = allowHeaders.toLowerCase();
    const sensitiveHeaders = ["authorization", "cookie", "x-auth-token", "x-api-key"];
    const found = sensitiveHeaders.filter((h) => lower.includes(h));
    if (found.length > 0) {
      score -= 1;
      if (severity === "none") severity = "warn";
      penalties.push({ category: CAT, message: `CORS allows sensitive request headers from wildcard origin`, pointsLost: 1 });
      issues.push({
        category: CAT,
        severity: "warning",
        message: `CORS allows sensitive headers (${found.join(", ")}) from any origin`,
        explanation: "Allowing authentication headers in CORS requests from a wildcard origin enables credential forwarding from any website.",
        suggestion: "Restrict CORS to specific origins whenever authentication headers are involved.",
      });
    }
  }

  return { score: Math.max(0, score), severity, issues, penalties };
}

/**
 * Parses Set-Cookie header lines into structured ParsedCookie objects.
 * Exported for unit tests.
 */
export function parseSetCookieHeaders(setCookieLines: string[]): ParsedCookie[] {
  return setCookieLines.map((line) => {
    const parts = line.split(";").map((p) => p.trim());
    const namePart = parts[0] ?? "";
    const eqIdx = namePart.indexOf("=");
    const name = eqIdx >= 0 ? namePart.slice(0, eqIdx).trim() : namePart;

    let hasSecure = false;
    let hasHttpOnly = false;
    let sameSite: ParsedCookie["sameSite"] = null;
    let domain: string | null = null;
    let maxAge: number | null = null;
    let path: string | null = null;

    for (let i = 1; i < parts.length; i++) {
      const lower = parts[i].toLowerCase();
      if (lower === "secure") {
        hasSecure = true;
      } else if (lower === "httponly") {
        hasHttpOnly = true;
      } else if (lower.startsWith("samesite=")) {
        const val = lower.slice("samesite=".length).trim();
        if (val === "strict" || val === "lax" || val === "none") sameSite = val;
      } else if (lower.startsWith("domain=")) {
        domain = parts[i].slice("domain=".length).trim().toLowerCase().replace(/^\./, "");
      } else if (lower.startsWith("max-age=")) {
        const parsed = parseInt(parts[i].slice("max-age=".length).trim(), 10);
        if (!isNaN(parsed)) maxAge = parsed;
      } else if (lower.startsWith("path=")) {
        path = parts[i].slice("path=".length).trim();
      }
    }

    return { name, hasSecure, hasHttpOnly, sameSite, domain, maxAge, path };
  });
}

/**
 * Linear penalty curve: 0 below freeThreshold, maxPenalty at/above fullPenaltyAt.
 * Exported for unit tests.
 */
export function penaltyCurve(
  value: number,
  freeThreshold: number,
  maxPenalty: number,
  fullPenaltyAt: number,
): number {
  if (value <= freeThreshold) return 0;
  if (value >= fullPenaltyAt) return maxPenalty;
  const ratio = (value - freeThreshold) / (fullPenaltyAt - freeThreshold);
  return Math.round(ratio * maxPenalty * 100) / 100;
}

// ================================================================
// Internal Scoring Functions
// ================================================================

function scoreXFrameOptions(value: string | null): { score: number; issues: Issue[]; penalties: Penalty[] } {
  const issues: Issue[] = [];
  const penalties: Penalty[] = [];
  const CAT = "Security Headers";

  if (!value) {
    penalties.push({ category: CAT, message: "Missing X-Frame-Options", pointsLost: 4 });
    issues.push({
      category: CAT,
      severity: "warning",
      message: "Missing X-Frame-Options",
      explanation:
        "Without this header, your page can be embedded in iframes, enabling clickjacking where users interact with an invisible overlay.",
      suggestion: "Add X-Frame-Options: DENY. Also set CSP frame-ancestors 'none' for modern browsers.",
    });
    return { score: 0, issues, penalties };
  }
  const upper = value.toUpperCase().trim();
  if (upper === "DENY" || upper === "SAMEORIGIN") {
    issues.push({
      category: CAT,
      severity: "passed",
      message: `X-Frame-Options: ${upper}`,
      explanation: "Clickjacking is prevented by restricting iframe embedding.",
      suggestion: "Also add CSP frame-ancestors for defence-in-depth.",
    });
    return { score: 4, issues, penalties };
  }
  penalties.push({ category: CAT, message: `X-Frame-Options: "${value}" is not DENY or SAMEORIGIN`, pointsLost: 2 });
  issues.push({
    category: CAT,
    severity: "warning",
    message: `X-Frame-Options: "${value}" — not DENY or SAMEORIGIN`,
    explanation: "ALLOW-FROM is deprecated and unsupported in modern browsers. Only DENY and SAMEORIGIN work reliably.",
    suggestion: "Use X-Frame-Options: DENY (recommended) or SAMEORIGIN.",
  });
  return { score: 2, issues, penalties };
}

function scoreReferrerPolicy(value: string | null): { score: number; issues: Issue[]; penalties: Penalty[] } {
  const issues: Issue[] = [];
  const penalties: Penalty[] = [];
  const CAT = "Security Headers";
  if (!value) {
    penalties.push({ category: CAT, message: "Missing Referrer-Policy", pointsLost: 2 });
    issues.push({
      category: CAT,
      severity: "warning",
      message: "Missing Referrer-Policy",
      explanation:
        "Without this header, browsers may send full URLs (including tokens in query strings) as the Referer to third-party sites.",
      suggestion: "Add Referrer-Policy: strict-origin-when-cross-origin",
    });
    return { score: 0, issues, penalties };
  }
  const lower = value.toLowerCase().trim();
  const STRONG = new Set(["no-referrer", "strict-origin", "strict-origin-when-cross-origin", "same-origin", "origin"]);
  const WEAK = new Set(["unsafe-url", "no-referrer-when-downgrade", ""]);
  if (WEAK.has(lower)) {
    penalties.push({ category: CAT, message: `Referrer-Policy "${lower}" leaks full URL cross-origin`, pointsLost: 1 });
    issues.push({
      category: CAT,
      severity: "warning",
      message: `Referrer-Policy "${lower}" leaks full URL to third parties`,
      explanation: `"${lower}" sends the full URL including path and query string on cross-origin requests, potentially exposing tokens or PII.`,
      suggestion: "Use Referrer-Policy: strict-origin-when-cross-origin (OWASP recommended default).",
    });
    return { score: 1, issues, penalties };
  }
  if (STRONG.has(lower)) {
    issues.push({
      category: CAT,
      severity: "passed",
      message: `Referrer-Policy: ${lower}`,
      explanation: "Referrer-Policy is set to a privacy-preserving value.",
      suggestion: "strict-origin-when-cross-origin is the recommended default.",
    });
    return { score: 2, issues, penalties };
  }
  issues.push({
    category: CAT,
    severity: "info",
    message: `Referrer-Policy: ${lower}`,
    explanation: "Referrer-Policy is present. Verify this value meets your privacy requirements.",
    suggestion: "Consider strict-origin-when-cross-origin for the best balance.",
  });
  return { score: 1.5, issues, penalties };
}

function scorePermissionsPolicy(value: string | null): { score: number; issues: Issue[]; penalties: Penalty[] } {
  const issues: Issue[] = [];
  const penalties: Penalty[] = [];
  const CAT = "Security Headers";
  if (!value) {
    penalties.push({ category: CAT, message: "Missing Permissions-Policy", pointsLost: 2 });
    issues.push({
      category: CAT,
      severity: "warning",
      message: "Missing Permissions-Policy",
      explanation:
        "Without Permissions-Policy, embedded third-party scripts can access camera, microphone, geolocation, and payment APIs.",
      suggestion: "Add Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=()",
    });
    return { score: 0, issues, penalties };
  }
  issues.push({
    category: CAT,
    severity: "passed",
    message: "Permissions-Policy header is present",
    explanation: "Browser feature access is explicitly controlled.",
    suggestion: "Review values — ensure camera=(), microphone=(), geolocation=() and payment=() are restricted.",
  });
  return { score: 2, issues, penalties };
}

function scoreCoopCoepCorp(headers: Headers): { score: number; issues: Issue[]; penalties: Penalty[] } {
  const issues: Issue[] = [];
  const penalties: Penalty[] = [];
  const CAT = "Security Headers";
  let score = 0;

  const checks = [
    { key: "cross-origin-opener-policy", name: "COOP", pts: 0.4,
      passExplanation: "COOP isolates your browsing context, protecting against cross-origin window attacks.",
      failExplanation: "Without COOP, malicious cross-origin popups can maintain a reference to your window.",
      suggestion: "Add Cross-Origin-Opener-Policy: same-origin" },
    { key: "cross-origin-embedder-policy", name: "COEP", pts: 0.4,
      passExplanation: "COEP ensures all sub-resources use CORS/CORP, enabling secure cross-origin isolation.",
      failExplanation: "COEP is required for SharedArrayBuffer and precise timers.",
      suggestion: "Add Cross-Origin-Embedder-Policy: require-corp" },
    { key: "cross-origin-resource-policy", name: "CORP", pts: 0.2,
      passExplanation: "CORP prevents other origins from loading this resource, mitigating Spectre-type attacks.",
      failExplanation: "Without CORP, your resources can be loaded by any origin via side-channel attacks.",
      suggestion: "Add Cross-Origin-Resource-Policy: same-origin" },
  ];

  for (const check of checks) {
    const val = headers.get(check.key);
    if (val) {
      score += check.pts;
      issues.push({ category: CAT, severity: "passed",
        message: `${check.key.toUpperCase().replace(/-/g, "-")}: ${val}`,
        explanation: check.passExplanation, suggestion: "Keep this header set." });
    } else {
      penalties.push({ category: CAT, message: `Missing ${check.key} (${check.name})`, pointsLost: check.pts });
      issues.push({ category: CAT, severity: "warning",
        message: `Missing ${check.key} (${check.name})`,
        explanation: check.failExplanation, suggestion: check.suggestion });
    }
  }

  return { score: Math.round(score * 10) / 10, issues, penalties };
}

function scoreCookies(
  cookies: ParsedCookie[],
  finalUrl: string,
): { score: number; issues: Issue[]; penalties: Penalty[]; cookieIssueStrings: string[] } {
  const issues: Issue[] = [];
  const penalties: Penalty[] = [];
  const cookieIssueStrings: string[] = [];
  const CAT = "Cookies & Session";

  if (cookies.length === 0) {
    issues.push({
      category: CAT, severity: "passed",
      message: "No cookies set on initial page load",
      explanation: "No Set-Cookie headers were found in the response.",
      suggestion: "When you add cookies, set Secure, HttpOnly, and SameSite=Lax on all of them.",
    });
    return { score: 10, issues, penalties, cookieIssueStrings };
  }

  let deduction = 0;

  // Privacy posture: penalize many cookies on first load (3 or fewer is the free threshold)
  const COOKIE_FREE_THRESHOLD = 3;
  if (cookies.length > COOKIE_FREE_THRESHOLD) {
    const extra = cookies.length - COOKIE_FREE_THRESHOLD;
    const pts = Math.min(3, extra);
    deduction += pts;
    penalties.push({ category: CAT, message: `${cookies.length} cookies set on initial load (${extra} above privacy threshold)`, pointsLost: pts });
    cookieIssueStrings.push(`${cookies.length} cookies set on initial page load — consider deferring non-essential cookies`);
    issues.push({ category: CAT, severity: "warning",
      message: `${cookies.length} cookies set on initial page load`,
      explanation: `Setting ${cookies.length} cookies on first load increases tracking surface. GDPR/CCPA may require consent before non-essential cookies.`,
      suggestion: "Defer analytics/marketing cookies until user consent. Limit initial load to strictly necessary cookies." });
  }
  let finalHost = "";
  try { finalHost = new URL(finalUrl).hostname; } catch { /* ignore */ }

  for (const cookie of cookies) {
    const n = `"${cookie.name}"`;

    if (!cookie.hasSecure) {
      const pts = 6;
      deduction += pts;
      penalties.push({ category: CAT, message: `Cookie ${n} missing Secure flag`, pointsLost: pts });
      cookieIssueStrings.push(`Cookie ${n} is missing Secure flag`);
      issues.push({ category: CAT, severity: "critical",
        message: `Cookie ${n} missing Secure flag`,
        explanation: "Cookies without Secure can be sent over HTTP, exposing them to network eavesdropping.",
        suggestion: `Set-Cookie: ${cookie.name}=...; Secure; HttpOnly; SameSite=Lax` });
    }

    if (cookie.sameSite === "none" && !cookie.hasSecure) {
      const pts = 5;
      deduction += pts;
      penalties.push({ category: CAT, message: `Cookie ${n}: SameSite=None requires Secure (rejected by browsers)`, pointsLost: pts });
      cookieIssueStrings.push(`Cookie ${n}: SameSite=None without Secure — browsers will reject this cookie`);
      issues.push({ category: CAT, severity: "critical",
        message: `Cookie ${n}: SameSite=None without Secure`,
        explanation: "Modern browsers reject SameSite=None cookies that lack Secure, making the cookie non-functional.",
        suggestion: "Add Secure flag when using SameSite=None." });
    }

    if (!cookie.hasHttpOnly) {
      const pts = 3;
      deduction += pts;
      penalties.push({ category: CAT, message: `Cookie ${n} missing HttpOnly flag`, pointsLost: pts });
      cookieIssueStrings.push(`Cookie ${n} is missing HttpOnly flag`);
      issues.push({ category: CAT, severity: "warning",
        message: `Cookie ${n} missing HttpOnly flag`,
        explanation: "Cookies without HttpOnly are accessible via document.cookie, making them vulnerable to XSS theft.",
        suggestion: `Add HttpOnly to cookie ${n}.` });
    }

    if (cookie.sameSite === null) {
      const pts = 2;
      deduction += pts;
      penalties.push({ category: CAT, message: `Cookie ${n} missing SameSite attribute`, pointsLost: pts });
      cookieIssueStrings.push(`Cookie ${n} is missing SameSite attribute`);
      issues.push({ category: CAT, severity: "warning",
        message: `Cookie ${n} missing SameSite attribute`,
        explanation: "Without SameSite, the cookie is sent on all cross-site requests, enabling CSRF attacks.",
        suggestion: `Add SameSite=Lax (or Strict for sensitive session cookies) to cookie ${n}.` });
    }

    if (cookie.domain && finalHost) {
      const cookieDomain = cookie.domain.replace(/^\./, "");
      if (
        finalHost !== cookieDomain &&
        finalHost.endsWith("." + cookieDomain) &&
        cookieDomain.split(".").length <= 2
      ) {
        const pts = 2;
        deduction += pts;
        penalties.push({ category: CAT, message: `Cookie ${n} domain "${cookie.domain}" is overly broad`, pointsLost: pts });
        cookieIssueStrings.push(`Cookie ${n} domain "${cookie.domain}" is overly broad`);
        issues.push({ category: CAT, severity: "warning",
          message: `Cookie ${n} has overly broad domain "${cookie.domain}"`,
          explanation: "A broad domain attribute shares the cookie with all subdomains, increasing theft risk via a compromised subdomain.",
          suggestion: "Omit the Domain attribute to scope the cookie to the exact host." });
      }
    }

    if (cookie.maxAge !== null && cookie.maxAge > 365 * 24 * 3600) {
      const pts = 1;
      deduction += pts;
      penalties.push({ category: CAT, message: `Cookie ${n} has very long Max-Age (${Math.round(cookie.maxAge / 86400)} days)`, pointsLost: pts });
      cookieIssueStrings.push(`Cookie ${n} has very long Max-Age (${Math.round(cookie.maxAge / 86400)} days)`);
      issues.push({ category: CAT, severity: "warning",
        message: `Cookie ${n} Max-Age: ${Math.round(cookie.maxAge / 86400)} days`,
        explanation: "Persistent session cookies with long lifetimes extend the window for stolen-cookie exploitation.",
        suggestion: "Use shorter Max-Age for session cookies. Prefer session cookies (no Max-Age) for authentication." });
    }

    if (cookie.hasSecure && cookie.hasHttpOnly && cookie.sameSite !== null && cookie.sameSite !== "none") {
      issues.push({ category: CAT, severity: "passed",
        message: `Cookie ${n} has all security attributes (Secure, HttpOnly, SameSite=${cookie.sameSite})`,
        explanation: "This cookie is properly secured.",
        suggestion: "Keep this configuration." });
    }
  }

  return { score: Math.max(0, 10 - deduction), issues, penalties, cookieIssueStrings };
}

function scoreCacheHygiene(
  headers: Headers,
  apiExposure: { issues: string[] },
  hasCookies: boolean,
): { score: number; issues: Issue[]; penalties: Penalty[] } {
  const issues: Issue[] = [];
  const penalties: Penalty[] = [];
  const CAT = "Cache & Exposure";
  let score = 5;

  const server = headers.get("server");
  const xPoweredBy = headers.get("x-powered-by");
  const cacheControl = headers.get("cache-control");

  if (server) {
    const revealing = /apache\/[\d.]+|nginx\/[\d.]+|iis\/[\d.]+|php\/[\d.]+|express/i.test(server);
    if (revealing) {
      score -= 1;
      penalties.push({ category: CAT, message: `Server header reveals software version (${server})`, pointsLost: 1 });
      issues.push({ category: CAT, severity: "warning",
        message: `Server header reveals software version: "${server}"`,
        explanation: "Exposing server name and version lets attackers target known CVEs for that exact version.",
        suggestion: "Configure your web server to suppress or anonymize the Server header." });
    } else {
      issues.push({ category: CAT, severity: "info",
        message: `Server header present (${server})`,
        explanation: "The server identifies itself without revealing a specific version.",
        suggestion: "Consider removing the Server header entirely for defence-in-depth." });
    }
  }

  if (xPoweredBy) {
    score -= 1;
    penalties.push({ category: CAT, message: `X-Powered-By exposes framework: ${xPoweredBy}`, pointsLost: 1 });
    issues.push({ category: CAT, severity: "warning",
      message: `X-Powered-By: "${xPoweredBy}" exposes framework`,
      explanation: "X-Powered-By tells attackers which framework or language you use, enabling targeted exploits.",
      suggestion: "Remove X-Powered-By. In Express: app.disable('x-powered-by'). In PHP: expose_php = Off in php.ini." });
  }

  if (hasCookies) {
    if (!cacheControl) {
      score -= 1;
      penalties.push({ category: CAT, message: "No Cache-Control on response that sets cookies", pointsLost: 1 });
      issues.push({ category: CAT, severity: "warning",
        message: "Missing Cache-Control on page that sets cookies",
        explanation: "Without cache headers, CDNs or shared proxies may cache authenticated responses and serve them to other users.",
        suggestion: "Add Cache-Control: no-store, private to all pages that set cookies." });
    } else if (
      !cacheControl.includes("no-store") &&
      !cacheControl.includes("private") &&
      !cacheControl.includes("no-cache")
    ) {
      score -= 1;
      penalties.push({ category: CAT, message: "Cache-Control may allow caching of cookie-bearing response", pointsLost: 1 });
      issues.push({ category: CAT, severity: "warning",
        message: `Cache-Control: "${cacheControl}" may cache authenticated pages`,
        explanation: "This Cache-Control value on a page with Set-Cookie may allow proxies to cache and replay authenticated sessions.",
        suggestion: "Add no-store or private to Cache-Control for pages that set cookies." });
    } else {
      issues.push({ category: CAT, severity: "passed",
        message: `Cache-Control: ${cacheControl} (correctly prevents caching of cookie-bearing response)`,
        explanation: "Cache control prevents authenticated page caching.",
        suggestion: "Keep this configuration." });
    }
  }

  if (apiExposure.issues.length > 0) {
    for (const issue of apiExposure.issues) {
      score -= 1;
      penalties.push({ category: CAT, message: issue, pointsLost: 1 });
      issues.push({ category: CAT, severity: "warning",
        message: issue,
        explanation: "Exposing API documentation or health endpoints publicly aids attacker reconnaissance.",
        suggestion: "Restrict /docs, /swagger, /openapi.json to authenticated users or internal networks." });
    }
  } else {
    issues.push({ category: CAT, severity: "passed",
      message: "No sensitive API documentation or health endpoints exposed",
      explanation: "No publicly accessible API docs or sensitive paths were found.",
      suggestion: "Continue restricting internal endpoints in production." });
  }

  return { score: Math.max(0, score), issues, penalties };
}

function scorePerformance(
  responseTimeMs: number,
  htmlSizeKb: number,
  scriptTagCount: number,
  cacheControl: string | null,
): { score: number; issues: Issue[]; penalties: Penalty[] } {
  const issues: Issue[] = [];
  const penalties: Penalty[] = [];
  const CAT = "Performance";

  const hasStrongCache =
    !!cacheControl &&
    (cacheControl.includes("max-age") || cacheControl.includes("s-maxage")) &&
    !cacheControl.includes("no-store") &&
    !cacheControl.includes("no-cache");
  const cacheMultiplier = hasStrongCache ? 0.8 : 1.0;

  const timePenalty = Math.round(penaltyCurve(responseTimeMs, 300, 3, 2000) * cacheMultiplier * 100) / 100;
  const sizePenalty = Math.round(penaltyCurve(htmlSizeKb, 250, 2, 2048) * cacheMultiplier * 100) / 100;
  const scriptPenalty = Math.round(penaltyCurve(scriptTagCount, 10, 3, 60) * cacheMultiplier * 100) / 100;
  const score = Math.max(0, Math.round((8 - timePenalty - sizePenalty - scriptPenalty) * 10) / 10);

  if (timePenalty === 0) {
    issues.push({ category: CAT, severity: "passed",
      message: `Response time: ${Math.round(responseTimeMs)}ms (excellent)`,
      explanation: "Server responds in under 300ms — meets Google's TTFB target.",
      suggestion: "Maintain fast response times with caching and optimized queries." });
  } else {
    if (timePenalty >= 3) {
      penalties.push({ category: CAT, message: `Slow response time (${Math.round(responseTimeMs)}ms)`, pointsLost: timePenalty });
    }
    issues.push({ category: CAT, severity: timePenalty >= 3 ? "warning" : "info",
      message: `Response time: ${Math.round(responseTimeMs)}ms (−${timePenalty} pts)`,
      explanation: `Response is ${Math.round(responseTimeMs)}ms. Google Core Web Vitals targets TTFB < 800ms.`,
      suggestion: "Add response caching, use a CDN, or optimize server-side processing." });
  }

  if (sizePenalty === 0) {
    issues.push({ category: CAT, severity: "passed",
      message: `HTML size: ${htmlSizeKb.toFixed(1)}KB (lean)`,
      explanation: "Small HTML payload parses fast, improving Time to Interactive.",
      suggestion: "Keep HTML lean — lazy load images and defer non-critical scripts." });
  } else {
    if (sizePenalty >= 2) {
      penalties.push({ category: CAT, message: `Large HTML payload (${htmlSizeKb.toFixed(1)}KB)`, pointsLost: sizePenalty });
    }
    issues.push({ category: CAT, severity: sizePenalty >= 2 ? "warning" : "info",
      message: `HTML size: ${htmlSizeKb.toFixed(1)}KB (−${sizePenalty} pts)`,
      explanation: "Large HTML documents slow parsing, especially on mobile and low-bandwidth connections.",
      suggestion: "Remove unnecessary markup, inline styles, and comments. Consider server-side rendering only essential content." });
  }

  if (scriptPenalty === 0) {
    issues.push({ category: CAT, severity: "passed",
      message: `${scriptTagCount} external script(s) — within threshold`,
      explanation: "Few external scripts minimize render-blocking requests.",
      suggestion: "Bundle scripts where possible to reduce HTTP requests." });
  } else {
    if (scriptPenalty >= 2) {
      penalties.push({ category: CAT, message: `High external script count (${scriptTagCount})`, pointsLost: scriptPenalty });
    }
    issues.push({ category: CAT, severity: scriptPenalty >= 2 ? "warning" : "info",
      message: `${scriptTagCount} external scripts (−${scriptPenalty} pts)`,
      explanation: "Each external script requires a network round-trip. High counts significantly delay page load.",
      suggestion: "Bundle scripts. Use async/defer attributes. Evaluate if all third-party scripts are necessary." });
  }

  if (hasStrongCache) {
    issues.push({ category: CAT, severity: "passed",
      message: "Strong caching detected — performance penalties reduced 20%",
      explanation: "Cache-Control with max-age means repeat visitors get cached assets, reducing load.",
      suggestion: "Continue using Cache-Control with appropriate max-age values for static assets." });
  }

  return { score, issues, penalties };
}

function scoreSeo(
  root: ReturnType<typeof parseHtml>,
  finalUrl: string,
  hasRobotsTxt: boolean,
  hasSitemapXml: boolean,
): {
  score: number;
  issues: Issue[];
  penalties: Penalty[];
  title: string | null;
  metaDescription: string | null;
  hasViewport: boolean;
  hasOpenGraph: boolean;
  canonicalUrl: string | null;
  hasStructuredData: boolean;
  hasNoindex: boolean;
} {
  const issues: Issue[] = [];
  const penalties: Penalty[] = [];
  const CAT = "SEO";
  let score = 0;

  // Title (3pts)
  const titleEl = root.querySelector("title");
  const title = titleEl?.text?.trim() ?? null;
  if (!title) {
    penalties.push({ category: CAT, message: "Missing <title> tag", pointsLost: 3 });
    issues.push({ category: CAT, severity: "critical",
      message: "Missing title tag",
      explanation: "<title> is a primary ranking signal and appears as the clickable headline in search results.",
      suggestion: "Add a descriptive <title> tag inside <head>." });
  } else if (title.length < 10 || title.length > 70) {
    score += 1.5;
    penalties.push({ category: CAT, message: `Title tag is ${title.length} chars (optimal: 10–70)`, pointsLost: 1.5 });
    issues.push({ category: CAT, severity: "warning",
      message: `Title tag is ${title.length < 10 ? "too short" : "too long"} (${title.length} chars)`,
      explanation: `"${title.slice(0, 60)}" — Google shows ~50–60 chars in SERPs.`,
      suggestion: "Keep title between 10 and 60 characters for best SERP display." });
  } else {
    score += 3;
    issues.push({ category: CAT, severity: "passed",
      message: `Title tag well-formed (${title.length} chars)`,
      explanation: `"${title.slice(0, 60)}" is within the optimal range.`,
      suggestion: "Keep your title descriptive and around 50–60 characters." });
  }

  // Meta description (1.5pts)
  const metaDescEl = root.querySelector('meta[name="description"]');
  const metaDescription = metaDescEl?.getAttribute("content")?.trim() ?? null;
  if (!metaDescription) {
    penalties.push({ category: CAT, message: "Missing meta description", pointsLost: 1.5 });
    issues.push({ category: CAT, severity: "warning",
      message: "Missing meta description",
      explanation: "Without a meta description, search engines generate a poor excerpt automatically.",
      suggestion: 'Add <meta name="description" content="120–160 char description">.' });
  } else if (metaDescription.length < 50 || metaDescription.length > 160) {
    score += 0.75;
    penalties.push({ category: CAT, message: `Meta description ${metaDescription.length} chars (optimal: 50–160)`, pointsLost: 0.75 });
    issues.push({ category: CAT, severity: "warning",
      message: `Meta description length: ${metaDescription.length} chars`,
      explanation: "Outside the 50–160 character optimal range for SERP snippets.",
      suggestion: "Aim for 120–160 characters for best search snippet display." });
  } else {
    score += 1.5;
    issues.push({ category: CAT, severity: "passed",
      message: `Meta description well-formed (${metaDescription.length} chars)`,
      explanation: "Meta description is within the optimal range.",
      suggestion: "Keep descriptions between 120–160 characters." });
  }

  // Viewport (0.5pts)
  const hasViewport = !!root.querySelector('meta[name="viewport"]');
  if (hasViewport) {
    score += 0.5;
    issues.push({ category: CAT, severity: "passed",
      message: "Viewport meta tag present",
      explanation: "Ensures correct rendering on mobile devices — required for mobile-first indexing.",
      suggestion: 'Keep: <meta name="viewport" content="width=device-width, initial-scale=1">' });
  } else {
    penalties.push({ category: CAT, message: "Missing viewport meta tag", pointsLost: 0.5 });
    issues.push({ category: CAT, severity: "warning",
      message: "Missing viewport meta tag",
      explanation: "Without viewport, your page appears zoomed out on mobile, harming UX and mobile search ranking.",
      suggestion: 'Add <meta name="viewport" content="width=device-width, initial-scale=1"> to <head>.' });
  }

  // Canonical (0.5pts)
  const canonicalEl = root.querySelector('link[rel="canonical"]');
  const canonicalUrl = canonicalEl?.getAttribute("href")?.trim() ?? null;
  if (canonicalUrl) {
    try {
      const canonHost = new URL(canonicalUrl).hostname;
      const finalHost = new URL(finalUrl).hostname;
      if (canonHost === finalHost) {
        score += 0.5;
        issues.push({ category: CAT, severity: "passed",
          message: "Canonical URL is present and matches host",
          explanation: "The canonical element signals the preferred URL to search engines.",
          suggestion: "Ensure canonicals always point to the exact URL you want indexed." });
      } else {
        penalties.push({ category: CAT, message: `Canonical host mismatch: "${canonHost}" vs "${finalHost}"`, pointsLost: 0.5 });
        issues.push({ category: CAT, severity: "warning",
          message: `Canonical URL host mismatch (${canonHost} ≠ ${finalHost})`,
          explanation: "A canonical pointing to a different host confuses search engines about the authoritative URL.",
          suggestion: "Ensure the canonical URL matches the actual domain of the page." });
      }
    } catch {
      score += 0.5;
    }
  } else {
    issues.push({ category: CAT, severity: "info",
      message: "No canonical link element found",
      explanation: "Without canonical, search engines may index multiple URL variants as separate pages.",
      suggestion: 'Add <link rel="canonical" href="https://yourdomain.com/page"> to <head>.' });
  }

  // Noindex (penalty)
  const robotsMeta = root.querySelector('meta[name="robots"]');
  const robotsContent = robotsMeta?.getAttribute("content")?.toLowerCase() ?? "";
  const hasNoindex = robotsContent.includes("noindex");
  if (hasNoindex) {
    score = Math.max(0, score - 0.5);
    penalties.push({ category: CAT, message: "Page has meta robots noindex — search engines will not index it", pointsLost: 0.5 });
    issues.push({ category: CAT, severity: "warning",
      message: "Page has meta robots noindex directive",
      explanation: "This page will not appear in search results. Critical if this page should be indexed at launch.",
      suggestion: 'Remove noindex from <meta name="robots"> before going live.' });
  }

  // Structured data
  const ldJsonScripts = root.querySelectorAll('script[type="application/ld+json"]');
  const hasStructuredData = ldJsonScripts.length > 0;
  if (hasStructuredData) {
    issues.push({ category: CAT, severity: "passed",
      message: `JSON-LD structured data found (${ldJsonScripts.length} block${ldJsonScripts.length > 1 ? "s" : ""})`,
      explanation: "Structured data enables rich results in Google Search (star ratings, breadcrumbs, FAQs).",
      suggestion: "Validate with Google's Rich Results Test: https://search.google.com/test/rich-results" });
  } else {
    issues.push({ category: CAT, severity: "info",
      message: "No JSON-LD structured data found",
      explanation: "Structured data unlocks rich SERP features that improve click-through rate.",
      suggestion: "Add Schema.org JSON-LD for your page type (WebSite, Article, Product, etc.)." });
  }

  // Open Graph
  const hasOpenGraph = !!root.querySelector('meta[property="og:title"]');
  if (hasOpenGraph) {
    issues.push({ category: CAT, severity: "passed",
      message: "Open Graph tags present",
      explanation: "OG tags control how your page appears when shared on social media.",
      suggestion: "Ensure og:title, og:description, og:image, and og:url are all set." });
  } else {
    issues.push({ category: CAT, severity: "info",
      message: "Open Graph tags not found",
      explanation: "Without OG tags, social platforms may display your page with a poor preview.",
      suggestion: "Add og:title, og:description, og:image, og:url meta tags." });
  }

  // Robots.txt (0.5pts)
  if (hasRobotsTxt) {
    score += 0.5;
    issues.push({ category: CAT, severity: "passed",
      message: "robots.txt is present",
      explanation: "robots.txt directs crawlers on which paths to index.",
      suggestion: "Include Sitemap: directive in robots.txt pointing to your sitemap." });
  } else {
    penalties.push({ category: CAT, message: "robots.txt not found", pointsLost: 0.5 });
    issues.push({ category: CAT, severity: "warning",
      message: "robots.txt not found",
      explanation: "Without robots.txt, search engine crawlers have no guidance on indexing.",
      suggestion: "Create /robots.txt with at minimum: User-agent: *\\nAllow: /" });
  }

  // Sitemap (0.5pts)
  if (hasSitemapXml) {
    score += 0.5;
    issues.push({ category: CAT, severity: "passed",
      message: "sitemap.xml is present",
      explanation: "A sitemap accelerates search engine discovery of all your pages.",
      suggestion: "Keep your sitemap updated and reference it in robots.txt." });
  } else {
    issues.push({ category: CAT, severity: "info",
      message: "sitemap.xml not found",
      explanation: "A sitemap helps search engines find all pages, especially important for larger sites.",
      suggestion: "Generate sitemap.xml and add Sitemap: https://yourdomain.com/sitemap.xml to robots.txt." });
  }

  return {
    score: Math.min(7, Math.max(0, Math.round(score * 10) / 10)),
    issues, penalties, title, metaDescription, hasViewport, hasOpenGraph,
    canonicalUrl, hasStructuredData, hasNoindex,
  };
}

function scoreAccessibility(root: ReturnType<typeof parseHtml>): {
  score: number;
  issues: Issue[];
  penalties: Penalty[];
} {
  const issues: Issue[] = [];
  const penalties: Penalty[] = [];
  const CAT = "Accessibility";
  let score = 5;

  // Inputs without accessible labels (2pts)
  const inputs = root.querySelectorAll(
    'input:not([type="hidden"]):not([type="submit"]):not([type="button"]):not([type="image"]):not([type="reset"])',
  );
  if (inputs.length > 0) {
    const labelledIds = new Set<string>();
    for (const label of root.querySelectorAll("label[for]")) {
      const f = label.getAttribute("for");
      if (f) labelledIds.add(f);
    }
    const unlabelled = inputs.filter((inp) => {
      const id = inp.getAttribute("id");
      const aria = inp.getAttribute("aria-label") || inp.getAttribute("aria-labelledby");
      const parentTag = inp.parentNode?.rawTagName?.toLowerCase();
      return !aria && parentTag !== "label" && !(id && labelledIds.has(id));
    });
    if (unlabelled.length > 0) {
      score -= 2;
      penalties.push({ category: CAT, message: `${unlabelled.length} input(s) without accessible labels`, pointsLost: 2 });
      issues.push({ category: CAT, severity: "warning",
        message: `${unlabelled.length} input(s) missing accessible labels`,
        explanation: "Screen readers cannot identify unlabelled inputs. Fails WCAG 2.1 SC 1.3.1.",
        suggestion: "Add <label for='id'> or aria-label attributes to all form inputs." });
    } else {
      issues.push({ category: CAT, severity: "passed",
        message: "All inputs appear to have accessible labels",
        explanation: "Inputs have associated labels or ARIA attributes.",
        suggestion: "Ensure labels are descriptive — avoid placeholder-only labelling." });
    }
  }

  // Images without alt (2pts)
  const images = root.querySelectorAll("img");
  if (images.length > 0) {
    const missingAlt = images.filter((img) => img.getAttribute("alt") === null);
    if (missingAlt.length > 0) {
      score -= 2;
      penalties.push({ category: CAT, message: `${missingAlt.length} image(s) missing alt attribute`, pointsLost: 2 });
      issues.push({ category: CAT, severity: "warning",
        message: `${missingAlt.length} image(s) missing alt attribute`,
        explanation: "Images without alt are invisible to screen readers. Fails WCAG 2.1 SC 1.1.1 (Non-text Content).",
        suggestion: "Add descriptive alt text to meaningful images. Use alt=\"\" for purely decorative images." });
    } else {
      issues.push({ category: CAT, severity: "passed",
        message: `All ${images.length} image(s) have alt attributes`,
        explanation: "Images have alt text, supporting screen reader users.",
        suggestion: "Ensure alt text is descriptive, not just filenames." });
    }
  }

  // Main landmark + heading structure (1pt)
  const hasMain = !!root.querySelector("main") || !!root.querySelector('[role="main"]');
  const hasHeading = !!root.querySelector("h1, h2");
  if (!hasMain || !hasHeading) {
    score -= 1;
    const missing = [!hasMain && "main landmark", !hasHeading && "h1/h2 heading"].filter(Boolean);
    penalties.push({ category: CAT, message: `Missing: ${missing.join(", ")}`, pointsLost: 1 });
    issues.push({ category: CAT, severity: "warning",
      message: `Missing page structure: ${missing.join(" and ")}`,
      explanation: "Landmarks and heading hierarchy allow screen readers to navigate efficiently. Fails WCAG 2.1 SC 1.3.1 and 2.4.1.",
      suggestion: "Wrap primary content in <main>. Add at least one <h1> for the page title." });
  } else {
    issues.push({ category: CAT, severity: "passed",
      message: "Page has main landmark and heading structure (h1/h2)",
      explanation: "<main> and headings enable efficient screen reader navigation.",
      suggestion: "Use a logical heading hierarchy (h1 → h2 → h3) throughout the page." });
  }

  // HTML lang attribute (1pt) — required by WCAG 2.1 SC 3.1.1
  const htmlEl = root.querySelector("html");
  const hasLang = !!htmlEl?.getAttribute("lang");
  if (!hasLang) {
    score -= 1;
    penalties.push({ category: CAT, message: "Missing lang attribute on <html> element", pointsLost: 1 });
    issues.push({ category: CAT, severity: "warning",
      message: "Missing lang attribute on <html> element",
      explanation: "Without a lang attribute, screen readers may use the wrong language for text-to-speech. Fails WCAG 2.1 SC 3.1.1.",
      suggestion: 'Add lang attribute: <html lang="en"> (use the appropriate BCP47 language tag).' });
  } else {
    issues.push({ category: CAT, severity: "passed",
      message: `HTML lang attribute present: "${htmlEl?.getAttribute("lang")}"`,
      explanation: "Assistive technologies can select the correct language engine for text-to-speech.",
      suggestion: "Ensure the lang value is a valid BCP47 language tag matching your content's primary language." });
  }

  return { score: Math.max(0, score), issues, penalties };
}

// ================================================================
// Headless Scan Module (feature-gated)
// ================================================================

// HeadlessResult and headlessScan are re-exported from ./headless.ts (see top of file)

// ================================================================
// Auxiliary HTTP Checks
// ================================================================

async function checkFile(baseUrl: string, path: string, signal: AbortSignal): Promise<boolean> {
  try {
    const url = new URL(path, baseUrl).toString();
    validateSsrfSync(url);
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 4_000);
    const onAbort = (): void => controller.abort();
    signal.addEventListener("abort", onAbort, { once: true });
    try {
      const res = await fetch(url, { method: "HEAD", signal: controller.signal });
      return res.ok;
    } finally {
      clearTimeout(timer);
      signal.removeEventListener("abort", onAbort);
    }
  } catch {
    return false;
  }
}

async function checkApiExposure(baseUrl: string, signal: AbortSignal): Promise<{ issues: string[] }> {
  const pathsToCheck = ["/docs", "/swagger", "/swagger-ui", "/api-docs", "/openapi.json"];
  const issues: string[] = [];
  await Promise.all(
    pathsToCheck.map(async (p) => {
      try {
        const url = new URL(p, baseUrl).toString();
        validateSsrfSync(url);
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), 3_000);
        const onAbort = (): void => controller.abort();
        signal.addEventListener("abort", onAbort, { once: true });
        let res: Response;
        try {
          res = await fetch(url, { method: "GET", signal: controller.signal });
        } finally {
          clearTimeout(timer);
          signal.removeEventListener("abort", onAbort);
        }
        if (res.ok) {
          const ct = res.headers.get("content-type") ?? "";
          if (!ct.includes("text/html") || p === "/openapi.json") {
            issues.push(`API documentation exposed at ${p}`);
          }
          await res.body?.cancel().catch(() => {});
        }
      } catch { /* ignore */ }
    }),
  );
  return { issues };
}

// ================================================================
// Main Scanner Entry Point
// ================================================================

export async function scanUrl(rawUrl: string): Promise<ScanResult> {
  const normalizedUrl = normalizeUrl(rawUrl);
  validateSsrfSync(normalizedUrl);
  await validateSsrfAsync(normalizedUrl);
  const controller = new AbortController();
  const absoluteTimer = setTimeout(() => controller.abort(), ABSOLUTE_TIMEOUT_MS);
  try {
    return await _scan(rawUrl, normalizedUrl, controller.signal);
  } finally {
    clearTimeout(absoluteTimer);
  }
}

async function _scan(rawUrl: string, normalizedUrl: string, signal: AbortSignal): Promise<ScanResult> {
  const startTime = Date.now();

  const { response, redirectChain } = await fetchWithManualRedirects(
    normalizedUrl, MAX_REDIRECTS, PER_HOP_TIMEOUT_MS,
    {
      "User-Agent": "DeployGuard/2.0 (Launch Readiness Scanner; https://deployguard.app)",
      Accept: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
      "Accept-Encoding": "gzip, deflate, br",
      "Accept-Language": "en-US,en;q=0.5",
    },
    signal,
  );

  const responseTimeMs = Date.now() - startTime;
  const finalUrl = redirectChain[redirectChain.length - 1] ?? normalizedUrl;
  const statusCode = response.status;
  const usesHttps = finalUrl.startsWith("https://");

  const responseHeadersSnapshot: Record<string, string> = {};
  for (const h of EVIDENCE_HEADERS) {
    const val = response.headers.get(h);
    if (val) responseHeadersSnapshot[h] = val;
  }

  const { text: html } = await readBodyCapped(response, MAX_BODY_BYTES);
  const htmlHash = createHash("sha256").update(html).digest("hex").slice(0, 16);
  const htmlSizeKb = Math.round((Buffer.byteLength(html, "utf8") / 1024) * 10) / 10;
  const root = parseHtml(html);
  const scriptTagCount = root.querySelectorAll("script[src]").length;

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const headersAny = response.headers as any;
  const setCookieLines: string[] =
    typeof headersAny["getSetCookie"] === "function"
      ? (headersAny.getSetCookie() as string[])
      : ([response.headers.get("set-cookie")].filter(Boolean) as string[]);

  const parsedCookies = parseSetCookieHeaders(setCookieLines);
  const hasCookies = setCookieLines.length > 0;

  const securityHeaders: Record<string, boolean> = {
    "content-security-policy": !!response.headers.get("content-security-policy"),
    "strict-transport-security": !!response.headers.get("strict-transport-security"),
    "x-frame-options": !!response.headers.get("x-frame-options"),
    "x-content-type-options": !!response.headers.get("x-content-type-options"),
    "referrer-policy": !!response.headers.get("referrer-policy"),
    "permissions-policy": !!response.headers.get("permissions-policy"),
  };

  const [hasRobotsTxt, hasSitemapXml, apiExposure] = await Promise.all([
    checkFile(finalUrl, "/robots.txt", signal),
    checkFile(finalUrl, "/sitemap.xml", signal),
    checkApiExposure(finalUrl, signal),
  ]);

  // ---- Run all scorers ----
  const allIssues: Issue[] = [];
  const allPenalties: Penalty[] = [];

  // HTTPS & Redirects (10pts)
  let httpsScore = 0;
  if (usesHttps) {
    httpsScore += 8;
    allIssues.push({ category: "HTTPS & Redirects", severity: "passed",
      message: "Site uses HTTPS", explanation: "Traffic is encrypted via TLS.",
      suggestion: "Maintain a valid certificate and redirect all HTTP to HTTPS." });
  } else {
    allPenalties.push({ category: "HTTPS & Redirects", message: "Site does not use HTTPS", pointsLost: 8 });
    allIssues.push({ category: "HTTPS & Redirects", severity: "critical",
      message: "Site does not use HTTPS",
      explanation: "Plain HTTP exposes users to eavesdropping and man-in-the-middle attacks.",
      suggestion: "Enable HTTPS with a TLS certificate. Free certificates via Let's Encrypt." });
  }
  if (redirectChain.length <= 2) {
    httpsScore += 2;
    allIssues.push({ category: "HTTPS & Redirects", severity: "passed",
      message: `Clean redirect chain (${Math.max(0, redirectChain.length - 1)} hop(s))`,
      explanation: "Short redirect chains preserve page speed and link equity.",
      suggestion: "Keep redirect chains to a single hop." });
  } else {
    allPenalties.push({ category: "HTTPS & Redirects", message: `Long redirect chain (${redirectChain.length - 1} hops)`, pointsLost: 2 });
    allIssues.push({ category: "HTTPS & Redirects", severity: "warning",
      message: `Long redirect chain (${redirectChain.length - 1} hops)`,
      explanation: "Multiple redirects add latency and reduce link equity.",
      suggestion: "Consolidate to a single redirect." });
  }

  // Security Headers (30pts: CSP 12 + HSTS 9 + XFO 4 + Referrer 2 + Permissions 2 + COOP/COEP/CORP 1)
  const cspR = analyzeCsp(response.headers.get("content-security-policy"));
  const hstsR = analyzeHsts(response.headers.get("strict-transport-security"), usesHttps);
  const xfoR = scoreXFrameOptions(response.headers.get("x-frame-options"));
  const rpR = scoreReferrerPolicy(response.headers.get("referrer-policy"));
  const ppR = scorePermissionsPolicy(response.headers.get("permissions-policy"));
  const coopR = scoreCoopCoepCorp(response.headers);

  const xcto = !!response.headers.get("x-content-type-options");
  allIssues.push(xcto
    ? { category: "Security Headers", severity: "passed", message: "X-Content-Type-Options: nosniff",
        explanation: "Prevents MIME-sniffing attacks.", suggestion: "Keep X-Content-Type-Options: nosniff." }
    : { category: "Security Headers", severity: "info", message: "X-Content-Type-Options not set",
        explanation: "Without this, browsers may MIME-sniff responses, enabling drive-by downloads.",
        suggestion: "Add X-Content-Type-Options: nosniff." });

  const securityScore = cspR.score + hstsR.score + xfoR.score + rpR.score + ppR.score + coopR.score;
  allIssues.push(...cspR.issues, ...hstsR.issues, ...xfoR.issues, ...rpR.issues, ...ppR.issues, ...coopR.issues);
  allPenalties.push(...cspR.penalties, ...hstsR.penalties, ...xfoR.penalties, ...rpR.penalties, ...ppR.penalties, ...coopR.penalties);

  // Cookies & Session (15pts)
  const cookieR = scoreCookies(parsedCookies, finalUrl);
  allIssues.push(...cookieR.issues);
  allPenalties.push(...cookieR.penalties);

  // CORS (10pts)
  const corsR = analyzeCors(
    response.headers.get("access-control-allow-origin"),
    response.headers.get("access-control-allow-credentials"),
    response.headers.get("access-control-allow-methods"),
    response.headers.get("access-control-allow-headers"),
  );
  allIssues.push(...corsR.issues);
  allPenalties.push(...corsR.penalties);

  // Cache & Exposure (7pts)
  const cacheR = scoreCacheHygiene(response.headers, apiExposure, hasCookies);
  allIssues.push(...cacheR.issues);
  allPenalties.push(...cacheR.penalties);

  // Performance (15pts)
  const perfR = scorePerformance(responseTimeMs, htmlSizeKb, scriptTagCount, response.headers.get("cache-control"));
  allIssues.push(...perfR.issues);
  allPenalties.push(...perfR.penalties);

  // SEO (7pts)
  const seoR = scoreSeo(root, finalUrl, hasRobotsTxt, hasSitemapXml);
  allIssues.push(...seoR.issues);
  allPenalties.push(...seoR.penalties);

  // Accessibility (5pts: inputs 2 + images 2 + main/headings 1)
  const a11yR = scoreAccessibility(root);
  allIssues.push(...a11yR.issues);
  allPenalties.push(...a11yR.penalties);

  // Structured Data (5pts)
  const sdR = scoreStructuredData(html);
  allIssues.push(...sdR.issues);
  allPenalties.push(...sdR.penalties);

  // Third-party Governance (10pts)
  const tpR = scoreThirdPartyGovernance(html, finalUrl);
  allIssues.push(...tpR.issues);
  allPenalties.push(...tpR.penalties);

  // ---- Final totals (10+30+10+10+10+5+8+7+5+5 = 100) ----
  const totalScore = Math.min(100, Math.max(0, Math.round(
    httpsScore + securityScore + cookieR.score + corsR.score + tpR.score + cacheR.score + perfR.score + seoR.score + sdR.score + a11yR.score,
  )));

  const grade =
    totalScore >= 85 ? "Excellent"
    : totalScore >= 70 ? "Good"
    : totalScore >= 50 ? "Needs Work"
    : "Risky";

  const scoreKillers = [...allPenalties]
    .sort((a, b) => b.pointsLost - a.pointsLost)
    .slice(0, 3)
    .map(({ category, message, pointsLost }) => ({
      category,
      message,
      pointsLost: Math.round(pointsLost * 10) / 10,
    }));

  const categoryScores = [
    { name: "HTTPS & Redirects", score: httpsScore, maxScore: 10, label: httpsScore >= 8 ? "Good" : httpsScore >= 5 ? "Fair" : "Poor" },
    { name: "Security Headers", score: Math.round(securityScore * 10) / 10, maxScore: 30, label: securityScore >= 24 ? "Good" : securityScore >= 15 ? "Fair" : "Poor" },
    { name: "Cookies & Session", score: cookieR.score, maxScore: 10, label: cookieR.score >= 8 ? "Good" : cookieR.score >= 5 ? "Fair" : "Poor" },
    { name: "CORS", score: Math.round(corsR.score * 10) / 10, maxScore: 10, label: corsR.score >= 8 ? "Good" : corsR.score >= 5 ? "Fair" : "Poor" },
    { name: "Third-party", score: tpR.score, maxScore: 10, label: tpR.score >= 8 ? "Good" : tpR.score >= 5 ? "Fair" : "Poor" },
    { name: "Cache & Exposure", score: cacheR.score, maxScore: 5, label: cacheR.score >= 4 ? "Good" : cacheR.score >= 2 ? "Fair" : "Poor" },
    { name: "Performance", score: Math.round(perfR.score * 10) / 10, maxScore: 8, label: perfR.score >= 6 ? "Good" : perfR.score >= 4 ? "Fair" : "Poor" },
    { name: "SEO", score: Math.round(seoR.score * 10) / 10, maxScore: 7, label: seoR.score >= 5.6 ? "Good" : seoR.score >= 3.5 ? "Fair" : "Poor" },
    { name: "Structured Data", score: Math.round(sdR.score * 10) / 10, maxScore: 5, label: sdR.score >= 4 ? "Good" : sdR.score >= 2 ? "Fair" : "Poor" },
    { name: "Accessibility", score: a11yR.score, maxScore: 5, label: a11yR.score >= 4 ? "Good" : a11yR.score >= 2 ? "Fair" : "Poor" },
  ];

  const criticalIssues = allIssues.filter((i) => i.severity === "critical");
  const warningIssues = allIssues.filter((i) => i.severity === "warning");

  // ---- Post-score optional engines (run in parallel) ----
  const featureVector = buildFeatureVector({
    httpsScore,
    securityScore,
    corsScore: corsR.score,
    cookieScore: cookieR.score,
    cacheScore: cacheR.score,
    perfScore: perfR.score,
    seoScore: seoR.score,
    a11yScore: a11yR.score,
    thirdPartyScore: tpR.score,
    structuredDataScore: sdR.score,
    totalScore,
    issues: allIssues,
    cookieCount: cookieR.cookieIssueStrings.length,
    hasCSP: securityHeaders["content-security-policy"] ?? false,
    hasHSTS: securityHeaders["strict-transport-security"] ?? false,
    usesHttps,
    hasCriticalCors: corsR.score <= 2,
    hasNoindex: seoR.hasNoindex,
  });

  const topFindings = scoreKillers.map(
    (k) => `[${k.category}] ${k.message} (−${k.pointsLost} pts)`,
  );

  const [headlessR, aiOverlay] = await Promise.all([
    _headlessScan(finalUrl),
    computeAiOverlay(featureVector, topFindings),
  ]);

  const enginesRan: string[] = ["structured-data", "third-party"];
  if (headlessR?.available) enginesRan.push("headless");
  if (aiOverlay) enginesRan.push("local-ai");

  // ---- Fix prompt ----
  let fixPrompt = `# DeployGuard Report (v4) — ${finalUrl}\n\nScore: ${totalScore}/100 (${grade})\nRubric: HTTPS(10) + Security(30) + Cookies(10) + CORS(10) + Third-party(10) + Cache(5) + Perf(8) + SEO(7) + StructuredData(5) + A11y(5) = 100\n\nTop Score Killers:\n`;
  for (const k of scoreKillers) {
    fixPrompt += `  • [${k.category}] ${k.message} (−${k.pointsLost} pts)\n`;
  }
  if (aiOverlay) {
    fixPrompt += `\nAI Overlay Score: ${aiOverlay.aiScore}/100 (${aiOverlay.riskLabel}) — ${aiOverlay.rationale}\n`;
  }
  if (criticalIssues.length > 0) {
    fixPrompt += `\n## Critical Issues — Fix Before Launch\n`;
    for (const i of criticalIssues) {
      fixPrompt += `\n### ${i.message}\nWhy: ${i.explanation}\nFix: ${i.suggestion}\n`;
    }
  }
  if (warningIssues.length > 0) {
    fixPrompt += `\n## Warnings — Fix Soon\n`;
    for (const i of warningIssues) {
      fixPrompt += `\n### ${i.message}\nWhy: ${i.explanation}\nFix: ${i.suggestion}\n`;
    }
  }
  fixPrompt += `\nGenerated by DeployGuard v4.0 | Engines: ${enginesRan.join(", ")}`;

  return {
    url: rawUrl,
    finalUrl,
    score: totalScore,
    grade,
    statusCode,
    redirectChain,
    usesHttps,
    responseTimeMs,
    title: seoR.title ?? null,
    metaDescription: seoR.metaDescription ?? null,
    hasViewport: seoR.hasViewport,
    hasOpenGraph: seoR.hasOpenGraph,
    hasRobotsTxt,
    hasSitemapXml,
    securityHeaders,
    cookieIssues: cookieR.cookieIssueStrings,
    htmlSizeKb,
    scriptTagCount,
    categoryScores,
    issues: allIssues,
    fixPrompt,
    htmlHash,
    responseHeadersSnapshot,
    corsScore: corsR.score,
    scoreKillers,
    canonicalUrl: seoR.canonicalUrl,
    hasStructuredData: seoR.hasStructuredData || sdR.blockCount > 0,
    hasNoindex: seoR.hasNoindex,
    structuredDataScore: sdR.score,
    thirdPartyScore: tpR.score,
    thirdPartyDomains: tpR.thirdPartyDomains,
    aiOverlay: aiOverlay ?? null,
    headlessScan: headlessR ?? null,
    enginesRan,
  };
}
