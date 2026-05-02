import { parse as parseHtml } from "node-html-parser";
import { createHash } from "crypto";
import { promises as dnsLookup } from "dns";

// ============================================================
// Constants
// ============================================================

const SECURITY_HEADERS = [
  "content-security-policy",
  "x-frame-options",
  "x-content-type-options",
  "referrer-policy",
  "permissions-policy",
  "strict-transport-security",
] as const;

const EVIDENCE_HEADERS = [
  ...SECURITY_HEADERS,
  "content-type",
  "server",
  "x-powered-by",
  "cache-control",
  "via",
];

// Private IPv4 ranges — loopback, RFC1918, link-local, CGNAT, test ranges
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

// Private IPv6 ranges — loopback, ULA, link-local, mapped
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

const BLOCKED_HOSTNAMES = new Set([
  "localhost",
  "0.0.0.0",
  "metadata.google.internal",
  "169.254.169.254",
  "instance-data",
]);

const MAX_BODY_BYTES = 2 * 1024 * 1024; // 2 MB
const MAX_REDIRECTS = 5;
const PER_HOP_TIMEOUT_MS = 8_000;
const ABSOLUTE_TIMEOUT_MS = 30_000;

// ============================================================
// Types
// ============================================================

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
  issues: Array<{
    category: string;
    severity: string;
    message: string;
    explanation: string;
    suggestion: string;
  }>;
  fixPrompt: string;
  htmlHash: string;
  responseHeadersSnapshot: Record<string, string>;
}

// ============================================================
// SSRF Protection — exported for tests
// ============================================================

/**
 * Returns true if the given IP address falls within a private/non-routable range.
 */
export function isPrivateIp(address: string): boolean {
  for (const re of PRIVATE_IPV4_RE) {
    if (re.test(address)) return true;
  }
  for (const re of PRIVATE_IPV6_RE) {
    if (re.test(address)) return true;
  }
  return false;
}

/**
 * Synchronous SSRF guard: validates protocol, blocked hostnames, and IP literals.
 * Does NOT resolve DNS — call validateSsrfAsync for full protection.
 */
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

  // URL.hostname for IPv6 addresses includes brackets: "[::1]" → strip them
  const raw = parsed.hostname.toLowerCase();
  const hostname = raw.startsWith("[") && raw.endsWith("]") ? raw.slice(1, -1) : raw;

  if (BLOCKED_HOSTNAMES.has(hostname)) {
    throw new Error(`Blocked hostname: ${hostname}`);
  }

  if (isPrivateIp(hostname)) {
    throw new Error(`Blocked private IP range: ${hostname}`);
  }
}

/**
 * Async SSRF guard: resolves the hostname to an IP address via the OS resolver,
 * then validates the resolved IP. Prevents DNS-based SSRF bypasses.
 */
async function validateSsrfAsync(url: string): Promise<void> {
  validateSsrfSync(url);

  const rawHostname = new URL(url).hostname.toLowerCase();
  // Strip IPv6 brackets so IP literal detection works correctly
  const hostname =
    rawHostname.startsWith("[") && rawHostname.endsWith("]")
      ? rawHostname.slice(1, -1)
      : rawHostname;

  // Skip DNS lookup for bare IP literals — already validated by validateSsrfSync
  if (/^\d+\.\d+\.\d+\.\d+$/.test(hostname) || hostname.includes(":")) {
    return;
  }

  let address: string;
  try {
    const result = await dnsLookup.lookup(hostname, { family: 0 });
    address = result.address;
  } catch {
    throw new Error(`Cannot resolve hostname: ${hostname}`);
  }

  if (isPrivateIp(address)) {
    throw new Error(`Blocked: ${hostname} resolves to private IP ${address}`);
  }
}

// ============================================================
// URL Normalization — exported for tests
// ============================================================

/**
 * Prepends https:// to bare domains. Preserves explicit non-http(s) schemes so
 * validateSsrfSync can reject them with the correct error message.
 */
export function normalizeUrl(input: string): string {
  const trimmed = input.trim();
  if (/^https?:\/\//i.test(trimmed)) return trimmed;
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(trimmed)) return trimmed;
  return `https://${trimmed}`;
}

// ============================================================
// HTTP Helpers
// ============================================================

/**
 * Follows redirects manually up to maxRedirects, performing a full SSRF check
 * on every redirect destination before following it.
 */
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

    // Non-redirect: return the final response
    if (response.status < 300 || response.status >= 400) {
      return { response, redirectChain: chain };
    }

    if (hop === maxRedirects) {
      await response.body?.cancel().catch(() => {});
      throw new Error(`Too many redirects (max ${maxRedirects})`);
    }

    const location = response.headers.get("location");
    if (!location) {
      return { response, redirectChain: chain };
    }

    await response.body?.cancel().catch(() => {});

    const nextUrl = new URL(location, currentUrl).toString();
    await validateSsrfAsync(nextUrl);

    chain.push(nextUrl);
    currentUrl = nextUrl;
  }

  throw new Error(`Too many redirects (max ${maxRedirects})`);
}

/**
 * Reads the response body with a hard size cap. Body bytes beyond maxBytes are
 * discarded and the connection is closed. Handles compressed content via fetch's
 * built-in decompression (gzip, deflate, br).
 */
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

async function checkFile(
  baseUrl: string,
  path: string,
  signal: AbortSignal,
): Promise<boolean> {
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

async function checkApiExposure(
  baseUrl: string,
  signal: AbortSignal,
): Promise<{ paths: string[]; issues: string[] }> {
  const pathsToCheck = ["/api", "/api/health", "/health", "/docs", "/swagger"];
  const exposed: string[] = [];
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
          exposed.push(p);
          if (p === "/docs" || p === "/swagger") {
            const ct = res.headers.get("content-type") ?? "";
            if (!ct.includes("text/html")) {
              issues.push(`API docs exposed at ${p} — consider restricting access in production`);
            }
          }
          await res.body?.cancel().catch(() => {});
        }
      } catch {
        // ignore individual probe failures
      }
    }),
  );

  return { paths: exposed, issues };
}

function analyzeCookies(headers: Headers): { issues: string[] } {
  const issues: string[] = [];
  const setCookieHeader = headers.get("set-cookie");
  if (!setCookieHeader) return { issues };

  const cookies = setCookieHeader.split(/,(?=[^;])/);
  for (const cookie of cookies) {
    const lower = cookie.toLowerCase();
    const nameMatch = cookie.match(/^([^=]+)=/);
    const name = nameMatch ? nameMatch[1].trim() : "unknown";
    if (!lower.includes("httponly")) issues.push(`Cookie "${name}" is missing HttpOnly flag`);
    if (!lower.includes("secure")) issues.push(`Cookie "${name}" is missing Secure flag`);
    if (!lower.includes("samesite")) issues.push(`Cookie "${name}" is missing SameSite attribute`);
  }

  return { issues };
}

function getResponseTimeBucket(ms: number): string {
  if (ms < 300) return "fast";
  if (ms < 1000) return "moderate";
  if (ms < 3000) return "slow";
  return "very slow";
}

// ============================================================
// Main Scanner
// ============================================================

export async function scanUrl(rawUrl: string): Promise<ScanResult> {
  const normalizedUrl = normalizeUrl(rawUrl);

  // 1. Sync SSRF check (fast path — no I/O)
  validateSsrfSync(normalizedUrl);

  // 2. Async DNS-based SSRF check
  await validateSsrfAsync(normalizedUrl);

  // 3. Absolute timeout governs all subsequent I/O
  const controller = new AbortController();
  const absoluteTimer = setTimeout(() => controller.abort(), ABSOLUTE_TIMEOUT_MS);

  try {
    return await _scan(rawUrl, normalizedUrl, controller.signal);
  } finally {
    clearTimeout(absoluteTimer);
  }
}

async function _scan(
  rawUrl: string,
  normalizedUrl: string,
  signal: AbortSignal,
): Promise<ScanResult> {
  const startTime = Date.now();

  const requestHeaders: Record<string, string> = {
    "User-Agent": "DeployGuard/1.0 (Launch Readiness Scanner)",
    Accept: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Encoding": "gzip, deflate, br",
    "Accept-Language": "en-US,en;q=0.5",
  };

  const { response, redirectChain } = await fetchWithManualRedirects(
    normalizedUrl,
    MAX_REDIRECTS,
    PER_HOP_TIMEOUT_MS,
    requestHeaders,
    signal,
  );

  const responseTimeMs = Date.now() - startTime;
  const finalUrl = redirectChain[redirectChain.length - 1] ?? normalizedUrl;
  const statusCode = response.status;
  const usesHttps = finalUrl.startsWith("https://");

  // Snapshot of security-relevant response headers (evidence the fetch happened)
  const responseHeadersSnapshot: Record<string, string> = {};
  for (const h of EVIDENCE_HEADERS) {
    const val = response.headers.get(h);
    if (val) responseHeadersSnapshot[h] = val;
  }

  // Read body with 2 MB cap; decompress is handled automatically by fetch
  const { text: html } = await readBodyCapped(response, MAX_BODY_BYTES);

  // SHA-256 fingerprint of the body — proof the page was actually fetched
  const htmlHash = createHash("sha256").update(html).digest("hex").slice(0, 16);

  const htmlSizeKb = Buffer.byteLength(html, "utf8") / 1024;
  const root = parseHtml(html);

  const titleEl = root.querySelector("title");
  const title = titleEl?.text?.trim() ?? null;

  const metaDescEl = root.querySelector('meta[name="description"]');
  const metaDescription = metaDescEl?.getAttribute("content")?.trim() ?? null;

  const viewportEl = root.querySelector('meta[name="viewport"]');
  const hasViewport = !!viewportEl;

  const ogTitleEl = root.querySelector('meta[property="og:title"]');
  const hasOpenGraph = !!ogTitleEl;

  const scriptTagCount = root.querySelectorAll("script[src]").length;

  const securityHeaders: Record<string, boolean> = {};
  for (const header of SECURITY_HEADERS) {
    securityHeaders[header] = !!response.headers.get(header);
  }

  const { issues: cookieIssues } = analyzeCookies(response.headers);

  const [hasRobotsTxt, hasSitemapXml, apiExposure] = await Promise.all([
    checkFile(finalUrl, "/robots.txt", signal),
    checkFile(finalUrl, "/sitemap.xml", signal),
    checkApiExposure(finalUrl, signal),
  ]);

  // ---- SCORING ----
  type Issue = {
    category: string;
    severity: string;
    message: string;
    explanation: string;
    suggestion: string;
  };
  const issues: Issue[] = [];

  // HTTPS & Redirects (15 pts)
  let httpsScore = 0;
  if (usesHttps) {
    httpsScore += 10;
    issues.push({
      category: "HTTPS & Redirects",
      severity: "passed",
      message: "Site uses HTTPS",
      explanation: "Your site is served over HTTPS, which encrypts traffic between users and your server.",
      suggestion: "Keep using HTTPS with a valid certificate.",
    });
  } else {
    issues.push({
      category: "HTTPS & Redirects",
      severity: "critical",
      message: "Site does not use HTTPS",
      explanation: "Your site is served over plain HTTP, exposing users to eavesdropping and MITM attacks.",
      suggestion: "Enable HTTPS using a TLS certificate. Most hosts provide free certificates via Let's Encrypt.",
    });
  }

  if (redirectChain.length <= 2) {
    httpsScore += 5;
    issues.push({
      category: "HTTPS & Redirects",
      severity: "passed",
      message: "Redirect chain is clean",
      explanation: `Redirect chain has ${redirectChain.length} step(s), which is minimal.`,
      suggestion: "Maintain short redirect chains to preserve performance.",
    });
  } else {
    issues.push({
      category: "HTTPS & Redirects",
      severity: "warning",
      message: `Long redirect chain (${redirectChain.length} hops)`,
      explanation: "Multiple redirects slow down page load and can negatively affect SEO.",
      suggestion: "Consolidate redirects to a single hop wherever possible.",
    });
  }

  // Security Headers (30 pts)
  const headerNames: Record<string, string> = {
    "content-security-policy": "Content-Security-Policy",
    "x-frame-options": "X-Frame-Options",
    "x-content-type-options": "X-Content-Type-Options",
    "referrer-policy": "Referrer-Policy",
    "permissions-policy": "Permissions-Policy",
    "strict-transport-security": "Strict-Transport-Security",
  };

  const headerExplanations: Record<string, { explanation: string; suggestion: string }> = {
    "content-security-policy": {
      explanation: "CSP prevents XSS attacks by telling the browser which sources are trusted for scripts, styles, and other resources.",
      suggestion: "Add a Content-Security-Policy header. Start with a report-only policy, then tighten it.",
    },
    "x-frame-options": {
      explanation: "This header prevents your page from being embedded in iframes, protecting against clickjacking attacks.",
      suggestion: "Add X-Frame-Options: DENY or SAMEORIGIN to your server response headers.",
    },
    "x-content-type-options": {
      explanation: "This header stops browsers from MIME-sniffing responses away from the declared content-type.",
      suggestion: "Add X-Content-Type-Options: nosniff to your server response headers.",
    },
    "referrer-policy": {
      explanation: "Controls how much referrer information is sent with requests, protecting user privacy.",
      suggestion: "Add Referrer-Policy: strict-origin-when-cross-origin or no-referrer.",
    },
    "permissions-policy": {
      explanation: "Allows you to control which browser APIs and features can be used on your page.",
      suggestion: "Add Permissions-Policy to restrict access to cameras, microphones, and geolocation.",
    },
    "strict-transport-security": {
      explanation: "HSTS tells browsers to always use HTTPS for your domain, preventing SSL stripping attacks.",
      suggestion: "Add Strict-Transport-Security: max-age=31536000; includeSubDomains",
    },
  };

  let securityScore = 0;
  const secHeaderPoints = 30 / SECURITY_HEADERS.length;
  for (const header of SECURITY_HEADERS) {
    if (securityHeaders[header]) {
      securityScore += secHeaderPoints;
      issues.push({
        category: "Security Headers",
        severity: "passed",
        message: `${headerNames[header]} is present`,
        explanation: `The ${headerNames[header]} header is set.`,
        suggestion: "Keep this header configured correctly.",
      });
    } else {
      const sev = ["content-security-policy", "strict-transport-security", "x-frame-options"].includes(header)
        ? "critical"
        : "warning";
      issues.push({
        category: "Security Headers",
        severity: sev,
        message: `Missing ${headerNames[header]}`,
        explanation: headerExplanations[header].explanation,
        suggestion: headerExplanations[header].suggestion,
      });
    }
  }

  // SEO (20 pts)
  let seoScore = 0;
  if (title && title.length >= 10 && title.length <= 70) {
    seoScore += 7;
    issues.push({
      category: "SEO",
      severity: "passed",
      message: "Title tag is well-formed",
      explanation: `Title "${title}" is ${title.length} chars — within the 10-70 recommended range.`,
      suggestion: "Keep your title descriptive and within 60 characters for best display in search results.",
    });
  } else if (title) {
    seoScore += 4;
    const len = title.length;
    issues.push({
      category: "SEO",
      severity: "warning",
      message: `Title tag length is ${len} chars (${len < 10 ? "too short" : "too long"})`,
      explanation: `Title "${title}" is ${len} chars. Google typically displays 50-60 chars.`,
      suggestion: "Keep your title between 50-60 characters for optimal search result display.",
    });
  } else {
    issues.push({
      category: "SEO",
      severity: "critical",
      message: "Missing title tag",
      explanation: "Your page has no <title> tag, which is required for search engine indexing.",
      suggestion: "Add a descriptive <title> tag to the <head> of your page.",
    });
  }

  if (metaDescription && metaDescription.length >= 50 && metaDescription.length <= 160) {
    seoScore += 7;
    issues.push({
      category: "SEO",
      severity: "passed",
      message: "Meta description is well-formed",
      explanation: `Meta description is ${metaDescription.length} chars — within the recommended range.`,
      suggestion: "Keep descriptions between 120-160 characters.",
    });
  } else if (metaDescription) {
    seoScore += 3;
    issues.push({
      category: "SEO",
      severity: "warning",
      message: `Meta description length is ${metaDescription.length} chars`,
      explanation: "The meta description is outside the optimal 50-160 character range.",
      suggestion: "Adjust your meta description to be between 120-160 characters for best search snippet display.",
    });
  } else {
    issues.push({
      category: "SEO",
      severity: "warning",
      message: "Missing meta description",
      explanation: "No meta description found. Search engines may generate one automatically, but it may not represent your page well.",
      suggestion: 'Add <meta name="description" content="Your description here"> to the <head>.',
    });
  }

  if (hasViewport) {
    seoScore += 3;
    issues.push({
      category: "SEO",
      severity: "passed",
      message: "Viewport meta tag is present",
      explanation: "The viewport tag ensures correct rendering on mobile devices.",
      suggestion: "Keep this tag configured correctly.",
    });
  } else {
    issues.push({
      category: "SEO",
      severity: "warning",
      message: "Missing viewport meta tag",
      explanation: "Without a viewport tag, your page may appear zoomed out on mobile devices.",
      suggestion: 'Add <meta name="viewport" content="width=device-width, initial-scale=1"> to the <head>.',
    });
  }

  if (hasOpenGraph) {
    seoScore += 3;
    issues.push({
      category: "SEO",
      severity: "passed",
      message: "Open Graph tags are present",
      explanation: "Open Graph tags control how your page appears when shared on social media.",
      suggestion: "Ensure og:title, og:description, and og:image are all set.",
    });
  } else {
    issues.push({
      category: "SEO",
      severity: "info",
      message: "Open Graph tags not found",
      explanation: "Without OG tags, social media platforms may display your page poorly when shared.",
      suggestion: "Add og:title, og:description, og:image, and og:url meta tags.",
    });
  }

  // Robots & Sitemap (10 pts)
  let robotsScore = 0;
  if (hasRobotsTxt) {
    robotsScore += 5;
    issues.push({
      category: "Robots & Sitemap",
      severity: "passed",
      message: "robots.txt is present",
      explanation: "robots.txt tells search engine crawlers which pages to index.",
      suggestion: "Ensure robots.txt correctly allows or disallows the right paths.",
    });
  } else {
    issues.push({
      category: "Robots & Sitemap",
      severity: "warning",
      message: "robots.txt not found",
      explanation: "Without robots.txt, crawlers have no guidance on what to index.",
      suggestion: "Create a /robots.txt file with appropriate rules. At minimum: User-agent: * / Allow: /",
    });
  }

  if (hasSitemapXml) {
    robotsScore += 5;
    issues.push({
      category: "Robots & Sitemap",
      severity: "passed",
      message: "sitemap.xml is present",
      explanation: "A sitemap helps search engines discover all pages on your site.",
      suggestion: "Keep your sitemap up to date and reference it in robots.txt.",
    });
  } else {
    issues.push({
      category: "Robots & Sitemap",
      severity: "info",
      message: "sitemap.xml not found",
      explanation: "A sitemap helps search engines discover all your pages, especially for larger sites.",
      suggestion: "Generate a sitemap.xml and add Sitemap: https://yourdomain.com/sitemap.xml to robots.txt.",
    });
  }

  // Cookies (10 pts)
  let cookieScore = 10;
  if (cookieIssues.length > 0) {
    const deduction = Math.min(cookieIssues.length * 3, 10);
    cookieScore = Math.max(10 - deduction, 0);
    for (const issue of cookieIssues) {
      issues.push({
        category: "Cookies",
        severity: "warning",
        message: issue,
        explanation: "Missing cookie security attributes can expose session tokens to XSS or network attacks.",
        suggestion: "Set HttpOnly, Secure, and SameSite=Lax (or Strict) on all cookies.",
      });
    }
  } else {
    issues.push({
      category: "Cookies",
      severity: "passed",
      message: "No cookie security issues detected",
      explanation: "All detected cookies have appropriate security attributes.",
      suggestion: "Continue setting HttpOnly, Secure, and SameSite on all cookies.",
    });
  }

  // Performance (10 pts)
  let perfScore = 0;
  const timeBucket = getResponseTimeBucket(responseTimeMs);

  if (timeBucket === "fast") {
    perfScore += 5;
    issues.push({
      category: "Performance",
      severity: "passed",
      message: `Response time is fast (${Math.round(responseTimeMs)}ms)`,
      explanation: "Your server responds in under 300ms, which is excellent.",
      suggestion: "Maintain fast response times with caching and efficient query patterns.",
    });
  } else if (timeBucket === "moderate") {
    perfScore += 3;
    issues.push({
      category: "Performance",
      severity: "info",
      message: `Response time is moderate (${Math.round(responseTimeMs)}ms)`,
      explanation: "Response time is between 300ms-1s. This is acceptable but could be improved.",
      suggestion: "Consider adding response caching, CDN, or optimizing server-side rendering.",
    });
  } else if (timeBucket === "slow") {
    perfScore += 1;
    issues.push({
      category: "Performance",
      severity: "warning",
      message: `Response time is slow (${Math.round(responseTimeMs)}ms)`,
      explanation: "Response time over 1s impacts user experience and Core Web Vitals.",
      suggestion: "Investigate slow database queries, add caching, or use a CDN for static assets.",
    });
  } else {
    issues.push({
      category: "Performance",
      severity: "critical",
      message: `Response time is very slow (${Math.round(responseTimeMs)}ms)`,
      explanation: "Response time over 3s causes significant user abandonment and poor SEO.",
      suggestion: "Urgent: profile your server for bottlenecks. Add caching layers and consider edge hosting.",
    });
  }

  if (htmlSizeKb < 100) {
    perfScore += 3;
    issues.push({
      category: "Performance",
      severity: "passed",
      message: `HTML size is lean (${htmlSizeKb.toFixed(1)}KB)`,
      explanation: "Small HTML payloads parse faster and improve Time to First Byte.",
      suggestion: "Keep HTML lean. Use lazy loading for images and defer non-critical scripts.",
    });
  } else if (htmlSizeKb < 300) {
    perfScore += 1;
    issues.push({
      category: "Performance",
      severity: "info",
      message: `HTML size is moderate (${htmlSizeKb.toFixed(1)}KB)`,
      explanation: "Larger HTML payloads take longer to parse.",
      suggestion: "Remove unnecessary HTML, comments, and inline scripts to reduce page weight.",
    });
  } else {
    issues.push({
      category: "Performance",
      severity: "warning",
      message: `HTML size is large (${htmlSizeKb.toFixed(1)}KB)`,
      explanation: "Large HTML documents significantly slow parsing on low-end devices.",
      suggestion: "Consider server-side rendering only essential content and lazy-loading the rest.",
    });
  }

  if (scriptTagCount <= 5) {
    perfScore += 2;
    issues.push({
      category: "Performance",
      severity: "passed",
      message: `Low script count (${scriptTagCount} external scripts)`,
      explanation: "Fewer external scripts means less network overhead and faster parsing.",
      suggestion: "Bundle scripts where possible to reduce the number of HTTP requests.",
    });
  } else if (scriptTagCount <= 15) {
    issues.push({
      category: "Performance",
      severity: "info",
      message: `Moderate script count (${scriptTagCount} external scripts)`,
      explanation: "Each external script adds a network round-trip.",
      suggestion: "Bundle and defer scripts to reduce render-blocking requests.",
    });
  } else {
    issues.push({
      category: "Performance",
      severity: "warning",
      message: `High script count (${scriptTagCount} external scripts)`,
      explanation: "Many external scripts can significantly delay page load, especially on mobile.",
      suggestion: "Audit and consolidate scripts. Use bundling tools to reduce HTTP requests.",
    });
  }

  // API Exposure (5 pts)
  let apiScore = 5;
  if (apiExposure.issues.length > 0) {
    apiScore = Math.max(5 - apiExposure.issues.length * 2, 0);
    for (const issue of apiExposure.issues) {
      issues.push({
        category: "API Exposure",
        severity: "warning",
        message: issue,
        explanation: "Exposing API documentation publicly can help attackers enumerate your API surface.",
        suggestion: "Restrict /docs and /swagger to authenticated users or internal networks in production.",
      });
    }
  } else {
    issues.push({
      category: "API Exposure",
      severity: "passed",
      message: "No sensitive API endpoints exposed",
      explanation: "No publicly accessible API documentation or health check paths were found.",
      suggestion: "Continue restricting sensitive internal endpoints.",
    });
  }

  // ---- TOTALS ----
  const totalScore = Math.min(
    100,
    Math.max(
      0,
      httpsScore + securityScore + seoScore + robotsScore + cookieScore + perfScore + apiScore,
    ),
  );

  const grade =
    totalScore >= 85
      ? "Excellent"
      : totalScore >= 70
        ? "Good"
        : totalScore >= 50
          ? "Needs Work"
          : "Risky";

  const categoryScores = [
    { name: "HTTPS & Redirects", score: Math.round(httpsScore), maxScore: 15, label: httpsScore >= 12 ? "Good" : httpsScore >= 8 ? "Fair" : "Poor" },
    { name: "Security Headers", score: Math.round(securityScore), maxScore: 30, label: securityScore >= 24 ? "Good" : securityScore >= 15 ? "Fair" : "Poor" },
    { name: "SEO", score: Math.round(seoScore), maxScore: 20, label: seoScore >= 16 ? "Good" : seoScore >= 10 ? "Fair" : "Poor" },
    { name: "Robots & Sitemap", score: Math.round(robotsScore), maxScore: 10, label: robotsScore >= 8 ? "Good" : robotsScore >= 5 ? "Fair" : "Poor" },
    { name: "Cookies", score: Math.round(cookieScore), maxScore: 10, label: cookieScore >= 8 ? "Good" : cookieScore >= 5 ? "Fair" : "Poor" },
    { name: "Performance", score: Math.round(perfScore), maxScore: 10, label: perfScore >= 8 ? "Good" : perfScore >= 5 ? "Fair" : "Poor" },
    { name: "API Exposure", score: Math.round(apiScore), maxScore: 5, label: apiScore >= 4 ? "Good" : apiScore >= 2 ? "Fair" : "Poor" },
  ];

  // ---- FIX PROMPT ----
  const criticalIssues = issues.filter((i) => i.severity === "critical");
  const warningIssues = issues.filter((i) => i.severity === "warning");

  let fixPrompt = `# DeployGuard Fix Prompt for ${finalUrl}\n\n`;
  fixPrompt += `Score: ${Math.round(totalScore)}/100 (${grade})\n\n`;

  if (criticalIssues.length > 0) {
    fixPrompt += `## Critical Issues (Fix Before Launch)\n`;
    for (const issue of criticalIssues) {
      fixPrompt += `\n### ${issue.message}\n`;
      fixPrompt += `**Why it matters:** ${issue.explanation}\n`;
      fixPrompt += `**How to fix:** ${issue.suggestion}\n`;
    }
  }

  if (warningIssues.length > 0) {
    fixPrompt += `\n## Warnings (Should Fix Soon)\n`;
    for (const issue of warningIssues) {
      fixPrompt += `\n### ${issue.message}\n`;
      fixPrompt += `**Why it matters:** ${issue.explanation}\n`;
      fixPrompt += `**How to fix:** ${issue.suggestion}\n`;
    }
  }

  fixPrompt += `\nGenerated by DeployGuard`;

  return {
    url: rawUrl,
    finalUrl,
    score: Math.round(totalScore),
    grade,
    statusCode,
    redirectChain,
    usesHttps,
    responseTimeMs,
    title: title ?? null,
    metaDescription: metaDescription ?? null,
    hasViewport,
    hasOpenGraph,
    hasRobotsTxt,
    hasSitemapXml,
    securityHeaders,
    cookieIssues,
    htmlSizeKb: Math.round(htmlSizeKb * 10) / 10,
    scriptTagCount,
    categoryScores,
    issues,
    fixPrompt,
    htmlHash,
    responseHeadersSnapshot,
  };
}
