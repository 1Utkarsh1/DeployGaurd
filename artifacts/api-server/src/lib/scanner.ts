import { parse as parseHtml } from "node-html-parser";

const SECURITY_HEADERS = [
  "content-security-policy",
  "x-frame-options",
  "x-content-type-options",
  "referrer-policy",
  "permissions-policy",
  "strict-transport-security",
] as const;

const PRIVATE_IP_RANGES = [
  /^127\./,
  /^10\./,
  /^192\.168\./,
  /^172\.(1[6-9]|2[0-9]|3[01])\./,
  /^169\.254\./,
  /^::1$/,
  /^fc00:/i,
  /^fe80:/i,
];

const BLOCKED_HOSTNAMES = ["localhost", "0.0.0.0", "metadata.google.internal", "169.254.169.254"];

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
  issues: Array<{ category: string; severity: string; message: string; explanation: string; suggestion: string }>;
  fixPrompt: string;
}

function normalizeUrl(input: string): string {
  const trimmed = input.trim();
  if (/^https?:\/\//i.test(trimmed)) {
    return trimmed;
  }
  // Preserve any other explicit scheme (ftp://, file://, etc.) so validateSsrf
  // can reject it cleanly with the right error message instead of garbling it.
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(trimmed)) {
    return trimmed;
  }
  return `https://${trimmed}`;
}

function validateSsrf(url: string): void {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    throw new Error("Invalid URL format");
  }

  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    throw new Error("Only http and https protocols are allowed");
  }

  const hostname = parsed.hostname.toLowerCase();

  if (BLOCKED_HOSTNAMES.includes(hostname)) {
    throw new Error(`Blocked hostname: ${hostname}`);
  }

  for (const pattern of PRIVATE_IP_RANGES) {
    if (pattern.test(hostname)) {
      throw new Error(`Blocked private IP range: ${hostname}`);
    }
  }
}

function getResponseTimeBucket(ms: number): string {
  if (ms < 300) return "fast";
  if (ms < 1000) return "moderate";
  if (ms < 3000) return "slow";
  return "very slow";
}

async function fetchWithTimeout(url: string, timeoutMs = 8000, options: RequestInit = {}): Promise<Response> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await fetch(url, { ...options, signal: controller.signal });
  } finally {
    clearTimeout(timer);
  }
}

async function checkFile(baseUrl: string, path: string): Promise<boolean> {
  try {
    const url = new URL(path, baseUrl).toString();
    validateSsrf(url);
    const res = await fetchWithTimeout(url, 4000, { method: "HEAD" });
    return res.ok;
  } catch {
    return false;
  }
}

interface CookieAnalysis {
  issues: string[];
}

function analyzeCookies(headers: Headers): CookieAnalysis {
  const issues: string[] = [];
  const setCookieHeader = headers.get("set-cookie");
  if (!setCookieHeader) return { issues };

  const cookies = setCookieHeader.split(/,(?=[^;])/);
  for (const cookie of cookies) {
    const lower = cookie.toLowerCase();
    const nameMatch = cookie.match(/^([^=]+)=/);
    const name = nameMatch ? nameMatch[1].trim() : "unknown";

    if (!lower.includes("httponly")) {
      issues.push(`Cookie "${name}" is missing HttpOnly flag`);
    }
    if (!lower.includes("secure")) {
      issues.push(`Cookie "${name}" is missing Secure flag`);
    }
    if (!lower.includes("samesite")) {
      issues.push(`Cookie "${name}" is missing SameSite attribute`);
    }
  }

  return { issues };
}

async function checkApiExposure(baseUrl: string): Promise<{ paths: string[]; issues: string[] }> {
  const pathsToCheck = ["/api", "/api/health", "/health", "/docs", "/swagger"];
  const exposed: string[] = [];
  const issues: string[] = [];

  await Promise.all(
    pathsToCheck.map(async (p) => {
      try {
        const url = new URL(p, baseUrl).toString();
        validateSsrf(url);
        const res = await fetchWithTimeout(url, 3000, { method: "GET" });
        if (res.ok) {
          exposed.push(p);
          if (p === "/docs" || p === "/swagger") {
            // Only flag if the response is actually API docs (JSON/YAML), not an HTML SPA fallback
            const contentType = res.headers.get("content-type") ?? "";
            const isHtml = contentType.includes("text/html");
            if (!isHtml) {
              issues.push(`API docs exposed at ${p} — consider restricting access in production`);
            }
          }
        }
      } catch {
        // ignore
      }
    })
  );

  return { paths: exposed, issues };
}

export async function scanUrl(rawUrl: string): Promise<ScanResult> {
  const normalizedUrl = normalizeUrl(rawUrl);
  validateSsrf(normalizedUrl);

  const redirectChain: string[] = [normalizedUrl];
  const startTime = Date.now();

  let response: Response;
  try {
    response = await fetchWithTimeout(normalizedUrl, 8000, {
      redirect: "follow",
      headers: {
        "User-Agent": "DeployGuard/1.0 (Launch Readiness Scanner)",
        Accept: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
      },
    });
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    throw new Error(`Failed to fetch URL: ${msg}`);
  }

  const responseTimeMs = Date.now() - startTime;
  const finalUrl = response.url || normalizedUrl;

  // Track redirects
  if (finalUrl !== normalizedUrl) {
    redirectChain.push(finalUrl);
  }

  const statusCode = response.status;
  const usesHttps = finalUrl.startsWith("https://");

  // Parse HTML
  const html = await response.text();
  const htmlSizeKb = Buffer.byteLength(html, "utf8") / 1024;
  const root = parseHtml(html);

  // SEO/Meta
  const titleEl = root.querySelector("title");
  const title = titleEl?.text?.trim() ?? null;

  const metaDescEl = root.querySelector('meta[name="description"]');
  const metaDescription = metaDescEl?.getAttribute("content")?.trim() ?? null;

  const viewportEl = root.querySelector('meta[name="viewport"]');
  const hasViewport = !!viewportEl;

  const ogTitleEl = root.querySelector('meta[property="og:title"]');
  const hasOpenGraph = !!ogTitleEl;

  // Script count
  const scriptTagCount = root.querySelectorAll("script[src]").length;

  // Security headers
  const securityHeaders: Record<string, boolean> = {};
  for (const header of SECURITY_HEADERS) {
    securityHeaders[header] = !!response.headers.get(header);
  }

  // Cookies
  const { issues: cookieIssues } = analyzeCookies(response.headers);

  // Robots/Sitemap
  const [hasRobotsTxt, hasSitemapXml] = await Promise.all([
    checkFile(finalUrl, "/robots.txt"),
    checkFile(finalUrl, "/sitemap.xml"),
  ]);

  // API exposure
  const apiExposure = await checkApiExposure(finalUrl);

  // --- SCORING ---
  const issues: Array<{ category: string; severity: string; message: string; explanation: string; suggestion: string }> = [];

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
      explanation: "Your site is served over plain HTTP, which exposes users to eavesdropping and man-in-the-middle attacks.",
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
      suggestion: 'Add X-Frame-Options: DENY or SAMEORIGIN to your server response headers.',
    },
    "x-content-type-options": {
      explanation: "This header stops browsers from MIME-sniffing responses away from the declared content-type.",
      suggestion: "Add X-Content-Type-Options: nosniff to your server response headers.",
    },
    "referrer-policy": {
      explanation: "Controls how much referrer information is sent with requests, protecting user privacy.",
      suggestion: 'Add Referrer-Policy: strict-origin-when-cross-origin or no-referrer.',
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
      explanation: "The meta description is outside the optimal 120-160 character range.",
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

  // Robots/Sitemap (10 pts)
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
    if (cookieIssues.length === 0) {
      // Covered below
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

  // Calculate total score
  const totalScore = Math.min(
    100,
    Math.max(
      0,
      httpsScore + securityScore + seoScore + robotsScore + cookieScore + perfScore + apiScore
    )
  );

  const grade =
    totalScore >= 85 ? "Excellent" : totalScore >= 70 ? "Good" : totalScore >= 50 ? "Needs Work" : "Risky";

  const categoryScores = [
    { name: "HTTPS & Redirects", score: Math.round(httpsScore), maxScore: 15, label: httpsScore >= 12 ? "Good" : httpsScore >= 8 ? "Fair" : "Poor" },
    { name: "Security Headers", score: Math.round(securityScore), maxScore: 30, label: securityScore >= 24 ? "Good" : securityScore >= 15 ? "Fair" : "Poor" },
    { name: "SEO", score: Math.round(seoScore), maxScore: 20, label: seoScore >= 16 ? "Good" : seoScore >= 10 ? "Fair" : "Poor" },
    { name: "Robots & Sitemap", score: Math.round(robotsScore), maxScore: 10, label: robotsScore >= 8 ? "Good" : robotsScore >= 5 ? "Fair" : "Poor" },
    { name: "Cookies", score: Math.round(cookieScore), maxScore: 10, label: cookieScore >= 8 ? "Good" : cookieScore >= 5 ? "Fair" : "Poor" },
    { name: "Performance", score: Math.round(perfScore), maxScore: 10, label: perfScore >= 8 ? "Good" : perfScore >= 5 ? "Fair" : "Poor" },
    { name: "API Exposure", score: Math.round(apiScore), maxScore: 5, label: apiScore >= 4 ? "Good" : apiScore >= 2 ? "Fair" : "Poor" },
  ];

  // Generate fix prompt
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
  };
}
