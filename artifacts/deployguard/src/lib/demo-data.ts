import type { ScanResult, ScanIssueSeverity } from "@workspace/api-client-react/src/generated/api.schemas";

export const DEMO_SCAN_RESULT: ScanResult = {
  id: 999,
  url: "https://staging.acmecorp.dev",
  finalUrl: "https://staging.acmecorp.dev",
  score: 68,
  grade: "Needs Work",
  statusCode: 200,
  redirectChain: [],
  usesHttps: true,
  responseTimeMs: 845,
  title: "AcmeCorp Staging Environment",
  metaDescription: null,
  hasViewport: true,
  hasOpenGraph: false,
  hasRobotsTxt: true,
  hasSitemapXml: false,
  securityHeaders: {
    "strict-transport-security": true,
    "content-security-policy": false,
    "x-frame-options": false,
    "x-content-type-options": false
  },
  cookieIssues: ["Session cookie missing Secure flag", "Analytics cookie missing SameSite attribute"],
  htmlSizeKb: 142.5,
  scriptTagCount: 18,
  categoryScores: [
    { name: "Security", score: 12, maxScore: 30, label: "Poor" },
    { name: "SEO", score: 15, maxScore: 25, label: "Fair" },
    { name: "Performance", score: 21, maxScore: 25, label: "Good" },
    { name: "Best Practices", score: 20, maxScore: 20, label: "Excellent" }
  ],
  issues: [
    {
      category: "Security",
      severity: "critical" as ScanIssueSeverity,
      message: "Missing Content-Security-Policy",
      explanation: "No CSP header is present, leaving the application vulnerable to Cross-Site Scripting (XSS) attacks.",
      suggestion: "Add a Content-Security-Policy header. E.g., `Content-Security-Policy: default-src 'self'; img-src *;`"
    },
    {
      category: "Security",
      severity: "warning" as ScanIssueSeverity,
      message: "Insecure Cookies",
      explanation: "Session cookies are being set without the Secure and SameSite flags.",
      suggestion: "Update your session middleware to set `Secure: true` and `SameSite: 'Lax'` on all cookies."
    },
    {
      category: "SEO",
      severity: "warning" as ScanIssueSeverity,
      message: "Missing Meta Description",
      explanation: "Pages without meta descriptions may have poor click-through rates from search engines.",
      suggestion: "Add a `<meta name=\"description\" content=\"...\">` tag to the document head."
    },
    {
      category: "SEO",
      severity: "info" as ScanIssueSeverity,
      message: "Missing Sitemap",
      explanation: "No sitemap.xml was found at the root.",
      suggestion: "Generate an XML sitemap and reference it in your robots.txt."
    },
    {
      category: "Performance",
      severity: "warning" as ScanIssueSeverity,
      message: "High Script Count",
      explanation: "Found 18 script tags. Too many scripts can block the main thread and delay interactivity.",
      suggestion: "Bundle scripts, use `defer` or `async`, or remove unused dependencies."
    },
    {
      category: "Best Practices",
      severity: "passed" as ScanIssueSeverity,
      message: "Valid HTTPS",
      explanation: "The site forces a secure connection with valid TLS.",
      suggestion: ""
    }
  ],
  fixPrompt: "Please help me fix these launch-readiness issues on my web app:\n\n1. Security: Add Content-Security-Policy header to prevent XSS.\n2. Security: Configure session cookies with Secure=true and SameSite=Lax.\n3. SEO: Add missing <meta name=\"description\"> to the document head.\n4. SEO: Generate a sitemap.xml.\n5. Performance: Optimize bundle to reduce the 18 script tags currently loading.\n\nCould you provide code snippets to address these in a standard Node/React stack?",
  createdAt: new Date().toISOString()
};
