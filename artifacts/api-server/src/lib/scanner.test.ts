import { describe, it, expect } from "vitest";
import {
  normalizeUrl,
  isPrivateIp,
  validateSsrfSync,
  parseCspDirectives,
  analyzeCsp,
  analyzeHsts,
  analyzeCors,
  parseSetCookieHeaders,
  penaltyCurve,
  headlessScan,
} from "./scanner.js";
import { computeMlOverlay, buildFeatureVector } from "./ml-overlay.js";
import { scoreStructuredData } from "./structured-data.js";
import { scoreThirdPartyGovernance } from "./third-party.js";
import { computeAiOverlay } from "./ai-overlay.js";

// ============================================================
// normalizeUrl
// ============================================================

describe("normalizeUrl", () => {
  it("prepends https:// to a bare domain", () => {
    expect(normalizeUrl("example.com")).toBe("https://example.com");
  });
  it("prepends https:// to a domain with path", () => {
    expect(normalizeUrl("example.com/path?q=1")).toBe("https://example.com/path?q=1");
  });
  it("preserves https:// scheme", () => {
    expect(normalizeUrl("https://example.com")).toBe("https://example.com");
  });
  it("preserves http:// scheme", () => {
    expect(normalizeUrl("http://example.com")).toBe("http://example.com");
  });
  it("preserves ftp:// so validateSsrfSync can reject it", () => {
    expect(normalizeUrl("ftp://example.com")).toBe("ftp://example.com");
  });
  it("preserves file:// so validateSsrfSync can reject it", () => {
    expect(normalizeUrl("file:///etc/passwd")).toBe("file:///etc/passwd");
  });
  it("trims leading/trailing whitespace", () => {
    expect(normalizeUrl("  example.com  ")).toBe("https://example.com");
  });
  it("handles uppercase scheme correctly", () => {
    expect(normalizeUrl("HTTPS://example.com")).toBe("HTTPS://example.com");
  });
});

// ============================================================
// isPrivateIp
// ============================================================

describe("isPrivateIp", () => {
  it("blocks loopback 127.0.0.1", () => expect(isPrivateIp("127.0.0.1")).toBe(true));
  it("blocks loopback 127.0.0.2", () => expect(isPrivateIp("127.0.0.2")).toBe(true));
  it("blocks RFC1918 10.0.0.1", () => expect(isPrivateIp("10.0.0.1")).toBe(true));
  it("blocks RFC1918 10.255.255.255", () => expect(isPrivateIp("10.255.255.255")).toBe(true));
  it("blocks RFC1918 192.168.0.1", () => expect(isPrivateIp("192.168.0.1")).toBe(true));
  it("blocks RFC1918 172.16.0.1", () => expect(isPrivateIp("172.16.0.1")).toBe(true));
  it("blocks RFC1918 172.31.255.255", () => expect(isPrivateIp("172.31.255.255")).toBe(true));
  it("blocks link-local 169.254.169.254", () => expect(isPrivateIp("169.254.169.254")).toBe(true));
  it("blocks link-local 169.254.0.1", () => expect(isPrivateIp("169.254.0.1")).toBe(true));
  it("blocks zero network 0.0.0.0", () => expect(isPrivateIp("0.0.0.0")).toBe(true));
  it("blocks CGNAT 100.64.0.1", () => expect(isPrivateIp("100.64.0.1")).toBe(true));
  it("blocks CGNAT 100.127.255.255", () => expect(isPrivateIp("100.127.255.255")).toBe(true));
  it("blocks TEST-NET 192.0.2.1", () => expect(isPrivateIp("192.0.2.1")).toBe(true));
  it("allows public 8.8.8.8", () => expect(isPrivateIp("8.8.8.8")).toBe(false));
  it("allows public 1.1.1.1", () => expect(isPrivateIp("1.1.1.1")).toBe(false));
  it("allows public 172.15.0.1 (just below RFC1918 range)", () => expect(isPrivateIp("172.15.0.1")).toBe(false));
  it("allows public 172.32.0.1 (just above RFC1918 range)", () => expect(isPrivateIp("172.32.0.1")).toBe(false));
  it("allows public 100.63.255.255 (just below CGNAT)", () => expect(isPrivateIp("100.63.255.255")).toBe(false));
  it("blocks IPv6 loopback ::1", () => expect(isPrivateIp("::1")).toBe(true));
  it("blocks ULA fc00::1", () => expect(isPrivateIp("fc00::1")).toBe(true));
  it("blocks ULA fd00::1", () => expect(isPrivateIp("fd00::1")).toBe(true));
  it("blocks ULA fdc3:1234::1", () => expect(isPrivateIp("fdc3:1234::1")).toBe(true));
  it("blocks link-local fe80::1", () => expect(isPrivateIp("fe80::1")).toBe(true));
  it("blocks IPv4-mapped ::ffff:10.0.0.1", () => expect(isPrivateIp("::ffff:10.0.0.1")).toBe(true));
  it("allows public 2001:db8::1", () => expect(isPrivateIp("2001:db8::1")).toBe(false));
  it("allows public 2606:4700::1", () => expect(isPrivateIp("2606:4700::1")).toBe(false));
});

// ============================================================
// validateSsrfSync
// ============================================================

describe("validateSsrfSync", () => {
  it("blocks ftp:// scheme", () => {
    expect(() => validateSsrfSync("ftp://example.com")).toThrow("Only http and https");
  });
  it("blocks file:// scheme", () => {
    expect(() => validateSsrfSync("file:///etc/passwd")).toThrow("Only http and https");
  });
  it("blocks gopher:// scheme", () => {
    expect(() => validateSsrfSync("gopher://example.com")).toThrow("Only http and https");
  });
  it("allows http://", () => {
    expect(() => validateSsrfSync("http://example.com")).not.toThrow();
  });
  it("allows https://", () => {
    expect(() => validateSsrfSync("https://example.com")).not.toThrow();
  });
  it("blocks localhost", () => {
    expect(() => validateSsrfSync("http://localhost")).toThrow("Blocked hostname");
  });
  it("blocks 0.0.0.0", () => {
    expect(() => validateSsrfSync("http://0.0.0.0")).toThrow();
  });
  it("blocks metadata.google.internal", () => {
    expect(() => validateSsrfSync("http://metadata.google.internal")).toThrow("Blocked hostname");
  });
  it("blocks 127.0.0.1 (loopback IP literal)", () => {
    expect(() => validateSsrfSync("http://127.0.0.1")).toThrow();
  });
  it("blocks 169.254.169.254 (AWS metadata IP literal)", () => {
    expect(() => validateSsrfSync("http://169.254.169.254/latest/meta-data")).toThrow();
  });
  it("blocks 10.0.0.1 (private IP literal)", () => {
    expect(() => validateSsrfSync("http://10.0.0.1")).toThrow();
  });
  it("blocks 192.168.1.1 (private IP literal)", () => {
    expect(() => validateSsrfSync("http://192.168.1.1")).toThrow();
  });
  it("blocks ::1 (IPv6 loopback bracket notation)", () => {
    expect(() => validateSsrfSync("http://[::1]")).toThrow();
  });
  it("allows a normal public URL", () => {
    expect(() => validateSsrfSync("https://github.com")).not.toThrow();
  });
  it("allows a public URL with path and query", () => {
    expect(() => validateSsrfSync("https://api.example.com/v1/data?token=abc")).not.toThrow();
  });
  it("throws on genuinely malformed URL", () => {
    expect(() => validateSsrfSync("not a url")).toThrow("Invalid URL");
  });
});

// ============================================================
// parseCspDirectives
// ============================================================

describe("parseCspDirectives", () => {
  it("parses a simple CSP with two directives", () => {
    const m = parseCspDirectives("default-src 'self'; script-src 'self' cdn.example.com");
    expect(m.get("default-src")).toEqual(["'self'"]);
    expect(m.get("script-src")).toEqual(["'self'", "cdn.example.com"]);
  });

  it("parses a directive with no tokens (e.g. upgrade-insecure-requests)", () => {
    const m = parseCspDirectives("upgrade-insecure-requests");
    expect(m.get("upgrade-insecure-requests")).toEqual([]);
  });

  it("lowercases directive names and token values", () => {
    const m = parseCspDirectives("Script-Src 'Unsafe-Inline' CDN.Example.COM");
    expect(m.has("script-src")).toBe(true);
    expect(m.get("script-src")).toEqual(["'unsafe-inline'", "cdn.example.com"]);
  });

  it("handles trailing semicolons gracefully", () => {
    const m = parseCspDirectives("default-src 'self';");
    expect(m.has("default-src")).toBe(true);
    expect(m.get("default-src")).toEqual(["'self'"]);
  });

  it("parses multiple directives with extra whitespace", () => {
    const m = parseCspDirectives("  default-src  'self'  ;  frame-ancestors  'none'  ");
    expect(m.get("default-src")).toEqual(["'self'"]);
    expect(m.get("frame-ancestors")).toEqual(["'none'"]);
  });

  it("parses frame-ancestors with multiple origins", () => {
    const m = parseCspDirectives("frame-ancestors https://app.example.com https://dashboard.example.com");
    expect(m.get("frame-ancestors")).toEqual(["https://app.example.com", "https://dashboard.example.com"]);
  });
});

// ============================================================
// analyzeCsp — CSP weakness detection
// ============================================================

describe("analyzeCsp", () => {
  it("returns score 0 and critical issue when CSP is missing", () => {
    const r = analyzeCsp(null);
    expect(r.score).toBe(0);
    expect(r.penalties[0]?.pointsLost).toBe(12);
    expect(r.issues.some((i) => i.severity === "critical")).toBe(true);
  });

  it("returns full score 12 for a tight CSP with nonce", () => {
    const csp =
      "default-src 'none'; script-src 'nonce-abc123' 'strict-dynamic'; object-src 'none'; frame-ancestors 'none'";
    const r = analyzeCsp(csp);
    expect(r.score).toBe(12);
    expect(r.issues.some((i) => i.severity === "critical")).toBe(false);
  });

  it("deducts 3 pts for missing default-src", () => {
    const r = analyzeCsp("script-src 'self'; object-src 'none'; frame-ancestors 'none'");
    expect(r.score).toBeLessThanOrEqual(9);
    expect(r.penalties.some((p) => p.message.includes("default-src"))).toBe(true);
  });

  it("deducts 2 pts for wildcard in default-src", () => {
    const r = analyzeCsp("default-src *; frame-ancestors 'none'");
    const wildcardPenalty = r.penalties.find((p) => p.message.includes("wildcard"));
    expect(wildcardPenalty).toBeDefined();
    expect(wildcardPenalty?.pointsLost).toBe(2);
  });

  it("deducts 1 pt for data: in default-src", () => {
    const r = analyzeCsp("default-src 'self' data:; frame-ancestors 'none'");
    expect(r.penalties.some((p) => p.message.includes("data:"))).toBe(true);
  });

  it("deducts 2 pts for unsafe-inline in script-src", () => {
    const r = analyzeCsp("default-src 'self'; script-src 'self' 'unsafe-inline'; frame-ancestors 'none'");
    const p = r.penalties.find((pen) => pen.message.includes("unsafe-inline"));
    expect(p?.pointsLost).toBe(2);
  });

  it("deducts 2 pts for unsafe-eval in script-src", () => {
    const r = analyzeCsp("default-src 'self'; script-src 'self' 'unsafe-eval'; frame-ancestors 'none'");
    const p = r.penalties.find((pen) => pen.message.includes("unsafe-eval"));
    expect(p?.pointsLost).toBe(2);
  });

  it("deducts 1 pt for missing frame-ancestors", () => {
    const r = analyzeCsp("default-src 'self'; script-src 'self'; object-src 'none'");
    expect(r.penalties.some((p) => p.message.includes("frame-ancestors"))).toBe(true);
  });

  it("deducts 1 pt for permissive frame-ancestors *", () => {
    const r = analyzeCsp("default-src 'self'; frame-ancestors *");
    expect(r.penalties.some((p) => p.message.includes("frame-ancestors") && p.message.includes("permissive"))).toBe(true);
  });

  it("gives bonus +1 for strict-dynamic in script-src (score capped at 12)", () => {
    const csp = "default-src 'none'; script-src 'strict-dynamic'; object-src 'none'; frame-ancestors 'none'";
    const r = analyzeCsp(csp);
    expect(r.score).toBe(12);
  });

  it("CSP with only unsafe-inline and unsafe-eval is heavily penalised", () => {
    const r = analyzeCsp("default-src 'self' 'unsafe-inline' 'unsafe-eval'");
    expect(r.score).toBeLessThanOrEqual(8);
    expect(r.penalties.length).toBeGreaterThanOrEqual(2);
  });

  it("floor is 0 even with many deductions", () => {
    const r = analyzeCsp("default-src * 'unsafe-inline' 'unsafe-eval' data:");
    expect(r.score).toBeGreaterThanOrEqual(0);
  });
});

// ============================================================
// analyzeHsts — completeness checks
// ============================================================

describe("analyzeHsts", () => {
  it("returns score 0 and critical issue when HSTS missing on HTTPS site", () => {
    const r = analyzeHsts(null, true);
    expect(r.score).toBe(0);
    expect(r.issues.some((i) => i.severity === "critical")).toBe(true);
    expect(r.penalties[0]?.pointsLost).toBe(9);
  });

  it("returns score 0 with info (not critical) when HSTS missing on HTTP site", () => {
    const r = analyzeHsts(null, false);
    expect(r.score).toBe(0);
    expect(r.issues.some((i) => i.severity === "critical")).toBe(false);
    expect(r.issues.some((i) => i.severity === "info")).toBe(true);
  });

  it("returns full score 9 for perfect HSTS", () => {
    const r = analyzeHsts("max-age=31536000; includeSubDomains; preload", true);
    expect(r.score).toBe(9);
    expect(r.issues.filter((i) => i.severity === "critical" || i.severity === "warning")).toHaveLength(0);
  });

  it("deducts 3 pts for max-age below 6 months (15768000s)", () => {
    const r = analyzeHsts("max-age=3600; includeSubDomains; preload", true);
    expect(r.penalties.some((p) => p.message.includes("max-age") && p.pointsLost === 3)).toBe(true);
    expect(r.score).toBe(9 - 3);
  });

  it("deducts 3 pts when max-age is missing from header", () => {
    const r = analyzeHsts("includeSubDomains; preload", true);
    expect(r.penalties.some((p) => p.pointsLost === 3)).toBe(true);
  });

  it("deducts 2 pts for missing includeSubDomains", () => {
    const r = analyzeHsts("max-age=31536000; preload", true);
    expect(r.penalties.some((p) => p.message.includes("includeSubDomains") && p.pointsLost === 2)).toBe(true);
    expect(r.score).toBe(9 - 2);
  });

  it("deducts 1 pt for missing preload", () => {
    const r = analyzeHsts("max-age=31536000; includeSubDomains", true);
    expect(r.penalties.some((p) => p.message.includes("preload") && p.pointsLost === 1)).toBe(true);
    expect(r.score).toBe(9 - 1);
  });

  it("HSTS with only short max-age gets score 9-3-2-1=3", () => {
    const r = analyzeHsts("max-age=100", true);
    expect(r.score).toBe(3);
  });

  it("score is never negative", () => {
    const r = analyzeHsts("max-age=1", true);
    expect(r.score).toBeGreaterThanOrEqual(0);
  });

  it("is case-insensitive for includeSubDomains and preload", () => {
    const r = analyzeHsts("max-age=31536000; IncludeSubDomains; PRELOAD", true);
    expect(r.score).toBe(9);
  });
});

// ============================================================
// analyzeCors — permissive CORS detection
// ============================================================

describe("analyzeCors", () => {
  it("returns score 10 and a passed issue when no CORS headers are present", () => {
    const r = analyzeCors(null, null);
    expect(r.score).toBe(10);
    expect(r.severity).toBe("none");
    expect(r.issues.some((i) => i.severity === "passed")).toBe(true);
  });

  it("deducts 4 pts (score 6) for wildcard origin without credentials", () => {
    const r = analyzeCors("*", null);
    expect(r.score).toBe(6);
    expect(r.severity).toBe("warn");
    expect(r.issues.some((i) => i.severity === "warning")).toBe(true);
  });

  it("deducts 4 pts (score 6) for wildcard + credentials=false", () => {
    const r = analyzeCors("*", "false");
    expect(r.score).toBe(6);
    expect(r.severity).toBe("warn");
  });

  it("critical: wildcard + credentials=true → score 2", () => {
    const r = analyzeCors("*", "true");
    expect(r.score).toBe(2);
    expect(r.severity).toBe("critical");
    expect(r.issues.some((i) => i.severity === "critical")).toBe(true);
  });

  it("no penalty for specific origin with credentials → score 10", () => {
    const r = analyzeCors("https://app.example.com", "true");
    expect(r.score).toBe(10);
    expect(r.issues.some((i) => i.severity === "passed")).toBe(true);
  });

  it("score 10 for specific origin without credentials", () => {
    const r = analyzeCors("https://partner.example.com", null);
    expect(r.score).toBe(10);
  });

  it("additional -2 for permissive methods (DELETE/PUT/PATCH) with wildcard origin", () => {
    const r = analyzeCors("*", null, "GET, POST, DELETE, PUT");
    expect(r.score).toBeLessThanOrEqual(4);
    expect(r.penalties.length).toBeGreaterThan(1);
    expect(r.issues.some((i) => i.message.toLowerCase().includes("method"))).toBe(true);
  });

  it("no extra penalty for permissive methods when origin is specific", () => {
    const r = analyzeCors("https://api.example.com", null, "GET, POST, DELETE");
    expect(r.score).toBe(10);
  });

  it("additional -1 for Authorization header in ACAH with wildcard origin", () => {
    const r = analyzeCors("*", null, null, "Authorization, Content-Type");
    expect(r.score).toBeLessThanOrEqual(5);
    expect(r.issues.some((i) => i.message.toLowerCase().includes("header"))).toBe(true);
  });

  it("clamps score to 0 minimum for multiple stacked deductions", () => {
    const r = analyzeCors("*", "true", "GET, DELETE, PUT", "Authorization");
    expect(r.score).toBeGreaterThanOrEqual(0);
    expect(r.severity).toBe("critical");
  });
});

// ============================================================
// parseSetCookieHeaders
// ============================================================

describe("parseSetCookieHeaders", () => {
  it("parses a fully-secured cookie correctly", () => {
    const cookies = parseSetCookieHeaders([
      "sessionId=abc123; Secure; HttpOnly; SameSite=Lax; Path=/",
    ]);
    expect(cookies).toHaveLength(1);
    const c = cookies[0]!;
    expect(c.name).toBe("sessionId");
    expect(c.hasSecure).toBe(true);
    expect(c.hasHttpOnly).toBe(true);
    expect(c.sameSite).toBe("lax");
    expect(c.path).toBe("/");
  });

  it("detects missing Secure flag", () => {
    const [c] = parseSetCookieHeaders(["token=xyz; HttpOnly; SameSite=Strict"]);
    expect(c?.hasSecure).toBe(false);
    expect(c?.hasHttpOnly).toBe(true);
    expect(c?.sameSite).toBe("strict");
  });

  it("detects missing HttpOnly flag", () => {
    const [c] = parseSetCookieHeaders(["pref=dark; Secure; SameSite=Lax"]);
    expect(c?.hasHttpOnly).toBe(false);
    expect(c?.hasSecure).toBe(true);
  });

  it("detects SameSite=None", () => {
    const [c] = parseSetCookieHeaders(["crossSite=1; Secure; SameSite=None"]);
    expect(c?.sameSite).toBe("none");
    expect(c?.hasSecure).toBe(true);
  });

  it("detects SameSite=None without Secure (dangerous)", () => {
    const [c] = parseSetCookieHeaders(["crossSite=1; SameSite=None"]);
    expect(c?.sameSite).toBe("none");
    expect(c?.hasSecure).toBe(false);
  });

  it("parses Max-Age correctly", () => {
    const [c] = parseSetCookieHeaders(["persist=1; Secure; HttpOnly; SameSite=Lax; Max-Age=31536000"]);
    expect(c?.maxAge).toBe(31536000);
  });

  it("parses Domain attribute", () => {
    const [c] = parseSetCookieHeaders(["user=1; Secure; Domain=example.com; SameSite=Lax"]);
    expect(c?.domain).toBe("example.com");
  });

  it("strips leading dot from Domain attribute", () => {
    const [c] = parseSetCookieHeaders(["user=1; Secure; Domain=.example.com; SameSite=Lax"]);
    expect(c?.domain).toBe("example.com");
  });

  it("handles missing SameSite attribute", () => {
    const [c] = parseSetCookieHeaders(["id=abc; Secure; HttpOnly"]);
    expect(c?.sameSite).toBeNull();
  });

  it("parses multiple cookies", () => {
    const cookies = parseSetCookieHeaders([
      "a=1; Secure; HttpOnly; SameSite=Lax",
      "b=2; HttpOnly; SameSite=Strict",
    ]);
    expect(cookies).toHaveLength(2);
    expect(cookies[0]?.name).toBe("a");
    expect(cookies[1]?.name).toBe("b");
    expect(cookies[1]?.hasSecure).toBe(false);
  });

  it("handles empty cookie name gracefully", () => {
    const [c] = parseSetCookieHeaders(["=noname; Secure"]);
    expect(c).toBeDefined();
    expect(c?.hasSecure).toBe(true);
  });
});

// ============================================================
// penaltyCurve — math verification
// ============================================================

describe("penaltyCurve", () => {
  it("returns 0 when value is at the free threshold", () => {
    expect(penaltyCurve(300, 300, 5, 2000)).toBe(0);
  });

  it("returns 0 when value is below the free threshold", () => {
    expect(penaltyCurve(0, 300, 5, 2000)).toBe(0);
    expect(penaltyCurve(100, 300, 5, 2000)).toBe(0);
    expect(penaltyCurve(299, 300, 5, 2000)).toBe(0);
  });

  it("returns maxPenalty when value is at the full-penalty threshold", () => {
    expect(penaltyCurve(2000, 300, 5, 2000)).toBe(5);
  });

  it("returns maxPenalty when value exceeds the full-penalty threshold", () => {
    expect(penaltyCurve(9999, 300, 5, 2000)).toBe(5);
    expect(penaltyCurve(2001, 300, 5, 2000)).toBe(5);
  });

  it("returns proportional value at midpoint", () => {
    const mid = (300 + 2000) / 2;
    const penalty = penaltyCurve(mid, 300, 5, 2000);
    expect(penalty).toBeCloseTo(2.5, 1);
  });

  it("response time curve: 1000ms gives ~2.06 pts penalty", () => {
    const penalty = penaltyCurve(1000, 300, 5, 2000);
    expect(penalty).toBeCloseTo(2.06, 1);
  });

  it("page size curve: 500KB gives ~0.73 pts penalty", () => {
    const penalty = penaltyCurve(500, 250, 5, 2048);
    expect(penalty).toBeCloseTo(0.73, 1);
  });

  it("script count curve: 35 scripts gives ~2.5 pts penalty", () => {
    const penalty = penaltyCurve(35, 10, 5, 60);
    expect(penalty).toBeCloseTo(2.5, 1);
  });

  it("penalty is monotonically increasing", () => {
    const values = [0, 300, 500, 1000, 1500, 2000, 3000];
    const penalties = values.map((v) => penaltyCurve(v, 300, 5, 2000));
    for (let i = 1; i < penalties.length; i++) {
      expect(penalties[i]!).toBeGreaterThanOrEqual(penalties[i - 1]!);
    }
  });

  it("handles freeThreshold === fullPenaltyAt edge case without throwing", () => {
    expect(() => penaltyCurve(500, 500, 5, 500)).not.toThrow();
  });
});

// ============================================================
// headlessScan — feature gate (HEADLESS_SCAN env)
// ============================================================

describe("headlessScan", () => {
  it("returns null when HEADLESS_SCAN is not set (default off)", async () => {
    delete process.env.HEADLESS_SCAN;
    const result = await headlessScan("https://example.com");
    expect(result).toBeNull();
  });

  it("returns a HeadlessResult (not null) when HEADLESS_SCAN=true", async () => {
    process.env.HEADLESS_SCAN = "true";
    const result = await headlessScan("https://example.com");
    expect(result).not.toBeNull();
    // Result shape is valid regardless of whether playwright+chromium are installed
    expect(typeof result?.available).toBe("boolean");
    expect("headlessScore" in (result ?? {})).toBe(true);
    delete process.env.HEADLESS_SCAN;
  }, 30_000);
});

// ============================================================
// ML Overlay — deterministic rule-based stub
// ============================================================

describe("computeMlOverlay", () => {
  const baseFeatures = () =>
    buildFeatureVector({
      httpsScore: 10,
      securityScore: 28,
      corsScore: 10,
      cookieScore: 15,
      cacheScore: 7,
      perfScore: 14,
      seoScore: 6,
      a11yScore: 5,
      totalScore: 95,
      issues: [],
      cookieCount: 0,
      hasCSP: true,
      hasHSTS: true,
      usesHttps: true,
      hasCriticalCors: false,
      hasNoindex: false,
    });

  it("returns a valid MlOverlayResult", () => {
    const result = computeMlOverlay(baseFeatures());
    expect(result.adjustedGrade).toBeDefined();
    expect(typeof result.confidence).toBe("number");
    expect(result.confidence).toBeGreaterThan(0);
    expect(result.confidence).toBeLessThanOrEqual(1);
    expect(result.rationale).toBeTruthy();
    expect(Array.isArray(result.featureImportance)).toBe(true);
  });

  it("rates a near-perfect site as Excellent with high confidence", () => {
    const result = computeMlOverlay(baseFeatures());
    expect(result.adjustedGrade).toBe("Excellent");
    expect(result.confidence).toBeGreaterThanOrEqual(0.85);
  });

  it("hard-downgrades to Risky when usesHttps is false regardless of score", () => {
    const features = buildFeatureVector({
      ...baseFeatures(),
      usesHttps: false,
      httpsScore: 0,
      totalScore: 65,
      issues: [{ severity: "critical", category: "HTTPS & Redirects" }],
    });
    const result = computeMlOverlay(features);
    expect(result.adjustedGrade).toBe("Risky");
    expect(result.confidence).toBeGreaterThanOrEqual(0.9);
  });

  it("downgrades to Needs Work when critical CORS misconfiguration is present", () => {
    const features = buildFeatureVector({
      ...baseFeatures(),
      hasCriticalCors: true,
      corsScore: 2,
      totalScore: 88,
      issues: [{ severity: "critical", category: "CORS" }],
    });
    const result = computeMlOverlay(features);
    expect(result.adjustedGrade).not.toBe("Excellent");
  });

  it("feature importance list has at most 5 entries", () => {
    const result = computeMlOverlay(baseFeatures());
    expect(result.featureImportance.length).toBeLessThanOrEqual(5);
  });

  it("buildFeatureVector maps criticalCount correctly", () => {
    const features = buildFeatureVector({
      ...baseFeatures(),
      issues: [
        { severity: "critical", category: "Security Headers" },
        { severity: "critical", category: "CORS" },
        { severity: "warning", category: "Cache & Exposure" },
      ],
    });
    expect(features.criticalCount).toBe(2);
    expect(features.warningCount).toBe(1);
  });

  it("buildFeatureVector defaults thirdPartyScore to 10 when not supplied", () => {
    const features = buildFeatureVector({
      httpsScore: 10, securityScore: 28, corsScore: 10, cookieScore: 15,
      cacheScore: 7, perfScore: 14, seoScore: 6, a11yScore: 5,
      totalScore: 95, issues: [], cookieCount: 0,
      hasCSP: true, hasHSTS: true, usesHttps: true, hasCriticalCors: false, hasNoindex: false,
    });
    expect(features.thirdPartyScore).toBe(10);
  });

  it("buildFeatureVector defaults structuredDataScore to 0 when not supplied", () => {
    const features = buildFeatureVector({
      httpsScore: 10, securityScore: 28, corsScore: 10, cookieScore: 15,
      cacheScore: 7, perfScore: 14, seoScore: 6, a11yScore: 5,
      totalScore: 95, issues: [], cookieCount: 0,
      hasCSP: true, hasHSTS: true, usesHttps: true, hasCriticalCors: false, hasNoindex: false,
    });
    expect(features.structuredDataScore).toBe(0);
  });

  it("buildFeatureVector stores thirdPartyScore and structuredDataScore when provided", () => {
    const features = buildFeatureVector({
      httpsScore: 10, securityScore: 28, corsScore: 10, cookieScore: 15,
      cacheScore: 7, perfScore: 14, seoScore: 6, a11yScore: 5,
      thirdPartyScore: 7, structuredDataScore: 4,
      totalScore: 85, issues: [], cookieCount: 0,
      hasCSP: true, hasHSTS: true, usesHttps: true, hasCriticalCors: false, hasNoindex: false,
    });
    expect(features.thirdPartyScore).toBe(7);
    expect(features.structuredDataScore).toBe(4);
  });
});

// ============================================================
// scoreStructuredData
// ============================================================

describe("scoreStructuredData", () => {
  it("scores 0 when no JSON-LD is present", () => {
    const r = scoreStructuredData("<html><body><p>Hello</p></body></html>");
    expect(r.score).toBe(0);
    expect(r.blockCount).toBe(0);
    expect(r.validBlockCount).toBe(0);
    expect(r.issues.some((i) => i.severity === "info")).toBe(true);
  });

  it("scores 5 for a perfect JSON-LD Organization block", () => {
    const html = `<script type="application/ld+json">{"@context":"https://schema.org","@type":"Organization","name":"Acme","url":"https://acme.com"}</script>`;
    const r = scoreStructuredData(html);
    expect(r.score).toBe(5);
    expect(r.blockCount).toBe(1);
    expect(r.validBlockCount).toBe(1);
  });

  it("deducts 1pt for missing @context", () => {
    const html = `<script type="application/ld+json">{"@type":"Organization","name":"Acme","url":"https://acme.com"}</script>`;
    const r = scoreStructuredData(html);
    expect(r.score).toBeLessThan(5);
    expect(r.penalties.some((p) => p.message.includes("@context"))).toBe(true);
  });

  it("deducts 1pt for missing @type", () => {
    const html = `<script type="application/ld+json">{"@context":"https://schema.org","name":"Acme"}</script>`;
    const r = scoreStructuredData(html);
    expect(r.score).toBeLessThan(5);
    expect(r.penalties.some((p) => p.message.includes("@type"))).toBe(true);
  });

  it("deducts 2pts for malformed JSON", () => {
    const html = `<script type="application/ld+json">{invalid json here}</script>`;
    const r = scoreStructuredData(html);
    expect(r.score).toBeLessThanOrEqual(3);
    expect(r.penalties.some((p) => p.pointsLost === 2)).toBe(true);
  });

  it("score is always in range 0-5", () => {
    const html = `<script type="application/ld+json">{bad}{also bad}</script><script type="application/ld+json">{again bad}</script>`;
    const r = scoreStructuredData(html);
    expect(r.score).toBeGreaterThanOrEqual(0);
    expect(r.score).toBeLessThanOrEqual(5);
  });
});

// ============================================================
// scoreThirdPartyGovernance
// ============================================================

describe("scoreThirdPartyGovernance", () => {
  it("scores 10 when no scripts are present", () => {
    const r = scoreThirdPartyGovernance("<html><body></body></html>", "https://example.com");
    expect(r.score).toBe(10);
    expect(r.thirdPartyScripts).toBe(0);
  });

  it("scores 10 when all scripts are same-origin", () => {
    const html = `<script src="/js/app.js"></script><script src="https://example.com/lib.js"></script>`;
    const r = scoreThirdPartyGovernance(html, "https://example.com");
    expect(r.score).toBe(10);
    expect(r.thirdPartyScripts).toBe(0);
  });

  it("deducts points for third-party scripts from known CDN", () => {
    const html = `<script src="https://cdn.jsdelivr.net/npm/axios.min.js"></script>`;
    const r = scoreThirdPartyGovernance(html, "https://example.com");
    expect(r.thirdPartyScripts).toBe(1);
    expect(r.score).toBeLessThan(10);
    expect(r.unknownDomains).not.toContain("cdn.jsdelivr.net");
  });

  it("adds unknown domain penalty for unrecognized script source", () => {
    const html = `<script src="https://unknown-analytics.io/track.js"></script>`;
    const r = scoreThirdPartyGovernance(html, "https://example.com");
    expect(r.thirdPartyScripts).toBe(1);
    expect(r.unknownDomains).toContain("unknown-analytics.io");
    expect(r.thirdPartyDomains).toContain("unknown-analytics.io");
  });

  it("score is always in range 0-10", () => {
    const manyScripts = Array.from({ length: 30 }, (_, i) =>
      `<script src="https://thirdparty${i}.io/track.js"></script>`
    ).join("");
    const r = scoreThirdPartyGovernance(manyScripts, "https://example.com");
    expect(r.score).toBeGreaterThanOrEqual(0);
    expect(r.score).toBeLessThanOrEqual(10);
  });

  it("counts correct thirdPartyDomains list", () => {
    const html = `
      <script src="https://fonts.googleapis.com/font.js"></script>
      <script src="https://cdn.jsdelivr.net/lib.js"></script>
      <script src="https://malicious-tracker.io/t.js"></script>
    `;
    const r = scoreThirdPartyGovernance(html, "https://example.com");
    expect(r.thirdPartyDomains).toContain("fonts.googleapis.com");
    expect(r.thirdPartyDomains).toContain("cdn.jsdelivr.net");
    expect(r.thirdPartyDomains).toContain("malicious-tracker.io");
    expect(r.thirdPartyDomains.length).toBe(3);
  });
});

// ============================================================
// computeAiOverlay — feature gate (LOCAL_AI env)
// ============================================================

describe("computeAiOverlay", () => {
  const features = buildFeatureVector({
    httpsScore: 10,
    securityScore: 28,
    corsScore: 10,
    cookieScore: 10,
    cacheScore: 5,
    perfScore: 8,
    seoScore: 6,
    a11yScore: 5,
    thirdPartyScore: 10,
    structuredDataScore: 3,
    totalScore: 90,
    issues: [],
    cookieCount: 0,
    hasCSP: true,
    hasHSTS: true,
    usesHttps: true,
    hasCriticalCors: false,
    hasNoindex: false,
  });

  it("returns null when LOCAL_AI is not set (default off)", async () => {
    delete process.env.LOCAL_AI;
    const result = await computeAiOverlay(features, []);
    expect(result).toBeNull();
  });

  it("returns null when LOCAL_AI=false", async () => {
    process.env.LOCAL_AI = "false";
    const result = await computeAiOverlay(features, []);
    expect(result).toBeNull();
    delete process.env.LOCAL_AI;
  });

  it("returns an AiOverlayResult (deterministic fallback) when LOCAL_AI=true and no model", async () => {
    process.env.LOCAL_AI = "true";
    delete process.env.LOCAL_AI_MODEL_PATH;
    const result = await computeAiOverlay(features, ["[Security] Missing CSP (-5 pts)"]);
    expect(result).not.toBeNull();
    expect(result!.aiScore).toBeGreaterThanOrEqual(0);
    expect(result!.aiScore).toBeLessThanOrEqual(100);
    expect(["Low", "Moderate", "High", "Critical"]).toContain(result!.riskLabel);
    expect(result!.rationale).toBeTruthy();
    expect(result!.engineUsed).toBe("deterministic-rules");
    delete process.env.LOCAL_AI;
  });

  it("sets riskLabel Low for high-scoring site", async () => {
    process.env.LOCAL_AI = "true";
    delete process.env.LOCAL_AI_MODEL_PATH;
    const result = await computeAiOverlay(features, []);
    expect(result!.riskLabel).toBe("Low");
    delete process.env.LOCAL_AI;
  });

  it("sets riskLabel Critical for HTTP site with many critical issues", async () => {
    process.env.LOCAL_AI = "true";
    delete process.env.LOCAL_AI_MODEL_PATH;
    const badFeatures = buildFeatureVector({
      httpsScore: 0,
      securityScore: 0,
      corsScore: 0,
      cookieScore: 0,
      cacheScore: 0,
      perfScore: 0,
      seoScore: 0,
      a11yScore: 0,
      thirdPartyScore: 0,
      structuredDataScore: 0,
      totalScore: 0,
      issues: [
        { severity: "critical", category: "HTTPS & Redirects" },
        { severity: "critical", category: "Security Headers" },
        { severity: "critical", category: "CORS" },
        { severity: "critical", category: "Cookies" },
      ],
      cookieCount: 5,
      hasCSP: false,
      hasHSTS: false,
      usesHttps: false,
      hasCriticalCors: true,
      hasNoindex: true,
    });
    const result = await computeAiOverlay(badFeatures, []);
    expect(result!.riskLabel).toBe("Critical");
    delete process.env.LOCAL_AI;
  });
});
