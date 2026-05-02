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
} from "./scanner.js";

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
  it("returns no issues when no CORS headers are present", () => {
    const r = analyzeCors(null, null);
    expect(r.issues).toHaveLength(0);
    expect(r.pointsLost).toBe(0);
  });

  it("warns and deducts 3 pts for wildcard origin without credentials", () => {
    const r = analyzeCors("*", null);
    expect(r.pointsLost).toBe(3);
    expect(r.issues.some((i) => i.severity === "warning")).toBe(true);
  });

  it("warns and deducts 3 pts for wildcard + credentials=false", () => {
    const r = analyzeCors("*", "false");
    expect(r.pointsLost).toBe(3);
  });

  it("critical: wildcard origin + credentials=true is a dangerous misconfiguration", () => {
    const r = analyzeCors("*", "true");
    expect(r.pointsLost).toBe(4);
    expect(r.issues.some((i) => i.severity === "critical")).toBe(true);
  });

  it("no penalty for specific origin with credentials", () => {
    const r = analyzeCors("https://app.example.com", "true");
    expect(r.pointsLost).toBe(0);
    expect(r.issues.some((i) => i.severity === "passed")).toBe(true);
  });

  it("no issues for specific origin without credentials", () => {
    const r = analyzeCors("https://partner.example.com", null);
    expect(r.issues).toHaveLength(0);
    expect(r.pointsLost).toBe(0);
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
