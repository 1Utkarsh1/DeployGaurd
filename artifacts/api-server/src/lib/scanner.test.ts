import { describe, it, expect } from "vitest";
import { normalizeUrl, isPrivateIp, validateSsrfSync } from "./scanner.js";

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
  // IPv4 — should block
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

  // IPv4 — should allow
  it("allows public 8.8.8.8", () => expect(isPrivateIp("8.8.8.8")).toBe(false));
  it("allows public 1.1.1.1", () => expect(isPrivateIp("1.1.1.1")).toBe(false));
  it("allows public 172.15.0.1 (just below RFC1918 range)", () => expect(isPrivateIp("172.15.0.1")).toBe(false));
  it("allows public 172.32.0.1 (just above RFC1918 range)", () => expect(isPrivateIp("172.32.0.1")).toBe(false));
  it("allows public 100.63.255.255 (just below CGNAT)", () => expect(isPrivateIp("100.63.255.255")).toBe(false));

  // IPv6 — should block
  it("blocks IPv6 loopback ::1", () => expect(isPrivateIp("::1")).toBe(true));
  it("blocks ULA fc00::1", () => expect(isPrivateIp("fc00::1")).toBe(true));
  it("blocks ULA fd00::1", () => expect(isPrivateIp("fd00::1")).toBe(true));
  it("blocks ULA fdc3:1234::1", () => expect(isPrivateIp("fdc3:1234::1")).toBe(true));
  it("blocks link-local fe80::1", () => expect(isPrivateIp("fe80::1")).toBe(true));
  it("blocks IPv4-mapped ::ffff:10.0.0.1", () => expect(isPrivateIp("::ffff:10.0.0.1")).toBe(true));

  // IPv6 — should allow
  it("allows public 2001:db8::1", () => expect(isPrivateIp("2001:db8::1")).toBe(false));
  it("allows public 2606:4700::1", () => expect(isPrivateIp("2606:4700::1")).toBe(false));
});

// ============================================================
// validateSsrfSync
// ============================================================

describe("validateSsrfSync", () => {
  // Protocol blocking
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

  // Blocked hostnames
  it("blocks localhost", () => {
    expect(() => validateSsrfSync("http://localhost")).toThrow("Blocked hostname");
  });
  it("blocks 0.0.0.0", () => {
    expect(() => validateSsrfSync("http://0.0.0.0")).toThrow();
  });
  it("blocks metadata.google.internal", () => {
    expect(() => validateSsrfSync("http://metadata.google.internal")).toThrow("Blocked hostname");
  });

  // IP literal blocking
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
  it("blocks ::1 (IPv6 loopback literal)", () => {
    expect(() => validateSsrfSync("http://[::1]")).toThrow();
  });

  // Should pass
  it("allows a normal public URL", () => {
    expect(() => validateSsrfSync("https://github.com")).not.toThrow();
  });
  it("allows a public URL with path and query", () => {
    expect(() => validateSsrfSync("https://api.example.com/v1/data?token=abc")).not.toThrow();
  });

  // Redirect count tracking via chain length
  it("throws on genuinely malformed URL", () => {
    expect(() => validateSsrfSync("not a url")).toThrow("Invalid URL");
  });
});
