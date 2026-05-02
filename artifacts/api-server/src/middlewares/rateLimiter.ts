import rateLimit from "express-rate-limit";

/**
 * Global rate limiter: 120 requests per minute per IP across all /api endpoints.
 * Applies to reads (GET) as well to prevent scraping.
 */
export const globalRateLimiter = rateLimit({
  windowMs: 60_000,
  max: 120,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Too many requests. Please slow down." },
});

/**
 * Scan-specific rate limiter: 10 scan submissions per minute per IP.
 * Scans are expensive — each one makes multiple outbound HTTP requests.
 */
export const scanRateLimiter = rateLimit({
  windowMs: 60_000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  handler: (_req, res) => {
    res.setHeader("Retry-After", "60");
    res.status(429).json({
      error:
        "Scan rate limit exceeded. Maximum 10 scans per minute per IP. Please wait before submitting another scan.",
    });
  },
});
