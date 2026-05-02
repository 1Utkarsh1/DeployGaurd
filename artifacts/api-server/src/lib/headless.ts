/// <reference lib="dom" />
/**
 * Headless Scan Module — real browser-based metrics via Playwright.
 *
 * Feature-gated: requires HEADLESS_SCAN=true in env.
 * Falls back gracefully if Playwright is not installed.
 *
 * When enabled:
 *   1. Launches a headless Chromium browser via Playwright
 *   2. Counts total resources loaded and their transfer sizes
 *   3. Detects render-blocking scripts/stylesheets in <head>
 *   4. Approximates LCP via PerformanceObserver
 *   5. Optionally runs axe-core for WCAG violation count
 *
 * Produces a headlessScore (0–10) from these metrics.
 * The deterministic score remains the primary result.
 */

export interface HeadlessResult {
  available: boolean;
  totalResourceCount: number | null;
  totalTransferSizeKb: number | null;
  renderBlockingCount: number | null;
  lcpMs: number | null;
  axeViolationCount: number | null;
  headlessScore: number | null;
  error?: string;
}

function computeHeadlessScore(
  lcpMs: number | null,
  renderBlockingCount: number | null,
  axeViolationCount: number | null,
): number {
  let score = 10;

  if (lcpMs !== null) {
    if (lcpMs > 4000) {
      score -= 5;
    } else if (lcpMs > 2500) {
      score -= 3;
    } else if (lcpMs > 1200) {
      score -= 1;
    }
  }

  if (renderBlockingCount !== null && renderBlockingCount > 0) {
    score -= Math.min(4, renderBlockingCount);
  }

  if (axeViolationCount !== null && axeViolationCount > 0) {
    score -= Math.min(2, axeViolationCount);
  }

  return Math.max(0, score);
}

export async function headlessScan(url: string): Promise<HeadlessResult | null> {
  if (process.env["HEADLESS_SCAN"] !== "true") {
    return null;
  }

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  let pw: any;
  try {
    // Dynamic import — playwright is an optional peer dependency
    // @ts-ignore
    pw = await import("playwright");
  } catch {
    return {
      available: false,
      totalResourceCount: null,
      totalTransferSizeKb: null,
      renderBlockingCount: null,
      lcpMs: null,
      axeViolationCount: null,
      headlessScore: null,
      error:
        "Playwright not installed. Run: pnpm --filter @workspace/api-server add playwright",
    };
  }

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  let browser: any;
  try {
    browser = await pw.chromium.launch({ headless: true });
    const context = await browser.newContext({
      userAgent:
        "DeployGuard/2.0 Headless Scanner (Chromium/Playwright; https://deployguard.app)",
    });
    const page = await context.newPage();

    let totalResourceCount = 0;
    let totalTransferSizeKb = 0;

    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    page.on("response", (res: any) => {
      totalResourceCount++;
      try {
        const lenHeader = res.headers()["content-length"];
        if (lenHeader) {
          const len = parseInt(lenHeader, 10);
          if (!isNaN(len)) totalTransferSizeKb += len / 1024;
        }
      } catch {
        /* ignore */
      }
    });

    await page.goto(url, { waitUntil: "networkidle", timeout: 20_000 });

    // LCP via PerformanceObserver
    const lcpMs: number | null = await page
      .evaluate((): Promise<number | null> => {
        return new Promise((resolve) => {
          if (!("PerformanceObserver" in window)) {
            resolve(null);
            return;
          }
          let lcp: number | null = null;
          try {
            const obs = new PerformanceObserver((list) => {
              for (const entry of list.getEntries()) {
                lcp = (entry as PerformanceEntry & { startTime: number }).startTime;
              }
            });
            obs.observe({ type: "largest-contentful-paint", buffered: true });
            setTimeout(() => resolve(lcp), 600);
          } catch {
            resolve(null);
          }
        });
      })
      .catch(() => null);

    // Render-blocking resources in <head>
    const renderBlockingCount: number = await page
      .evaluate(() => {
        let count = 0;
        Array.from(document.querySelectorAll("head script[src]")).forEach((el) => {
          const s = el as HTMLScriptElement;
          if (!s.async && !s.defer) count++;
        });
        count += document.querySelectorAll('head link[rel="stylesheet"]').length;
        return count;
      })
      .catch(() => 0);

    // axe-core accessibility violations (optional)
    let axeViolationCount: number | null = null;
    try {
      // @ts-ignore — optional peer dependency
      const axeMod = await import("axe-core").catch(() => null);
      if (axeMod && typeof axeMod.source === "string") {
        await page.addScriptTag({ content: axeMod.source });
        axeViolationCount = await page
          .evaluate(async () => {
            // eslint-disable-next-line @typescript-eslint/no-explicit-any
            const results = await (window as any).axe.run();
            return (results.violations as unknown[]).length;
          })
          .catch(() => null);
      }
    } catch {
      /* axe not available */
    }

    await browser.close();

    const headlessScore = computeHeadlessScore(lcpMs, renderBlockingCount, axeViolationCount);
    return {
      available: true,
      totalResourceCount,
      totalTransferSizeKb: Math.round(totalTransferSizeKb * 10) / 10,
      renderBlockingCount,
      lcpMs: lcpMs !== null ? Math.round(lcpMs) : null,
      axeViolationCount,
      headlessScore,
    };
  } catch (err: unknown) {
    try {
      await browser?.close();
    } catch {
      /* ignore */
    }
    return {
      available: false,
      totalResourceCount: null,
      totalTransferSizeKb: null,
      renderBlockingCount: null,
      lcpMs: null,
      axeViolationCount: null,
      headlessScore: null,
      error: err instanceof Error ? err.message : String(err),
    };
  }
}
