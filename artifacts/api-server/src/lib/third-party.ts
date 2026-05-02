/**
 * Third-party Governance Scorer
 *
 * Analyzes third-party script dependencies and scores governance posture (0–10).
 * Penalizes sites with excessive or unrecognized third-party scripts.
 */

interface TpIssue {
  category: string;
  severity: "critical" | "warning" | "info" | "passed";
  message: string;
  explanation: string;
  suggestion: string;
}

interface TpPenalty {
  category: string;
  message: string;
  pointsLost: number;
}

export interface ThirdPartyResult {
  score: number;
  issues: TpIssue[];
  penalties: TpPenalty[];
  totalScripts: number;
  thirdPartyScripts: number;
  thirdPartyDomains: string[];
  unknownDomains: string[];
}

const CAT = "Third-party";

const KNOWN_SERVICES = new Set([
  "analytics.google.com",
  "g.doubleclick.net",
  "tagmanager.google.com",
  "www.googletagmanager.com",
  "googletagmanager.com",
  "www.google-analytics.com",
  "google-analytics.com",
  "ssl.google-analytics.com",
  "static.cloudflareinsights.com",
  "cdn.jsdelivr.net",
  "cdnjs.cloudflare.com",
  "ajax.googleapis.com",
  "fonts.googleapis.com",
  "fonts.gstatic.com",
  "apis.google.com",
  "accounts.google.com",
  "www.google.com",
  "polyfill.io",
  "unpkg.com",
  "js.stripe.com",
  "checkout.stripe.com",
  "m.stripe.com",
  "r.stripe.com",
  "assets.adobedtm.com",
  "connect.facebook.net",
  "platform.twitter.com",
  "d3js.org",
  "code.jquery.com",
  "maxcdn.bootstrapcdn.com",
  "stackpath.bootstrapcdn.com",
  "cdn.cookielaw.org",
  "js.hs-scripts.com",
  "static.hotjar.com",
  "script.hotjar.com",
  "cdn.segment.com",
  "cdn.amplitude.com",
  "js.intercomcdn.com",
  "widget.intercom.io",
  "js.driftt.com",
  "fast.wistia.net",
  "player.vimeo.com",
  "www.youtube.com",
  "s.ytimg.com",
  "cdn.shopify.com",
  "www.paypalobjects.com",
  "www.paypal.com",
  "cdn.onesignal.com",
  "cdn.freshdesk.com",
  "js.freshchat.com",
]);

function extractDomain(src: string): string | null {
  try {
    if (src.startsWith("//")) src = "https:" + src;
    if (!src.startsWith("http")) return null;
    return new URL(src).hostname.toLowerCase();
  } catch {
    return null;
  }
}

function extractScriptSrcs(html: string): string[] {
  const srcs: string[] = [];
  const re = /<script[^>]+src=["']([^"']+)["'][^>]*>/gi;
  let m: RegExpExecArray | null;
  while ((m = re.exec(html)) !== null) {
    if (m[1]) srcs.push(m[1]);
  }
  return srcs;
}

function getPageDomain(pageUrl: string): string {
  try {
    return new URL(pageUrl).hostname.toLowerCase();
  } catch {
    return "";
  }
}

function isSameOrSubdomain(scriptDomain: string, pageDomain: string): boolean {
  if (!pageDomain) return false;
  if (scriptDomain === pageDomain) return true;
  if (scriptDomain.endsWith("." + pageDomain)) return true;
  return false;
}

export function scoreThirdPartyGovernance(html: string, pageUrl: string): ThirdPartyResult {
  const issues: TpIssue[] = [];
  const penalties: TpPenalty[] = [];
  const pageDomain = getPageDomain(pageUrl);
  const srcs = extractScriptSrcs(html);
  const totalScripts = srcs.length;

  const thirdPartyDomainSet = new Set<string>();
  const unknownDomainSet = new Set<string>();
  let thirdPartyScripts = 0;

  for (const src of srcs) {
    const domain = extractDomain(src);
    if (!domain) continue;
    if (isSameOrSubdomain(domain, pageDomain)) continue;
    thirdPartyScripts++;
    thirdPartyDomainSet.add(domain);
    if (!KNOWN_SERVICES.has(domain)) {
      unknownDomainSet.add(domain);
    }
  }

  const thirdPartyDomains = Array.from(thirdPartyDomainSet);
  const unknownDomains = Array.from(unknownDomainSet);
  let score = 10;

  if (thirdPartyScripts === 0) {
    issues.push({
      category: CAT,
      severity: "passed",
      message: `No third-party scripts detected (${totalScripts} total script(s), all same-origin)`,
      explanation:
        "All scripts are served from your own domain, minimizing external data sharing and supply-chain risk.",
      suggestion:
        "Continue self-hosting scripts where feasible. Periodically review new additions to avoid scope creep.",
    });
  } else {
    if (thirdPartyScripts <= 3) {
      score -= 2;
      issues.push({
        category: CAT,
        severity: "info",
        message: `${thirdPartyScripts} third-party script(s) from ${thirdPartyDomains.length} domain(s)`,
        explanation:
          "A small number of third-party scripts is manageable but each adds load risk and data exposure.",
        suggestion: "Ensure each third-party script has a clear purpose and is loaded with async or defer.",
      });
    } else if (thirdPartyScripts <= 6) {
      score -= 4;
      penalties.push({
        category: CAT,
        message: `${thirdPartyScripts} third-party scripts detected`,
        pointsLost: 4,
      });
      issues.push({
        category: CAT,
        severity: "warning",
        message: `${thirdPartyScripts} third-party scripts from ${thirdPartyDomains.length} domain(s) — consider reducing`,
        explanation:
          "Moderate third-party script load increases page load time and creates multiple external trust boundaries.",
        suggestion:
          "Audit third-party scripts. Remove unused ones, defer analytics until after page load.",
      });
    } else if (thirdPartyScripts <= 15) {
      score -= 7;
      penalties.push({
        category: CAT,
        message: `High third-party script count (${thirdPartyScripts})`,
        pointsLost: 7,
      });
      issues.push({
        category: CAT,
        severity: "warning",
        message: `High third-party script load: ${thirdPartyScripts} scripts from ${thirdPartyDomains.length} domain(s)`,
        explanation:
          "Each third-party script delays rendering, exposes user data to external parties, and introduces supply-chain risk.",
        suggestion:
          "Aggressively audit: use Lighthouse, remove unused scripts, load non-critical scripts asynchronously.",
      });
    } else {
      score -= 10;
      penalties.push({
        category: CAT,
        message: `Excessive third-party scripts (${thirdPartyScripts})`,
        pointsLost: 10,
      });
      issues.push({
        category: CAT,
        severity: "warning",
        message: `Excessive third-party scripts: ${thirdPartyScripts} from ${thirdPartyDomains.length} domain(s)`,
        explanation:
          "This many external scripts significantly impacts performance, privacy, and supply-chain security.",
        suggestion:
          "Perform a full script audit. Self-host critical scripts, remove marketing/tracking scripts until post-launch.",
      });
    }

    if (unknownDomains.length > 0) {
      const pts = Math.min(3, unknownDomains.length);
      score -= pts;
      penalties.push({
        category: CAT,
        message: `${unknownDomains.length} script(s) from unrecognized domain(s)`,
        pointsLost: pts,
      });
      const domainList = unknownDomains.slice(0, 5).join(", ");
      issues.push({
        category: CAT,
        severity: "warning",
        message: `Scripts from ${unknownDomains.length} unrecognized domain(s): ${domainList}${unknownDomains.length > 5 ? " …" : ""}`,
        explanation:
          "Scripts from unknown domains carry higher supply-chain risk. Ensure these are intentional and trusted.",
        suggestion:
          "Verify each unknown script domain. Use Subresource Integrity (SRI) hashes for third-party scripts.",
      });
    } else {
      issues.push({
        category: CAT,
        severity: "info",
        message: `All ${thirdPartyScripts} third-party script(s) come from known services`,
        explanation: "All external scripts are from recognized CDNs or services.",
        suggestion:
          "Consider adding Subresource Integrity (SRI) hashes to lock script versions against tampering.",
      });
    }
  }

  return {
    score: Math.min(10, Math.max(0, score)),
    issues,
    penalties,
    totalScripts,
    thirdPartyScripts,
    thirdPartyDomains,
    unknownDomains,
  };
}
