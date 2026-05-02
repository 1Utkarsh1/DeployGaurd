/**
 * ML/LLM Overlay — deterministic rule-based stub.
 *
 * Design:
 *   Takes a FeatureVector extracted from scan results, applies weighted rules,
 *   and outputs an MlOverlayResult with an "expected expert grade" and confidence.
 *
 *   No external API calls. Fully offline + deterministic.
 *   This is a stub for future model training — replace the rule-based logic
 *   with a trained model checkpoint once enough scan data is collected.
 *
 * Interface contract (stable — do not change signatures):
 *   buildFeatureVector(result) → FeatureVector
 *   computeMlOverlay(features) → MlOverlayResult
 */

export interface FeatureVector {
  httpsScore: number;
  securityScore: number;
  corsScore: number;
  cookieScore: number;
  cacheScore: number;
  perfScore: number;
  seoScore: number;
  a11yScore: number;
  thirdPartyScore: number;
  structuredDataScore: number;
  totalScore: number;
  criticalCount: number;
  warningCount: number;
  cookieCount: number;
  hasCSP: boolean;
  hasHSTS: boolean;
  usesHttps: boolean;
  hasCriticalCors: boolean;
  hasNoindex: boolean;
}

export interface FeatureImportance {
  feature: string;
  contribution: number;
}

export interface MlOverlayResult {
  adjustedGrade: string;
  confidence: number;
  rationale: string;
  featureImportance: FeatureImportance[];
}

type Grade = "Excellent" | "Good" | "Needs Work" | "Risky";

function gradeFromScore(score: number): Grade {
  if (score >= 85) return "Excellent";
  if (score >= 70) return "Good";
  if (score >= 50) return "Needs Work";
  return "Risky";
}

/**
 * Rule-based overlay that downgrade/upgrades the deterministic score-based grade
 * using expert heuristics. Confidence reflects how well-supported the conclusion is.
 *
 * Future training target: replace rules with a small gradient-boosted tree or
 * logistic regression trained on human-labelled "expected grade" annotations.
 */
export function computeMlOverlay(features: FeatureVector): MlOverlayResult {
  const scoreGrade = gradeFromScore(features.totalScore);
  let adjustedGrade: Grade = scoreGrade;
  let confidence = 0.75;
  const rationale: string[] = [];
  const importance: FeatureImportance[] = [];

  if (!features.usesHttps) {
    adjustedGrade = "Risky";
    confidence = 0.97;
    rationale.push("No HTTPS — all traffic is unencrypted (hard downgrade to Risky regardless of other factors).");
    importance.push({ feature: "usesHttps", contribution: -30 });
  }

  if (features.hasCriticalCors) {
    if (adjustedGrade === "Excellent" || adjustedGrade === "Good") {
      adjustedGrade = "Needs Work";
      confidence = Math.max(confidence, 0.88);
      rationale.push("Critical CORS misconfiguration (wildcard + credentials) overrides an otherwise high score.");
      importance.push({ feature: "hasCriticalCors", contribution: -20 });
    }
  }

  if (!features.hasCSP && !features.hasHSTS) {
    if (adjustedGrade === "Excellent") {
      adjustedGrade = "Good";
      confidence = Math.max(confidence, 0.82);
      rationale.push("Both CSP and HSTS are missing — expert reviewers rarely rate this Excellent.");
      importance.push({ feature: "hasCSP+hasHSTS", contribution: -10 });
    }
  }

  if (features.criticalCount >= 3) {
    if (adjustedGrade === "Good" || adjustedGrade === "Excellent") {
      adjustedGrade = "Needs Work";
      confidence = Math.max(confidence, 0.80);
      rationale.push(`${features.criticalCount} critical issues present — grade adjusted down.`);
      importance.push({ feature: "criticalCount", contribution: -features.criticalCount * 3 });
    }
  }

  if (features.hasNoindex && features.seoScore < 4) {
    rationale.push("noindex directive detected — page will not be indexed, negating SEO investment.");
    importance.push({ feature: "hasNoindex", contribution: -5 });
    confidence = Math.max(confidence, 0.78);
  }

  if (features.totalScore >= 90 && features.criticalCount === 0 && features.warningCount <= 2 && features.usesHttps && features.hasCSP && features.hasHSTS) {
    adjustedGrade = "Excellent";
    confidence = 0.93;
    rationale.push("Near-perfect score with HTTPS, CSP, HSTS and no critical issues — high confidence Excellent.");
    importance.push({ feature: "totalScore+security", contribution: 15 });
  }

  importance.push({ feature: "totalScore", contribution: features.totalScore - 50 });
  importance.push({ feature: "securityScore", contribution: features.securityScore - 15 });

  const rationale_text =
    rationale.length > 0
      ? rationale.join(" ")
      : `Score ${features.totalScore}/100 maps directly to ${scoreGrade}. No strong signals detected to adjust the grade.`;

  return {
    adjustedGrade,
    confidence: Math.round(confidence * 100) / 100,
    rationale: rationale_text,
    featureImportance: importance
      .sort((a, b) => Math.abs(b.contribution) - Math.abs(a.contribution))
      .slice(0, 5),
  };
}

/**
 * Convenience helper to build a FeatureVector from raw scan result fields.
 * Import this alongside computeMlOverlay to produce the overlay in one call.
 */
export function buildFeatureVector(params: {
  httpsScore: number;
  securityScore: number;
  corsScore: number;
  cookieScore: number;
  cacheScore: number;
  perfScore: number;
  seoScore: number;
  a11yScore: number;
  thirdPartyScore?: number;
  structuredDataScore?: number;
  totalScore: number;
  issues: Array<{ severity: string; category: string }>;
  cookieCount: number;
  hasCSP: boolean;
  hasHSTS: boolean;
  usesHttps: boolean;
  hasCriticalCors: boolean;
  hasNoindex: boolean;
}): FeatureVector {
  return {
    httpsScore: params.httpsScore,
    securityScore: params.securityScore,
    corsScore: params.corsScore,
    cookieScore: params.cookieScore,
    cacheScore: params.cacheScore,
    perfScore: params.perfScore,
    seoScore: params.seoScore,
    a11yScore: params.a11yScore,
    thirdPartyScore: params.thirdPartyScore ?? 10,
    structuredDataScore: params.structuredDataScore ?? 0,
    totalScore: params.totalScore,
    criticalCount: params.issues.filter((i) => i.severity === "critical").length,
    warningCount: params.issues.filter((i) => i.severity === "warning").length,
    cookieCount: params.cookieCount,
    hasCSP: params.hasCSP,
    hasHSTS: params.hasHSTS,
    usesHttps: params.usesHttps,
    hasCriticalCors: params.hasCriticalCors,
    hasNoindex: params.hasNoindex,
  };
}
