/**
 * AI Overlay Score Module
 *
 * Feature-gated via LOCAL_AI=true (off by default).
 * When disabled: returns null — the deterministic ml-overlay is the primary grade.
 *
 * Strategy:
 *   A) LOCAL_AI=false (default): returns null; deterministic ml-overlay already runs
 *   B) LOCAL_AI=true:
 *      1. Attempts to load a tiny local GGUF model via node-llama-cpp
 *      2. If model loads: generates a scored prompt → parses response
 *      3. If model unavailable or fails: falls back to enhanced deterministic rules
 *      4. Fail closed — no crash, no external API calls
 *
 * Returns: { aiScore 0–100, confidence, rationale, riskLabel, engineUsed }
 */

import type { FeatureVector } from "./ml-overlay.js";

export interface AiOverlayResult {
  aiScore: number;
  confidence: number;
  rationale: string;
  riskLabel: "Low" | "Moderate" | "High" | "Critical";
  engineUsed: "deterministic-rules" | "local-llm" | "none";
}

function isLocalAiEnabled(): boolean {
  return process.env["LOCAL_AI"] === "true";
}

function buildPrompt(features: FeatureVector, topFindings: string[]): string {
  return `You are a web security expert scoring a website's production launch readiness.

Site metrics:
- HTTPS: ${features.usesHttps ? "yes" : "NO (critical failure)"}
- Security headers score: ${features.securityScore}/30 (CSP: ${features.hasCSP}, HSTS: ${features.hasHSTS})
- CORS score: ${features.corsScore}/10 (critical CORS misconfiguration: ${features.hasCriticalCors})
- Cookie score: ${features.cookieScore}/10
- Third-party governance: ${features.thirdPartyScore}/10
- Structured data score: ${features.structuredDataScore}/5
- SEO score: ${features.seoScore}/7
- Performance score: ${features.perfScore}/8
- Accessibility score: ${features.a11yScore}/5
- Total deterministic score: ${features.totalScore}/100
- Critical issues: ${features.criticalCount}
- Warnings: ${features.warningCount}
- Page has noindex: ${features.hasNoindex}

Top findings:
${topFindings.slice(0, 5).map((f, i) => `${i + 1}. ${f}`).join("\n")}

Based on all the above data, provide:
1. An AI risk score (integer 0-100, where 100 is production-ready)
2. A risk label (exactly one of: Low, Moderate, High, Critical)
3. A one-sentence rationale for your score

Respond in JSON only: {"score": N, "riskLabel": "...", "rationale": "..."}`;
}

function parseLlmResponse(
  text: string,
): { score: number; riskLabel: string; rationale: string } | null {
  try {
    const jsonMatch = text.match(/\{[^}]+\}/);
    if (!jsonMatch) return null;
    const parsed = JSON.parse(jsonMatch[0]) as Record<string, unknown>;
    const score = Number(parsed["score"]);
    const riskLabel = String(parsed["riskLabel"] ?? "Moderate");
    const rationale = String(parsed["rationale"] ?? "");
    if (isNaN(score) || score < 0 || score > 100) return null;
    return { score: Math.round(score), riskLabel, rationale };
  } catch {
    return null;
  }
}

function toRiskLabel(score: number): AiOverlayResult["riskLabel"] {
  if (score >= 85) return "Low";
  if (score >= 70) return "Moderate";
  if (score >= 50) return "High";
  return "Critical";
}

function deterministicAiScore(features: FeatureVector): AiOverlayResult {
  let score = features.totalScore;
  const rationale: string[] = [];

  if (!features.usesHttps) {
    score = Math.min(score, 20);
    rationale.push("No HTTPS — critical security failure overrides all other factors.");
  }

  if (features.hasCriticalCors) {
    score = Math.max(0, score - 15);
    rationale.push("Critical CORS misconfiguration exposes user credentials to any website.");
  }

  const secRatio = features.securityScore / 30;
  if (secRatio < 0.4) {
    score -= 8;
    rationale.push(`Weak security headers (${features.securityScore}/30) — major risk for production.`);
  } else if (secRatio >= 0.85) {
    score += 2;
    rationale.push("Strong security header posture.");
  }

  if (features.thirdPartyScore < 5) {
    score -= 5;
    rationale.push(
      `Poor third-party governance (${features.thirdPartyScore}/10) increases supply-chain risk.`,
    );
  } else if (features.thirdPartyScore === 10) {
    score += 1;
    rationale.push("No third-party scripts — minimal supply-chain risk.");
  }

  if (features.structuredDataScore === 0) {
    rationale.push("No structured data — SEO rich results unavailable.");
  } else if (features.structuredDataScore >= 4) {
    score += 1;
    rationale.push("Valid structured data — eligible for search rich results.");
  }

  if (features.hasNoindex) {
    score -= 5;
    rationale.push("noindex directive blocks all search engine indexing.");
  }

  if (features.criticalCount >= 3) {
    score -= features.criticalCount * 2;
    rationale.push(`${features.criticalCount} critical issues require immediate pre-launch attention.`);
  }

  score = Math.min(100, Math.max(0, Math.round(score)));

  const confidence =
    features.criticalCount === 0 && features.warningCount <= 2 ? 0.88 : 0.78;

  const riskLabel = toRiskLabel(score);

  return {
    aiScore: score,
    confidence,
    rationale:
      rationale.length > 0
        ? rationale.join(" ")
        : `Deterministic AI evaluation: ${score}/100 based on full feature analysis.`,
    riskLabel,
    engineUsed: "deterministic-rules",
  };
}

async function tryLocalLlm(
  features: FeatureVector,
  topFindings: string[],
): Promise<AiOverlayResult | null> {
  const modelPath = process.env["LOCAL_AI_MODEL_PATH"];
  if (!modelPath) {
    return null;
  }

  let llamaModule: Record<string, unknown>;
  try {
    // @ts-ignore — optional peer dependency, not in node_modules
    llamaModule = (await import("node-llama-cpp")) as Record<string, unknown>;
  } catch {
    return null;
  }

  const getLlama = llamaModule["getLlama"];
  if (typeof getLlama !== "function") {
    return null;
  }

  try {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const llama = await (getLlama as () => Promise<any>)();
    const model = await llama.loadModel({ modelPath });
    const context = await model.createContext({ contextSize: 512 });
    const session = new (llamaModule["LlamaChatSession"] as new (opts: unknown) => {
      prompt: (text: string, opts: unknown) => Promise<string>;
    })({ contextSequence: context.getSequence() });

    const prompt = buildPrompt(features, topFindings);
    const response = await session.prompt(prompt, { maxTokens: 150, temperature: 0.05 });

    const parsed = parseLlmResponse(String(response));
    if (!parsed) return null;

    const validLabels = new Set(["Low", "Moderate", "High", "Critical"]);
    const riskLabel = validLabels.has(parsed.riskLabel)
      ? (parsed.riskLabel as AiOverlayResult["riskLabel"])
      : toRiskLabel(parsed.score);

    return {
      aiScore: parsed.score,
      confidence: 0.85,
      rationale: parsed.rationale,
      riskLabel,
      engineUsed: "local-llm",
    };
  } catch {
    return null;
  }
}

export async function computeAiOverlay(
  features: FeatureVector,
  topFindings: string[],
): Promise<AiOverlayResult | null> {
  if (!isLocalAiEnabled()) {
    return null;
  }

  const llmResult = await tryLocalLlm(features, topFindings);
  if (llmResult) return llmResult;

  return deterministicAiScore(features);
}
