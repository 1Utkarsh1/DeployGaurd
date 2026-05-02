/**
 * Structured Data Correctness Scorer
 *
 * Validates JSON-LD structured data blocks (schema.org) found in HTML.
 * Score 0–5: 0 if absent, up to 5 for valid, well-formed schema.
 */

interface SdIssue {
  category: string;
  severity: "critical" | "warning" | "info" | "passed";
  message: string;
  explanation: string;
  suggestion: string;
}

interface SdPenalty {
  category: string;
  message: string;
  pointsLost: number;
}

export interface StructuredDataResult {
  score: number;
  issues: SdIssue[];
  penalties: SdPenalty[];
  blockCount: number;
  validBlockCount: number;
}

const CAT = "Structured Data";

const KNOWN_TYPES = new Set([
  "Organization",
  "WebSite",
  "Article",
  "BlogPosting",
  "NewsArticle",
  "Product",
  "FAQPage",
  "BreadcrumbList",
  "LocalBusiness",
  "Person",
  "Event",
  "Recipe",
  "HowTo",
  "VideoObject",
  "ImageObject",
  "WebPage",
  "SoftwareApplication",
  "JobPosting",
  "Review",
  "Course",
  "Book",
  "Movie",
  "MusicRecording",
  "ItemList",
  "SearchAction",
]);

const EXPECTED_PROPS: Record<string, string[]> = {
  Organization: ["name", "url"],
  WebSite: ["name", "url"],
  Article: ["headline", "author", "datePublished"],
  BlogPosting: ["headline", "author", "datePublished"],
  NewsArticle: ["headline", "author", "datePublished"],
  Product: ["name", "description"],
  LocalBusiness: ["name", "address"],
  FAQPage: ["mainEntity"],
  BreadcrumbList: ["itemListElement"],
};

function extractLdJsonBlocks(html: string): string[] {
  const blocks: string[] = [];
  const re = /<script[^>]+type=["']application\/ld\+json["'][^>]*>([\s\S]*?)<\/script>/gi;
  let m: RegExpExecArray | null;
  while ((m = re.exec(html)) !== null) {
    const content = m[1];
    if (content) blocks.push(content.trim());
  }
  return blocks;
}

export function scoreStructuredData(html: string): StructuredDataResult {
  const issues: SdIssue[] = [];
  const penalties: SdPenalty[] = [];
  const blocks = extractLdJsonBlocks(html);

  if (blocks.length === 0) {
    issues.push({
      category: CAT,
      severity: "info",
      message: "No JSON-LD structured data found",
      explanation:
        "Structured data enables rich results in Google Search (star ratings, breadcrumbs, FAQs). Sites without it miss significant SERP features.",
      suggestion:
        "Add Schema.org JSON-LD for your page type (WebSite, Article, Product, Organization, etc.). See: https://schema.org",
    });
    return { score: 0, issues, penalties, blockCount: 0, validBlockCount: 0 };
  }

  let score = 5;
  let validBlockCount = 0;

  for (let i = 0; i < blocks.length; i++) {
    const raw = blocks[i]!;
    const label = blocks.length > 1 ? ` (block ${i + 1})` : "";

    let parsed: unknown;
    try {
      parsed = JSON.parse(raw);
    } catch {
      const pts = 2;
      score -= pts;
      penalties.push({ category: CAT, message: `JSON-LD block${label} is not valid JSON`, pointsLost: pts });
      issues.push({
        category: CAT,
        severity: "warning",
        message: `JSON-LD block${label} failed to parse as JSON`,
        explanation:
          "Malformed JSON-LD is silently ignored by search engines and rich-result parsers, wasting the effort of adding structured data.",
        suggestion:
          "Validate JSON-LD syntax at https://search.google.com/test/rich-results",
      });
      continue;
    }

    if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
      score -= 1;
      issues.push({
        category: CAT,
        severity: "warning",
        message: `JSON-LD block${label} root must be an object`,
        explanation:
          "The root of a JSON-LD block should be a JSON object, not an array or primitive.",
        suggestion: "Wrap array data in a @graph property inside a root object.",
      });
      continue;
    }

    const obj = parsed as Record<string, unknown>;
    validBlockCount++;

    // @context check
    if (!obj["@context"]) {
      const pts = 1;
      score -= pts;
      penalties.push({ category: CAT, message: `JSON-LD block${label} missing @context`, pointsLost: pts });
      issues.push({
        category: CAT,
        severity: "warning",
        message: `JSON-LD block${label} missing @context`,
        explanation:
          "@context is required to link the vocabulary — without it search engines ignore the data.",
        suggestion: 'Add "@context": "https://schema.org" to the JSON-LD block.',
      });
    } else {
      const ctx = String(obj["@context"]);
      const isSchemaOrg =
        ctx === "https://schema.org" ||
        ctx === "http://schema.org" ||
        ctx === "https://schema.org/";
      if (!isSchemaOrg) {
        score -= 0.5;
        issues.push({
          category: CAT,
          severity: "info",
          message: `JSON-LD block${label} @context is not schema.org ("${ctx.slice(0, 60)}")`,
          explanation:
            "Non-schema.org contexts are valid but uncommon. Google primarily supports Schema.org for rich results.",
          suggestion: 'Use "@context": "https://schema.org" for maximum search engine support.',
        });
      }
    }

    // @type check
    if (!obj["@type"]) {
      const pts = 1;
      score -= pts;
      penalties.push({ category: CAT, message: `JSON-LD block${label} missing @type`, pointsLost: pts });
      issues.push({
        category: CAT,
        severity: "warning",
        message: `JSON-LD block${label} missing @type`,
        explanation:
          "@type tells search engines what kind of entity this describes, enabling specific rich results.",
        suggestion:
          "Add a @type like WebSite, Organization, Article, or Product.",
      });
    } else {
      const typeName = String(obj["@type"]);
      if (!KNOWN_TYPES.has(typeName)) {
        score -= 0.25;
        issues.push({
          category: CAT,
          severity: "info",
          message: `JSON-LD block${label} uses type "${typeName}" — verify it is a recognized Schema.org type`,
          explanation:
            "Unknown types may not trigger rich results. Check schema.org for the correct type name.",
          suggestion: `See https://schema.org/${typeName} — if invalid, switch to a recognized type.`,
        });
      }

      // Expected properties check for known types
      const expectedProps = EXPECTED_PROPS[typeName];
      if (expectedProps) {
        const missingProps = expectedProps.filter((p) => !(p in obj));
        if (missingProps.length > 0) {
          score -= 0.5;
          issues.push({
            category: CAT,
            severity: "info",
            message: `JSON-LD ${typeName}${label} missing recommended properties: ${missingProps.join(", ")}`,
            explanation: `These properties are expected for ${typeName} rich results and may limit eligibility.`,
            suggestion: `Add ${missingProps.join(", ")} to your JSON-LD ${typeName} block.`,
          });
        } else {
          issues.push({
            category: CAT,
            severity: "passed",
            message: `JSON-LD ${typeName}${label} has all expected properties`,
            explanation: `All recommended properties for ${typeName} are present.`,
            suggestion:
              "Validate with https://search.google.com/test/rich-results to confirm rich result eligibility.",
          });
        }
      } else if (KNOWN_TYPES.has(typeName)) {
        issues.push({
          category: CAT,
          severity: "passed",
          message: `JSON-LD ${typeName}${label} is a valid schema.org type`,
          explanation: `"${typeName}" is a recognized schema.org type.`,
          suggestion:
            "Validate with https://search.google.com/test/rich-results to confirm rich result eligibility.",
        });
      }
    }
  }

  if (validBlockCount > 0 && score >= 5) {
    issues.unshift({
      category: CAT,
      severity: "passed",
      message: `${validBlockCount} valid JSON-LD block(s) — well formed`,
      explanation: "Structured data is correctly formed and uses schema.org.",
      suggestion: "Validate with Google's Rich Results Test for production eligibility.",
    });
  }

  return {
    score: Math.min(5, Math.max(0, Math.round(score * 10) / 10)),
    issues,
    penalties,
    blockCount: blocks.length,
    validBlockCount,
  };
}
