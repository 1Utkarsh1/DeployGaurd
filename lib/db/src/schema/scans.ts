import {
  pgTable,
  serial,
  text,
  integer,
  real,
  boolean,
  jsonb,
  timestamp,
} from "drizzle-orm/pg-core";
import { createInsertSchema } from "drizzle-zod";
import { z } from "zod/v4";

export const scansTable = pgTable("scans", {
  id: serial("id").primaryKey(),
  url: text("url").notNull(),
  finalUrl: text("final_url").notNull(),
  score: real("score").notNull(),
  grade: text("grade").notNull(),
  statusCode: integer("status_code").notNull(),
  redirectChain: jsonb("redirect_chain").notNull().$type<string[]>(),
  usesHttps: boolean("uses_https").notNull(),
  responseTimeMs: real("response_time_ms").notNull(),
  title: text("title"),
  metaDescription: text("meta_description"),
  hasViewport: boolean("has_viewport").notNull().default(false),
  hasOpenGraph: boolean("has_open_graph").notNull().default(false),
  hasRobotsTxt: boolean("has_robots_txt").notNull().default(false),
  hasSitemapXml: boolean("has_sitemap_xml").notNull().default(false),
  securityHeaders: jsonb("security_headers").notNull().$type<Record<string, boolean>>(),
  cookieIssues: jsonb("cookie_issues").notNull().$type<string[]>(),
  htmlSizeKb: real("html_size_kb").notNull(),
  scriptTagCount: integer("script_tag_count").notNull(),
  categoryScores: jsonb("category_scores").notNull().$type<
    Array<{ name: string; score: number; maxScore: number; label: string }>
  >(),
  issues: jsonb("issues").notNull().$type<
    Array<{
      category: string;
      severity: string;
      message: string;
      explanation: string;
      suggestion: string;
    }>
  >(),
  fixPrompt: text("fix_prompt").notNull(),
  htmlHash: text("html_hash").notNull().default(""),
  responseHeadersSnapshot: jsonb("response_headers_snapshot")
    .notNull()
    .$type<Record<string, string>>()
    .default({}),
  scoreKillers: jsonb("score_killers")
    .notNull()
    .$type<Array<{ category: string; message: string; pointsLost: number }>>()
    .default([]),
  canonicalUrl: text("canonical_url"),
  hasStructuredData: boolean("has_structured_data").notNull().default(false),
  hasNoindex: boolean("has_noindex").notNull().default(false),
  corsScore: real("cors_score").notNull().default(10),
  structuredDataScore: real("structured_data_score").notNull().default(0),
  thirdPartyScore: real("third_party_score").notNull().default(10),
  thirdPartyDomains: jsonb("third_party_domains").notNull().$type<string[]>().default([]),
  aiOverlay: jsonb("ai_overlay").$type<{
    aiScore: number;
    confidence: number;
    rationale: string;
    riskLabel: string;
    engineUsed: string;
  } | null>(),
  headlessScan: jsonb("headless_scan").$type<{
    available: boolean;
    totalResourceCount: number | null;
    totalTransferSizeKb: number | null;
    renderBlockingCount: number | null;
    lcpMs: number | null;
    axeViolationCount: number | null;
    headlessScore: number | null;
    error?: string;
  } | null>(),
  enginesRan: jsonb("engines_ran").notNull().$type<string[]>().default([]),
  createdAt: timestamp("created_at").defaultNow().notNull(),
});

export const insertScanSchema = createInsertSchema(scansTable).omit({ id: true, createdAt: true });
export type InsertScan = z.infer<typeof insertScanSchema>;
export type Scan = typeof scansTable.$inferSelect;
