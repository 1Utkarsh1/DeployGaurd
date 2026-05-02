import { Router, type IRouter } from "express";
import { desc, eq, sql } from "drizzle-orm";
import { db, scansTable } from "@workspace/db";
import {
  CreateScanBody,
  CreateScanResponse,
  GetScanParams,
  GetScanResponse,
  DeleteScanParams,
  DeleteScanResponse,
  ListScansQueryParams,
  ListScansResponse,
  GetScanStatsResponse,
} from "@workspace/api-zod";
import { scanUrl } from "../lib/scanner";
import { scanRateLimiter } from "../middlewares/rateLimiter";

const router: IRouter = Router();

let activeScanCount = 0;
const MAX_CONCURRENT_SCANS = 3;

router.post("/scan", scanRateLimiter, async (req, res): Promise<void> => {
  const parsed = CreateScanBody.safeParse(req.body);
  if (!parsed.success) {
    const first = parsed.error.issues[0];
    res.status(400).json({ error: first?.message ?? "Invalid request body" });
    return;
  }

  if (activeScanCount >= MAX_CONCURRENT_SCANS) {
    res.setHeader("Retry-After", "10");
    res.status(429).json({
      error: `Server is busy (${activeScanCount} scans in progress). Please try again in a few seconds.`,
    });
    return;
  }

  const { url } = parsed.data;
  activeScanCount++;
  let result;
  try {
    result = await scanUrl(url);
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    req.log.warn({ url, err: msg }, "Scan failed");
    res.status(400).json({ error: msg });
    return;
  } finally {
    activeScanCount--;
  }

  const [scan] = await db
    .insert(scansTable)
    .values({
      url: result.url,
      finalUrl: result.finalUrl,
      score: result.score,
      grade: result.grade,
      statusCode: result.statusCode,
      redirectChain: result.redirectChain,
      usesHttps: result.usesHttps,
      responseTimeMs: result.responseTimeMs,
      title: result.title ?? null,
      metaDescription: result.metaDescription ?? null,
      hasViewport: result.hasViewport,
      hasOpenGraph: result.hasOpenGraph,
      hasRobotsTxt: result.hasRobotsTxt,
      hasSitemapXml: result.hasSitemapXml,
      securityHeaders: result.securityHeaders,
      cookieIssues: result.cookieIssues,
      htmlSizeKb: result.htmlSizeKb,
      scriptTagCount: result.scriptTagCount,
      categoryScores: result.categoryScores,
      issues: result.issues,
      fixPrompt: result.fixPrompt,
      htmlHash: result.htmlHash,
      responseHeadersSnapshot: result.responseHeadersSnapshot,
      scoreKillers: result.scoreKillers,
      canonicalUrl: result.canonicalUrl ?? null,
      hasStructuredData: result.hasStructuredData,
      hasNoindex: result.hasNoindex,
    })
    .returning();

  res.json(
    CreateScanResponse.parse({
      ...scan,
      createdAt: scan.createdAt.toISOString(),
    }),
  );
});

router.get("/scans", async (req, res): Promise<void> => {
  const query = ListScansQueryParams.safeParse(req.query);
  const limit = query.success ? (query.data.limit ?? 20) : 20;
  const offset = query.success ? (query.data.offset ?? 0) : 0;

  const [scans, countResult] = await Promise.all([
    db
      .select({
        id: scansTable.id,
        url: scansTable.url,
        score: scansTable.score,
        grade: scansTable.grade,
        createdAt: scansTable.createdAt,
      })
      .from(scansTable)
      .orderBy(desc(scansTable.createdAt))
      .limit(limit)
      .offset(offset),
    db.select({ count: sql<number>`count(*)` }).from(scansTable),
  ]);

  res.json(
    ListScansResponse.parse({
      scans: scans.map((s) => ({ ...s, createdAt: s.createdAt.toISOString() })),
      total: Number(countResult[0]?.count ?? 0),
    }),
  );
});

router.get("/scans/stats", async (req, res): Promise<void> => {
  const [allScans, recentScans] = await Promise.all([
    db.select({ score: scansTable.score, grade: scansTable.grade }).from(scansTable),
    db
      .select({
        id: scansTable.id,
        url: scansTable.url,
        score: scansTable.score,
        grade: scansTable.grade,
        createdAt: scansTable.createdAt,
      })
      .from(scansTable)
      .orderBy(desc(scansTable.createdAt))
      .limit(5),
  ]);

  const totalScans = allScans.length;
  const averageScore =
    totalScans > 0 ? allScans.reduce((sum, s) => sum + s.score, 0) / totalScans : 0;
  const gradeCounts: Record<string, number> = {};
  for (const s of allScans) {
    gradeCounts[s.grade] = (gradeCounts[s.grade] ?? 0) + 1;
  }

  res.json(
    GetScanStatsResponse.parse({
      totalScans,
      averageScore: Math.round(averageScore),
      gradeCounts,
      recentActivity: recentScans.map((s) => ({ ...s, createdAt: s.createdAt.toISOString() })),
    }),
  );
});

router.get("/scans/:id", async (req, res): Promise<void> => {
  const raw = Array.isArray(req.params.id) ? req.params.id[0] : req.params.id;
  const params = GetScanParams.safeParse({ id: parseInt(raw, 10) });
  if (!params.success) {
    res.status(400).json({ error: "Invalid scan ID" });
    return;
  }

  const [scan] = await db
    .select()
    .from(scansTable)
    .where(eq(scansTable.id, params.data.id));

  if (!scan) {
    res.status(404).json({ error: "Scan not found" });
    return;
  }

  res.json(GetScanResponse.parse({ ...scan, createdAt: scan.createdAt.toISOString() }));
});

router.delete("/scans/:id", async (req, res): Promise<void> => {
  const raw = Array.isArray(req.params.id) ? req.params.id[0] : req.params.id;
  const params = DeleteScanParams.safeParse({ id: parseInt(raw, 10) });
  if (!params.success) {
    res.status(400).json({ error: "Invalid scan ID" });
    return;
  }

  const [deleted] = await db
    .delete(scansTable)
    .where(eq(scansTable.id, params.data.id))
    .returning();

  if (!deleted) {
    res.status(404).json({ error: "Scan not found" });
    return;
  }

  res.json(DeleteScanResponse.parse({ success: true }));
});

export default router;
