import type { ScanResult, CategoryScore, ScanIssue } from "@workspace/api-client-react";
import { ShieldAlert, AlertTriangle, Info, CheckCircle2, Copy, FileCode2, Flame, TrendingDown } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { useToast } from "@/hooks/use-toast";

export function ScanResults({ result }: { result: ScanResult }) {
  const { toast } = useToast();

  const getScoreColor = (score: number) => {
    if (score >= 80) return "text-success";
    if (score >= 60) return "text-warning";
    return "text-destructive";
  };

  const getBarColor = (pct: number) => {
    if (pct >= 80) return "bg-success";
    if (pct >= 60) return "bg-warning";
    return "bg-destructive";
  };

  const getSeverityIcon = (severity: string) => {
    switch (severity) {
      case "critical": return <ShieldAlert className="h-5 w-5 text-destructive" />;
      case "warning": return <AlertTriangle className="h-5 w-5 text-warning" />;
      case "passed": return <CheckCircle2 className="h-5 w-5 text-success" />;
      default: return <Info className="h-5 w-5 text-info" />;
    }
  };

  const getSeverityBadge = (severity: string) => {
    switch (severity) {
      case "critical": return <Badge variant="destructive">Critical</Badge>;
      case "warning": return <Badge className="bg-warning text-warning-foreground hover:bg-warning/80">Warning</Badge>;
      case "passed": return <Badge className="bg-success text-success-foreground hover:bg-success/80">Passed</Badge>;
      default: return <Badge className="bg-info text-info-foreground hover:bg-info/80">Info</Badge>;
    }
  };

  const copyToClipboard = () => {
    navigator.clipboard.writeText(result.fixPrompt);
    toast({
      title: "Copied to clipboard",
      description: "Paste this prompt into any AI coding assistant to fix these issues.",
    });
  };

  const groupedIssues = result.issues.reduce<Record<string, ScanIssue[]>>((acc, issue) => {
    if (!acc[issue.category]) acc[issue.category] = [];
    acc[issue.category].push(issue);
    return acc;
  }, {});

  const criticalCount = result.issues.filter((i) => i.severity === "critical").length;
  const warningCount = result.issues.filter((i) => i.severity === "warning").length;

  const engineLabels: Record<string, string> = {
    "structured-data": "🔗 Structured Data",
    "third-party": "📊 Third-party",
    "headless": "🔬 Headless",
    "local-ai": "🤖 Local AI",
  };

  const aiOverlay = (result as { aiOverlay?: { aiScore: number; riskLabel: string; rationale: string; confidence: number; engineUsed: string } | null }).aiOverlay;
  const enginesRan = (result as { enginesRan?: string[] }).enginesRan ?? [];
  const thirdPartyDomains = (result as { thirdPartyDomains?: string[] }).thirdPartyDomains ?? [];

  return (
    <div className="space-y-8 animate-in fade-in slide-in-from-bottom-4 duration-700">

      {/* Engine Badges */}
      {enginesRan.length > 0 && (
        <div className="flex flex-wrap gap-2 items-center">
          <span className="text-xs font-medium text-muted-foreground uppercase tracking-wide mr-1">Engines:</span>
          {enginesRan.map((engine) => (
            <Badge
              key={engine}
              variant="outline"
              className="text-xs px-2 py-0.5 font-mono border-primary/30 text-primary/80"
            >
              {engineLabels[engine] ?? engine}
            </Badge>
          ))}
        </div>
      )}

      {/* Top row: Score + Quick Stats */}
      <div className="flex flex-col md:flex-row gap-6 items-start md:items-stretch">
        {/* Score Card — Core + AI side by side when AI overlay present */}
        <Card className="w-full md:w-auto shrink-0 bg-card border-card-border overflow-hidden relative">
          <div className="absolute inset-0 bg-gradient-to-br from-primary/5 to-transparent pointer-events-none" />
          <CardContent className={`p-8 flex flex-col items-center justify-center h-full ${aiOverlay ? "min-w-[340px]" : "min-w-[240px]"}`}>
            {aiOverlay ? (
              <div className="flex gap-8 items-center w-full justify-center">
                <div className="flex flex-col items-center">
                  <div className="text-xs font-medium text-muted-foreground uppercase tracking-wider mb-1">Core</div>
                  <div className={`text-7xl font-bold tracking-tighter tabular-nums ${getScoreColor(result.score)}`}>
                    {result.score}
                  </div>
                </div>
                <div className="w-px h-20 bg-border" />
                <div className="flex flex-col items-center">
                  <div className="text-xs font-medium text-muted-foreground uppercase tracking-wider mb-1">AI</div>
                  <div className={`text-7xl font-bold tracking-tighter tabular-nums ${getScoreColor(aiOverlay.aiScore)}`}>
                    {aiOverlay.aiScore}
                  </div>
                  <div className="mt-1 text-xs text-muted-foreground">{aiOverlay.riskLabel}</div>
                </div>
              </div>
            ) : (
              <>
                <div className="text-sm font-medium text-muted-foreground uppercase tracking-wider mb-2">Final Score</div>
                <div className={`text-8xl font-bold tracking-tighter tabular-nums ${getScoreColor(result.score)}`}>
                  {result.score}
                </div>
              </>
            )}
            <div className="mt-4">
              <Badge variant="outline" className="text-base px-4 py-1 font-semibold uppercase tracking-widest border-2">
                {result.grade}
              </Badge>
            </div>
            {aiOverlay && (
              <div className="mt-3 text-xs text-muted-foreground text-center max-w-[280px] italic leading-relaxed">
                {aiOverlay.rationale}
              </div>
            )}
            <div className="mt-4 flex gap-3 text-sm">
              {criticalCount > 0 && (
                <span className="text-destructive font-medium">{criticalCount} critical</span>
              )}
              {warningCount > 0 && (
                <span className="text-warning font-medium">{warningCount} warnings</span>
              )}
              {criticalCount === 0 && warningCount === 0 && (
                <span className="text-success font-medium">No issues</span>
              )}
            </div>
            <div className="mt-3 text-xs text-muted-foreground font-mono">
              {new Date(result.createdAt).toLocaleString()}
            </div>
          </CardContent>
        </Card>

        {/* Quick Summary Stats */}
        <div className="flex-1 grid grid-cols-2 lg:grid-cols-4 gap-4 w-full">
          <Card>
            <CardContent className="p-4 flex flex-col items-center justify-center text-center h-full min-h-[90px]">
              <div className="text-xs font-medium text-muted-foreground uppercase tracking-wide mb-1">Status</div>
              <div className={`text-2xl font-mono font-bold ${result.statusCode < 400 ? "text-success" : "text-destructive"}`}>
                {result.statusCode}
              </div>
            </CardContent>
          </Card>
          <Card>
            <CardContent className="p-4 flex flex-col items-center justify-center text-center h-full min-h-[90px]">
              <div className="text-xs font-medium text-muted-foreground uppercase tracking-wide mb-1">Response</div>
              <div className={`text-2xl font-mono font-bold ${result.responseTimeMs < 300 ? "text-success" : result.responseTimeMs < 1000 ? "text-warning" : "text-destructive"}`}>
                {Math.round(result.responseTimeMs)}ms
              </div>
            </CardContent>
          </Card>
          <Card>
            <CardContent className="p-4 flex flex-col items-center justify-center text-center h-full min-h-[90px]">
              <div className="text-xs font-medium text-muted-foreground uppercase tracking-wide mb-1">Protocol</div>
              <div className={`text-2xl font-mono font-bold ${result.usesHttps ? "text-success" : "text-destructive"}`}>
                {result.usesHttps ? "HTTPS" : "HTTP"}
              </div>
            </CardContent>
          </Card>
          <Card>
            <CardContent className="p-4 flex flex-col items-center justify-center text-center h-full min-h-[90px]">
              <div className="text-xs font-medium text-muted-foreground uppercase tracking-wide mb-1">Page Size</div>
              <div className="text-2xl font-mono font-bold">
                {result.htmlSizeKb.toFixed(1)}
                <span className="text-base font-normal text-muted-foreground">kb</span>
              </div>
            </CardContent>
          </Card>
          <Card className="col-span-2">
            <CardContent className="p-4 flex flex-col justify-center h-full min-h-[90px]">
              <div className="text-xs font-medium text-muted-foreground uppercase tracking-wide mb-1">Final URL</div>
              <div className="text-sm font-mono truncate" title={result.finalUrl}>{result.finalUrl}</div>
              {result.redirectChain.length > 1 && (
                <div className="text-xs text-muted-foreground mt-1">{result.redirectChain.length - 1} redirect(s)</div>
              )}
            </CardContent>
          </Card>
          <Card>
            <CardContent className="p-4 flex flex-col items-center justify-center text-center h-full min-h-[90px]">
              <div className="text-xs font-medium text-muted-foreground uppercase tracking-wide mb-1">Scripts</div>
              <div className={`text-2xl font-mono font-bold ${result.scriptTagCount <= 10 ? "text-success" : result.scriptTagCount <= 30 ? "text-warning" : "text-destructive"}`}>
                {result.scriptTagCount}
              </div>
            </CardContent>
          </Card>
          <Card>
            <CardContent className="p-4 flex flex-col items-center justify-center text-center h-full min-h-[90px]">
              <div className="text-xs font-medium text-muted-foreground uppercase tracking-wide mb-1">Noindex</div>
              <div className={`text-xl font-mono font-bold ${result.hasNoindex ? "text-destructive" : "text-success"}`}>
                {result.hasNoindex ? "YES ⚠" : "No"}
              </div>
            </CardContent>
          </Card>
        </div>
      </div>

      {/* Score Killers — Top 3 */}
      {result.scoreKillers && result.scoreKillers.length > 0 && (
        <Card className="border-destructive/30 bg-destructive/5">
          <CardHeader className="pb-3">
            <CardTitle className="flex items-center gap-2 text-base">
              <Flame className="h-5 w-5 text-destructive" />
              Top Score Killers
            </CardTitle>
            <CardDescription>The three findings costing the most points — fix these first.</CardDescription>
          </CardHeader>
          <CardContent className="pt-0">
            <div className="space-y-2">
              {result.scoreKillers.map((killer, idx) => (
                <div
                  key={idx}
                  className="flex items-start gap-3 p-3 rounded-md bg-card border border-border/60"
                >
                  <div className="flex-shrink-0 w-6 h-6 rounded-full bg-destructive/15 text-destructive font-bold text-xs flex items-center justify-center">
                    {idx + 1}
                  </div>
                  <div className="flex-1 min-w-0">
                    <div className="flex items-start justify-between gap-2">
                      <span className="text-sm font-medium leading-tight">{killer.message}</span>
                      <span className="flex-shrink-0 font-mono text-sm font-bold text-destructive whitespace-nowrap">
                        −{killer.pointsLost} pts
                      </span>
                    </div>
                    <div className="text-xs text-muted-foreground mt-0.5">{killer.category}</div>
                  </div>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}

      {/* Category Scores */}
      <div>
        <h3 className="text-lg font-semibold mb-4 text-muted-foreground uppercase tracking-wider">Category Breakdown</h3>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
          {result.categoryScores.map((cat: CategoryScore) => {
            const percent = (cat.score / cat.maxScore) * 100;
            return (
              <Card key={cat.name} className="bg-card/50">
                <CardContent className="p-4">
                  <div className="flex justify-between items-center mb-2">
                    <div className="font-medium text-sm">{cat.name}</div>
                    <div className={`font-mono text-sm font-semibold ${getScoreColor(percent)}`}>
                      {cat.score}/{cat.maxScore}
                    </div>
                  </div>
                  <div className="h-1.5 w-full rounded-full bg-muted overflow-hidden">
                    <div
                      className={`h-full rounded-full transition-all duration-700 ${getBarColor(percent)}`}
                      style={{ width: `${Math.min(100, percent)}%` }}
                    />
                  </div>
                </CardContent>
              </Card>
            );
          })}
        </div>
      </div>

      {/* Third-party Domains */}
      {thirdPartyDomains.length > 0 && (
        <div>
          <h3 className="text-lg font-semibold mb-3 text-muted-foreground uppercase tracking-wider">
            Third-party Script Domains ({thirdPartyDomains.length})
          </h3>
          <div className="flex flex-wrap gap-2">
            {thirdPartyDomains.map((domain) => (
              <Badge
                key={domain}
                variant="outline"
                className="text-xs font-mono px-2 py-1 border-warning/40 text-warning-foreground/80"
              >
                {domain}
              </Badge>
            ))}
          </div>
        </div>
      )}

      {/* Detailed Findings */}
      <div className="space-y-6">
        <h3 className="text-xl font-bold border-b border-border/60 pb-3">Detailed Findings</h3>
        {Object.entries(groupedIssues).map(([category, issues]) => (
          <div key={category} className="space-y-2">
            <h4 className="text-sm font-semibold text-muted-foreground uppercase tracking-wider px-1">{category}</h4>
            <div className="space-y-2">
              {issues.map((issue, idx) => (
                <Card
                  key={idx}
                  className={
                    issue.severity === "critical"
                      ? "border-destructive/40 bg-destructive/5"
                      : issue.severity === "passed"
                      ? "border-success/20 bg-success/5"
                      : ""
                  }
                >
                  <CardContent className="p-4 sm:p-5 flex gap-4">
                    <div className="mt-0.5 shrink-0">{getSeverityIcon(issue.severity)}</div>
                    <div className="flex-1 space-y-1.5 min-w-0">
                      <div className="flex flex-col sm:flex-row sm:items-start justify-between gap-2">
                        <div className="font-semibold leading-tight">{issue.message}</div>
                        <div className="shrink-0">{getSeverityBadge(issue.severity)}</div>
                      </div>
                      <p className="text-sm text-muted-foreground leading-relaxed">{issue.explanation}</p>
                      {issue.suggestion && issue.severity !== "passed" && (
                        <div className="mt-2 p-3 bg-muted/40 rounded-md border border-border/50 text-sm">
                          <span className="font-semibold text-foreground">Fix: </span>
                          <span className="text-muted-foreground font-mono text-xs">{issue.suggestion}</span>
                        </div>
                      )}
                    </div>
                  </CardContent>
                </Card>
              ))}
            </div>
          </div>
        ))}
      </div>

      {/* Scan Evidence Panel */}
      <Card className="border-border/40 bg-muted/20">
        <CardHeader className="pb-2">
          <CardTitle className="flex items-center gap-2 text-sm font-semibold text-muted-foreground uppercase tracking-wider">
            <TrendingDown className="h-4 w-4" />
            Scan Evidence
          </CardTitle>
          <CardDescription className="text-xs">
            Cryptographic proof this scan was fetched live — not faked or cached.
          </CardDescription>
        </CardHeader>
        <CardContent className="pt-0">
          <dl className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-sm font-mono">
            <div>
              <dt className="text-xs text-muted-foreground mb-0.5">Final URL</dt>
              <dd className="truncate text-foreground/80">{result.finalUrl}</dd>
            </div>
            <div>
              <dt className="text-xs text-muted-foreground mb-0.5">HTTP Status</dt>
              <dd className="text-foreground/80">{result.statusCode}</dd>
            </div>
            <div>
              <dt className="text-xs text-muted-foreground mb-0.5">Body SHA-256 (first 16 hex chars)</dt>
              <dd className="text-foreground/80 tracking-widest">{result.htmlHash}</dd>
            </div>
            <div>
              <dt className="text-xs text-muted-foreground mb-0.5">Response Time</dt>
              <dd className="text-foreground/80">{Math.round(result.responseTimeMs)} ms</dd>
            </div>
            <div>
              <dt className="text-xs text-muted-foreground mb-0.5">Structured Data</dt>
              <dd className={result.hasStructuredData ? "text-success" : "text-muted-foreground"}>
                {result.hasStructuredData ? "JSON-LD detected" : "None found"}
              </dd>
            </div>
            <div>
              <dt className="text-xs text-muted-foreground mb-0.5">Canonical URL</dt>
              <dd className="truncate text-foreground/80">{result.canonicalUrl ?? "—"}</dd>
            </div>
            {Object.keys(result.responseHeadersSnapshot).length > 0 && (
              <div className="sm:col-span-2">
                <dt className="text-xs text-muted-foreground mb-1">Headers Received</dt>
                <dd className="flex flex-wrap gap-1.5">
                  {Object.entries(result.responseHeadersSnapshot).map(([k, v]) => (
                    <span key={k} className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-muted border border-border/40 text-xs text-muted-foreground">
                      <span className="text-foreground/60">{k}:</span>
                      <span className="truncate max-w-[180px]">{v}</span>
                    </span>
                  ))}
                </dd>
              </div>
            )}
          </dl>
        </CardContent>
      </Card>

      {/* Fix Prompt Panel */}
      <Card className="border-primary/20 bg-primary/5">
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="flex items-center gap-2 text-base">
              <FileCode2 className="h-5 w-5" />
              Agent Fix Prompt
            </CardTitle>
            <Button variant="outline" size="sm" onClick={copyToClipboard}>
              <Copy className="h-4 w-4 mr-2" />
              Copy
            </Button>
          </div>
          <CardDescription>
            Paste this into any AI coding assistant to get targeted fixes for these issues.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <pre className="bg-card p-4 rounded-md border border-border/60 text-xs font-mono text-muted-foreground whitespace-pre-wrap overflow-auto max-h-[280px] leading-relaxed">
            {result.fixPrompt}
          </pre>
        </CardContent>
      </Card>
    </div>
  );
}
