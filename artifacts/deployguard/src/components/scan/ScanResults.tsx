import type { ScanResult, CategoryScore, ScanIssue } from "@workspace/api-client-react";
import { ShieldCheck, ShieldAlert, AlertTriangle, Info, CheckCircle2, Copy, FileCode2 } from "lucide-react";
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
      description: "You can now paste this prompt to an AI coding agent to fix these issues.",
    });
  };

  const groupedIssues = result.issues.reduce<Record<string, ScanIssue[]>>((acc, issue) => {
    if (!acc[issue.category]) acc[issue.category] = [];
    acc[issue.category].push(issue);
    return acc;
  }, {});

  return (
    <div className="space-y-8 animate-in fade-in slide-in-from-bottom-4 duration-700">
      <div className="flex flex-col md:flex-row gap-6 items-start md:items-center">
        {/* Score Card */}
        <Card className="w-full md:w-auto shrink-0 bg-card border-card-border overflow-hidden relative">
          <div className="absolute inset-0 bg-gradient-to-br from-primary/5 to-transparent pointer-events-none" />
          <CardContent className="p-8 flex flex-col items-center justify-center min-w-[240px]">
            <div className="text-sm font-medium text-muted-foreground uppercase tracking-wider mb-2">Final Score</div>
            <div className={`text-7xl font-bold tracking-tighter ${getScoreColor(result.score)}`}>
              {result.score}
            </div>
            <div className="mt-4">
              <Badge variant="outline" className="text-base px-4 py-1 font-semibold uppercase tracking-widest border-2">
                {result.grade}
              </Badge>
            </div>
            <div className="mt-6 text-sm text-muted-foreground font-mono">
              Scanned: {new Date(result.createdAt).toLocaleString()}
            </div>
          </CardContent>
        </Card>

        {/* Quick Summary Stats */}
        <div className="flex-1 grid grid-cols-2 lg:grid-cols-4 gap-4 w-full">
          <Card>
            <CardContent className="p-4 flex flex-col items-center justify-center text-center h-full">
              <div className="text-sm text-muted-foreground mb-1">Status Code</div>
              <div className="text-2xl font-mono">{result.statusCode}</div>
            </CardContent>
          </Card>
          <Card>
            <CardContent className="p-4 flex flex-col items-center justify-center text-center h-full">
              <div className="text-sm text-muted-foreground mb-1">Response Time</div>
              <div className="text-2xl font-mono">{result.responseTimeMs}ms</div>
            </CardContent>
          </Card>
          <Card>
            <CardContent className="p-4 flex flex-col items-center justify-center text-center h-full">
              <div className="text-sm text-muted-foreground mb-1">Protocol</div>
              <div className={`text-2xl font-mono font-medium ${result.usesHttps ? "text-success" : "text-destructive"}`}>
                {result.usesHttps ? "HTTPS" : "HTTP"}
              </div>
            </CardContent>
          </Card>
          <Card>
            <CardContent className="p-4 flex flex-col items-center justify-center text-center h-full">
              <div className="text-sm text-muted-foreground mb-1">Page Size</div>
              <div className="text-2xl font-mono">{result.htmlSizeKb.toFixed(1)}kb</div>
            </CardContent>
          </Card>
        </div>
      </div>

      {/* Category Scores */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {result.categoryScores.map((cat: CategoryScore) => {
          const percent = (cat.score / cat.maxScore) * 100;
          return (
            <Card key={cat.name} className="bg-card/50">
              <CardContent className="p-4">
                <div className="flex justify-between items-center mb-2">
                  <div className="font-medium">{cat.name}</div>
                  <div className="font-mono text-sm">{cat.score}/{cat.maxScore}</div>
                </div>
                <div className="h-2 w-full rounded-full bg-muted overflow-hidden">
                  <div
                    className={`h-full rounded-full transition-all duration-500 ${getBarColor(percent)}`}
                    style={{ width: `${Math.min(100, percent)}%` }}
                  />
                </div>
              </CardContent>
            </Card>
          );
        })}
      </div>

      {/* Issues List */}
      <div className="space-y-6">
        <h3 className="text-2xl font-bold border-b pb-2">Detailed Findings</h3>
        {Object.entries(groupedIssues).map(([category, issues]) => (
          <div key={category} className="space-y-3">
            <h4 className="text-lg font-semibold text-muted-foreground uppercase tracking-wider">{category}</h4>
            <div className="space-y-3">
              {issues.map((issue, idx) => (
                <Card key={idx} className={issue.severity === "critical" ? "border-destructive/50 bg-destructive/5" : ""}>
                  <CardContent className="p-4 sm:p-5 flex gap-4">
                    <div className="mt-0.5 shrink-0">
                      {getSeverityIcon(issue.severity)}
                    </div>
                    <div className="flex-1 space-y-2">
                      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                        <div className="font-semibold text-lg">{issue.message}</div>
                        <div>{getSeverityBadge(issue.severity)}</div>
                      </div>
                      <p className="text-sm text-muted-foreground leading-relaxed">{issue.explanation}</p>
                      {issue.suggestion && (
                        <div className="mt-3 p-3 bg-muted/50 rounded-md border text-sm font-mono text-muted-foreground">
                          <span className="font-sans font-medium text-foreground block mb-1">Fix:</span>
                          {issue.suggestion}
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

      {/* Fix Prompt Panel */}
      <Card className="border-primary/20 bg-primary/5">
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="flex items-center gap-2">
              <FileCode2 className="h-5 w-5" />
              Agent Fix Prompt
            </CardTitle>
            <Button variant="outline" size="sm" onClick={copyToClipboard}>
              <Copy className="h-4 w-4 mr-2" />
              Copy Prompt
            </Button>
          </div>
          <CardDescription>
            Copy this tailored prompt into your favorite AI coding assistant to quickly resolve these issues.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <pre className="bg-card p-4 rounded-md border text-sm font-mono text-muted-foreground whitespace-pre-wrap overflow-auto max-h-[300px]">
            {result.fixPrompt}
          </pre>
        </CardContent>
      </Card>
    </div>
  );
}
