import { useState } from "react";
import { useListScans, useGetScanStats, useDeleteScan, getListScansQueryKey, getGetScanStatsQueryKey } from "@workspace/api-client-react";
import type { ScanSummary } from "@workspace/api-client-react";
import { useQueryClient } from "@tanstack/react-query";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Trash2, ExternalLink, Activity, AlertTriangle } from "lucide-react";
import { Skeleton } from "@/components/ui/skeleton";

interface HistorySectionProps {
  onSelectScan: (id: number) => void;
}

export function HistorySection({ onSelectScan }: HistorySectionProps) {
  const queryClient = useQueryClient();
  const [confirmDeleteId, setConfirmDeleteId] = useState<number | null>(null);

  const { data: statsData, isLoading: isLoadingStats } = useGetScanStats();
  const { data: listData, isLoading: isLoadingList } = useListScans();

  const deleteScan = useDeleteScan({
    mutation: {
      onSuccess: () => {
        setConfirmDeleteId(null);
        queryClient.invalidateQueries({ queryKey: getListScansQueryKey() });
        queryClient.invalidateQueries({ queryKey: getGetScanStatsQueryKey() });
      },
    },
  });

  const getScoreColor = (score: number) => {
    if (score >= 80) return "text-success";
    if (score >= 60) return "text-warning";
    return "text-destructive";
  };

  const handleDeleteClick = (e: React.MouseEvent, id: number) => {
    e.stopPropagation();
    if (confirmDeleteId === id) {
      deleteScan.mutate({ id });
    } else {
      setConfirmDeleteId(id);
    }
  };

  const handleCancelDelete = (e: React.MouseEvent) => {
    e.stopPropagation();
    setConfirmDeleteId(null);
  };

  const averageScoreDisplay =
    statsData?.averageScore !== undefined ? statsData.averageScore.toFixed(1) : "—";

  return (
    <div className="space-y-8 mt-16 pt-16 border-t border-border/40">
      <div className="flex items-center gap-2 mb-6">
        <Activity className="h-6 w-6 text-primary" />
        <h2 className="text-2xl font-bold tracking-tight">Fleet Overview</h2>
      </div>

      {/* Stats row */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <Card className="bg-card/50">
          <CardHeader className="pb-2">
            <CardTitle className="text-xs font-medium text-muted-foreground uppercase tracking-wide">Total Scans</CardTitle>
          </CardHeader>
          <CardContent>
            {isLoadingStats ? (
              <Skeleton className="h-8 w-16" />
            ) : (
              <div className="text-3xl font-bold tabular-nums">{statsData?.totalScans ?? 0}</div>
            )}
          </CardContent>
        </Card>

        <Card className="bg-card/50">
          <CardHeader className="pb-2">
            <CardTitle className="text-xs font-medium text-muted-foreground uppercase tracking-wide">Avg Score</CardTitle>
          </CardHeader>
          <CardContent>
            {isLoadingStats ? (
              <Skeleton className="h-8 w-16" />
            ) : (
              <div className={`text-3xl font-bold tabular-nums ${getScoreColor(statsData?.averageScore ?? 0)}`}>
                {averageScoreDisplay}
              </div>
            )}
          </CardContent>
        </Card>

        <Card className="bg-card/50">
          <CardHeader className="pb-2">
            <CardTitle className="text-xs font-medium text-muted-foreground uppercase tracking-wide">Grade Distribution</CardTitle>
          </CardHeader>
          <CardContent>
            {isLoadingStats ? (
              <Skeleton className="h-8 w-full" />
            ) : (
              <div className="flex flex-wrap gap-2">
                {Object.keys(statsData?.gradeCounts ?? {}).length === 0 ? (
                  <span className="text-sm text-muted-foreground">No scans yet</span>
                ) : (
                  Object.entries(statsData?.gradeCounts ?? {}).map(([grade, count]) => (
                    <Badge key={grade} variant="secondary" className="font-mono text-xs">
                      {grade}: {count}
                    </Badge>
                  ))
                )}
              </div>
            )}
          </CardContent>
        </Card>
      </div>

      {/* History Table */}
      <Card>
        <CardHeader>
          <CardTitle className="text-lg">Recent Scans</CardTitle>
        </CardHeader>
        <CardContent>
          {isLoadingList ? (
            <div className="space-y-3">
              <Skeleton className="h-10 w-full" />
              <Skeleton className="h-10 w-full" />
              <Skeleton className="h-10 w-full" />
            </div>
          ) : !listData?.scans?.length ? (
            <div className="text-center py-12 text-muted-foreground">
              <Activity className="h-10 w-10 mx-auto mb-3 opacity-30" />
              <p>No scans yet. Enter a URL above to get started.</p>
            </div>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>URL</TableHead>
                  <TableHead className="w-[80px] text-right">Score</TableHead>
                  <TableHead className="w-[130px]">Grade</TableHead>
                  <TableHead className="w-[160px]">Date</TableHead>
                  <TableHead className="w-[120px] text-right">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {listData.scans.map((scan: ScanSummary) => (
                  <TableRow
                    key={scan.id}
                    className="cursor-pointer hover:bg-muted/40 group"
                    onClick={() => {
                      if (confirmDeleteId !== scan.id) onSelectScan(scan.id);
                    }}
                  >
                    <TableCell className="font-medium">
                      <div className="flex items-center gap-2 min-w-0">
                        <span className="truncate max-w-[260px] font-mono text-sm" title={scan.url}>
                          {scan.url}
                        </span>
                        <ExternalLink className="h-3 w-3 text-muted-foreground shrink-0 opacity-0 group-hover:opacity-100 transition-opacity" />
                      </div>
                    </TableCell>
                    <TableCell className={`text-right font-bold tabular-nums ${getScoreColor(scan.score)}`}>
                      {scan.score}
                    </TableCell>
                    <TableCell>
                      <Badge variant="outline" className="text-xs">{scan.grade}</Badge>
                    </TableCell>
                    <TableCell className="text-muted-foreground text-sm tabular-nums">
                      {new Date(scan.createdAt).toLocaleDateString(undefined, {
                        month: "short",
                        day: "numeric",
                        year: "numeric",
                      })}
                    </TableCell>
                    <TableCell>
                      <div className="flex items-center justify-end gap-1" onClick={(e) => e.stopPropagation()}>
                        {confirmDeleteId === scan.id ? (
                          <>
                            <Button
                              variant="destructive"
                              size="sm"
                              className="h-7 px-2 text-xs"
                              onClick={(e) => handleDeleteClick(e, scan.id)}
                              disabled={deleteScan.isPending}
                            >
                              <AlertTriangle className="h-3 w-3 mr-1" />
                              Confirm
                            </Button>
                            <Button
                              variant="ghost"
                              size="sm"
                              className="h-7 px-2 text-xs"
                              onClick={handleCancelDelete}
                            >
                              Cancel
                            </Button>
                          </>
                        ) : (
                          <Button
                            variant="ghost"
                            size="icon"
                            className="h-8 w-8 text-muted-foreground hover:text-destructive opacity-0 group-hover:opacity-100 transition-opacity"
                            onClick={(e) => handleDeleteClick(e, scan.id)}
                          >
                            <Trash2 className="h-4 w-4" />
                          </Button>
                        )}
                      </div>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
