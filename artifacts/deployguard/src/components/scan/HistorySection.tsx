import { useListScans, useGetScanStats, useDeleteScan, getListScansQueryKey, getGetScanStatsQueryKey } from "@workspace/api-client-react";
import type { ScanSummary } from "@workspace/api-client-react";
import { useQueryClient } from "@tanstack/react-query";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Trash2, ExternalLink, Activity } from "lucide-react";
import { Skeleton } from "@/components/ui/skeleton";

interface HistorySectionProps {
  onSelectScan: (id: number) => void;
}

export function HistorySection({ onSelectScan }: HistorySectionProps) {
  const queryClient = useQueryClient();
  const { data: statsData, isLoading: isLoadingStats } = useGetScanStats();
  const { data: listData, isLoading: isLoadingList } = useListScans();

  const deleteScan = useDeleteScan({
    mutation: {
      onSuccess: () => {
        queryClient.invalidateQueries({ queryKey: getListScansQueryKey() });
        queryClient.invalidateQueries({ queryKey: getGetScanStatsQueryKey() });
      }
    }
  });

  const getScoreColor = (score: number) => {
    if (score >= 80) return "text-success";
    if (score >= 60) return "text-warning";
    return "text-destructive";
  };

  const handleDelete = (e: React.MouseEvent, id: number) => {
    e.stopPropagation();
    deleteScan.mutate({ id });
  };

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
            <CardTitle className="text-sm font-medium text-muted-foreground uppercase">Total Scans</CardTitle>
          </CardHeader>
          <CardContent>
            {isLoadingStats ? <Skeleton className="h-8 w-16" /> : (
              <div className="text-3xl font-bold">{statsData?.totalScans || 0}</div>
            )}
          </CardContent>
        </Card>
        <Card className="bg-card/50">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium text-muted-foreground uppercase">Avg Score</CardTitle>
          </CardHeader>
          <CardContent>
            {isLoadingStats ? <Skeleton className="h-8 w-16" /> : (
              <div className={`text-3xl font-bold ${getScoreColor(statsData?.averageScore || 0)}`}>
                {statsData?.averageScore?.toFixed(1) || 0}
              </div>
            )}
          </CardContent>
        </Card>
        <Card className="bg-card/50">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium text-muted-foreground uppercase">Grade Distribution</CardTitle>
          </CardHeader>
          <CardContent>
            {isLoadingStats ? <Skeleton className="h-8 w-full" /> : (
              <div className="flex flex-wrap gap-2">
                {Object.entries(statsData?.gradeCounts || {}).map(([grade, count]) => (
                  <Badge key={grade} variant="secondary" className="font-mono">
                    {grade}: {count}
                  </Badge>
                ))}
              </div>
            )}
          </CardContent>
        </Card>
      </div>

      {/* History Table */}
      <Card>
        <CardHeader>
          <CardTitle className="text-xl">Recent Scans</CardTitle>
        </CardHeader>
        <CardContent>
          {isLoadingList ? (
            <div className="space-y-4">
              <Skeleton className="h-10 w-full" />
              <Skeleton className="h-10 w-full" />
              <Skeleton className="h-10 w-full" />
            </div>
          ) : !listData?.scans?.length ? (
            <div className="text-center py-8 text-muted-foreground">
              No scans performed yet. Enter a URL above to start.
            </div>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>URL</TableHead>
                  <TableHead className="w-[100px] text-right">Score</TableHead>
                  <TableHead className="w-[150px]">Grade</TableHead>
                  <TableHead className="w-[200px]">Date</TableHead>
                  <TableHead className="w-[80px]"></TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {listData.scans.map((scan: ScanSummary) => (
                  <TableRow
                    key={scan.id}
                    className="cursor-pointer hover:bg-muted/50 group"
                    onClick={() => onSelectScan(scan.id)}
                  >
                    <TableCell className="font-medium">
                      <div className="flex items-center gap-2">
                        {scan.url}
                        <ExternalLink className="h-3 w-3 text-muted-foreground opacity-0 group-hover:opacity-100 transition-opacity" />
                      </div>
                    </TableCell>
                    <TableCell className={`text-right font-bold ${getScoreColor(scan.score)}`}>
                      {scan.score}
                    </TableCell>
                    <TableCell>
                      <Badge variant="outline">{scan.grade}</Badge>
                    </TableCell>
                    <TableCell className="text-muted-foreground text-sm">
                      {new Date(scan.createdAt).toLocaleDateString()}
                    </TableCell>
                    <TableCell>
                      <Button
                        variant="ghost"
                        size="icon"
                        className="h-8 w-8 text-muted-foreground hover:text-destructive opacity-0 group-hover:opacity-100 transition-opacity"
                        onClick={(e) => handleDelete(e, scan.id)}
                        disabled={deleteScan.isPending}
                      >
                        <Trash2 className="h-4 w-4" />
                      </Button>
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
