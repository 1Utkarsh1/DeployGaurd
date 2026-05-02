import { useState } from "react";
import { Navbar } from "@/components/layout/Navbar";
import { ScanInput } from "@/components/scan/ScanInput";
import { ScanResults } from "@/components/scan/ScanResults";
import { HistorySection } from "@/components/scan/HistorySection";
import {
  useCreateScan,
  useGetScan,
  getListScansQueryKey,
  getGetScanStatsQueryKey,
  getGetScanQueryKey,
} from "@workspace/api-client-react";
import type { ScanResult } from "@workspace/api-client-react";
import { useQueryClient } from "@tanstack/react-query";
import { useToast } from "@/hooks/use-toast";

export default function Home() {
  const [activeScan, setActiveScan] = useState<ScanResult | null>(null);
  const [selectedScanId, setSelectedScanId] = useState<number | null>(null);
  const queryClient = useQueryClient();
  const { toast } = useToast();

  const createScan = useCreateScan({
    mutation: {
      onSuccess: (data) => {
        setActiveScan(data);
        setSelectedScanId(null);
        queryClient.invalidateQueries({ queryKey: getListScansQueryKey() });
        queryClient.invalidateQueries({ queryKey: getGetScanStatsQueryKey() });
      },
      onError: (err) => {
        const message =
          typeof err === "object" && err !== null && "error" in err
            ? String((err as { error: unknown }).error)
            : "An error occurred while scanning the URL.";
        toast({
          variant: "destructive",
          title: "Scan failed",
          description: message,
        });
      },
    },
  });

  const { data: selectedScanData } = useGetScan(selectedScanId as number, {
    query: {
      enabled: !!selectedScanId,
      queryKey: getGetScanQueryKey(selectedScanId as number),
    },
  });

  const handleScan = (url: string) => {
    createScan.mutate({ data: { url } });
  };

  const handleSelectHistoryScan = (id: number) => {
    setSelectedScanId(id);
    setActiveScan(null);
    window.scrollTo({ top: 0, behavior: "smooth" });
  };

  const currentResult = selectedScanData || activeScan;

  return (
    <div className="min-h-screen flex flex-col relative overflow-hidden">
      <div className="absolute inset-0 bg-[linear-gradient(to_right,#80808012_1px,transparent_1px),linear-gradient(to_bottom,#80808012_1px,transparent_1px)] bg-[size:24px_24px] pointer-events-none" />
      <div className="absolute left-0 right-0 top-0 -z-10 m-auto h-[310px] w-[310px] rounded-full bg-primary/20 opacity-20 blur-[100px]" />

      <Navbar />

      <main className="flex-1 container mx-auto max-w-screen-xl px-4 py-12 relative z-10">
        <section className="mb-16">
          <ScanInput onScan={handleScan} isScanning={createScan.isPending} />
        </section>

        {currentResult && (
          <section className="mb-16">
            <ScanResults result={currentResult} />
          </section>
        )}

        <HistorySection onSelectScan={handleSelectHistoryScan} />
      </main>
    </div>
  );
}
