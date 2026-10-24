"use client";

import { Download } from "lucide-react";
import { useState } from "react";

import { Button } from "@/components/Button";
import { downloadReport } from "@/lib/api";

export function DownloadReportButton({ scanId, compact = false }: { scanId: number; compact?: boolean }) {
  const [loading, setLoading] = useState(false);

  async function handleDownload() {
    setLoading(true);
    try {
      await downloadReport(scanId);
    } catch (err) {
      window.alert(err instanceof Error ? err.message : "Unable to download report");
    } finally {
      setLoading(false);
    }
  }

  return (
    <Button type="button" variant="secondary" className={compact ? "h-9 px-3" : ""} onClick={handleDownload} disabled={loading}>
      <Download size={16} />
      {loading ? "Preparing" : "PDF"}
    </Button>
  );
}
