"use client";

import { ArrowLeft, CheckCircle2, GitCompare, Save } from "lucide-react";
import Link from "next/link";
import { useParams, useRouter } from "next/navigation";
import { FormEvent, useEffect, useMemo, useState } from "react";

import { Button } from "@/components/Button";
import { DownloadReportButton } from "@/components/DownloadReportButton";
import { ProtectedRoute } from "@/components/ProtectedRoute";
import { RiskGradeBadge } from "@/components/RiskGrade";
import { SeverityBadge } from "@/components/SeverityBadge";
import { Shell } from "@/components/Shell";
import { EmptyState, ErrorState, LoadingState } from "@/components/Status";
import { Finding, Scan, ScanComparison, apiFetch } from "@/lib/api";

const severities: Array<Finding["severity"] | "All"> = ["All", "Critical", "High", "Medium", "Low"];

export default function ScanDetailsPage() {
  return (
    <ProtectedRoute>
      <Shell>
        <ScanDetailsContent />
      </Shell>
    </ProtectedRoute>
  );
}

function ScanDetailsContent() {
  const params = useParams<{ id: string }>();
  const router = useRouter();
  const scanId = Number(params.id);
  const [scan, setScan] = useState<Scan | null>(null);
  const [comparison, setComparison] = useState<ScanComparison | null>(null);
  const [severity, setSeverity] = useState<Finding["severity"] | "All">("All");
  const [loading, setLoading] = useState(true);
  const [savingFindingId, setSavingFindingId] = useState<number | null>(null);
  const [error, setError] = useState("");
  const [message, setMessage] = useState("");

  async function loadScan() {
    setError("");
    const scanData = await apiFetch<Scan>(`/scans/${scanId}`);
    setScan(scanData);
    const compareData = await apiFetch<ScanComparison>(`/scans/compare/latest?target_id=${scanData.target_id}`);
    setComparison(compareData);
  }

  useEffect(() => {
    if (!Number.isFinite(scanId)) {
      router.replace("/dashboard");
      return;
    }
    loadScan()
      .catch((err) => setError(err instanceof Error ? err.message : "Unable to load scan"))
      .finally(() => setLoading(false));
  }, [scanId]);

  const filteredFindings = useMemo(() => {
    if (!scan) return [];
    return severity === "All" ? scan.findings : scan.findings.filter((finding) => finding.severity === severity);
  }, [scan, severity]);

  async function updateFinding(event: FormEvent<HTMLFormElement>, finding: Finding) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    setSavingFindingId(finding.id);
    setError("");
    setMessage("");
    try {
      await apiFetch<Finding>(`/scans/findings/${finding.id}`, {
        method: "PATCH",
        body: JSON.stringify({
          is_reviewed: form.get("is_reviewed") === "on",
          review_notes: form.get("review_notes")
        })
      });
      setMessage("Finding review updated.");
      await loadScan();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unable to update finding");
    } finally {
      setSavingFindingId(null);
    }
  }

  if (loading) {
    return <LoadingState title="Loading scan" message="Fetching scan metadata, findings, and comparison data." />;
  }

  if (!scan) {
    return <ErrorState message={error || "Scan not found"} onRetry={loadScan} />;
  }

  return (
    <div className="grid gap-6">
      <section className="flex flex-col gap-3 sm:flex-row sm:items-end sm:justify-between">
        <div>
          <Link className="focus-ring mb-3 inline-flex items-center gap-2 rounded-md text-sm font-semibold text-brand" href="/dashboard#scans">
            <ArrowLeft size={16} />
            Scan history
          </Link>
          <div className="flex flex-wrap items-center gap-3">
            <h1 className="text-2xl font-bold tracking-normal">Scan #{scan.id}</h1>
            <RiskGradeBadge grade={scan.risk_grade} />
          </div>
          <p className="mt-1 text-sm text-slate-600">{scan.risk_explanation}</p>
        </div>
        <DownloadReportButton scanId={scan.id} />
      </section>

      {error ? <ErrorState message={error} onRetry={loadScan} /> : null}
      {message ? <p className="rounded-md border border-line bg-white px-4 py-3 text-sm text-slate-600 shadow-sm">{message}</p> : null}

      <section className="grid gap-4 md:grid-cols-4">
        <SummaryCard label="Risk score" value={`${scan.total_risk_score}/100`} />
        <SummaryCard label="Status" value={scan.status} />
        <SummaryCard label="Findings" value={scan.findings.length} />
        <SummaryCard label="Reviewed" value={scan.findings.filter((finding) => finding.is_reviewed).length} />
      </section>

      <section className="rounded-lg border border-line bg-white p-4 shadow-sm">
        <div className="mb-4 flex items-start gap-3">
          <span className="flex size-9 items-center justify-center rounded-md bg-teal-50 text-brand">
            <GitCompare size={18} />
          </span>
          <div>
            <h2 className="text-base font-bold">Latest Scan Comparison</h2>
            <p className="mt-1 text-xs text-slate-500">Compares the latest completed scan for this project with the previous completed scan.</p>
          </div>
        </div>
        {!comparison?.previous_scan_id ? (
          <EmptyState title="No previous scan" message="Run at least two completed scans for this project to compare changes." />
        ) : (
          <div className="grid gap-3 md:grid-cols-3">
            <CompareColumn title="New" findings={comparison.new_findings} tone="border-red-100 bg-red-50" />
            <CompareColumn title="Persistent" findings={comparison.persistent_findings} tone="border-amber-100 bg-amber-50" />
            <CompareColumn title="Resolved" findings={comparison.resolved_findings} tone="border-emerald-100 bg-emerald-50" />
          </div>
        )}
      </section>

      <section className="rounded-lg border border-line bg-white p-4 shadow-sm">
        <div className="mb-4 flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
          <div>
            <h2 className="text-base font-bold">Findings</h2>
            <p className="mt-1 text-xs text-slate-500">Review findings, record notes, and track remediation decisions.</p>
          </div>
          <select className="focus-ring h-10 rounded-md border border-line bg-white px-3 text-sm" value={severity} onChange={(event) => setSeverity(event.target.value as Finding["severity"] | "All")}>
            {severities.map((item) => (
              <option key={item} value={item}>{item === "All" ? "All severities" : item}</option>
            ))}
          </select>
        </div>

        {filteredFindings.length === 0 ? (
          <EmptyState title="No findings" message="No findings match the current severity filter." />
        ) : (
          <div className="grid gap-3">
            {filteredFindings.map((finding) => (
              <article key={finding.id} className="rounded-md border border-line p-4">
                <div className="flex flex-wrap items-start justify-between gap-3">
                  <div className="min-w-0">
                    <div className="flex flex-wrap items-center gap-2">
                      <SeverityBadge severity={finding.severity} />
                      {finding.is_reviewed ? <span className="inline-flex items-center gap-1 rounded-md bg-emerald-50 px-2 py-1 text-xs font-bold text-emerald-700"><CheckCircle2 size={14} />Reviewed</span> : null}
                    </div>
                    <h3 className="mt-2 font-bold">{finding.title}</h3>
                    <p className="mt-1 font-mono text-xs text-slate-500">{finding.endpoint_path} · {finding.check_name}</p>
                  </div>
                </div>
                <div className="mt-3 grid gap-3 text-sm text-slate-600">
                  <p><span className="font-semibold text-ink">Evidence:</span> {finding.evidence}</p>
                  <p><span className="font-semibold text-ink">Remediation:</span> {finding.recommendation}</p>
                </div>
                <form onSubmit={(event) => updateFinding(event, finding)} className="mt-4 grid gap-3 rounded-md bg-panel p-3">
                  <label className="flex items-center gap-2 text-sm font-semibold text-slate-700">
                    <input name="is_reviewed" type="checkbox" defaultChecked={finding.is_reviewed} className="size-4 accent-teal-700" />
                    Mark as reviewed
                  </label>
                  <textarea name="review_notes" defaultValue={finding.review_notes ?? ""} className="focus-ring min-h-20 rounded-md border border-line bg-white px-3 py-2 text-sm" placeholder="Add remediation notes, owner, ticket link, or accepted-risk context." />
                  <Button className="justify-self-start" variant="secondary" disabled={savingFindingId === finding.id}>
                    <Save size={16} />
                    {savingFindingId === finding.id ? "Saving" : "Save review"}
                  </Button>
                </form>
              </article>
            ))}
          </div>
        )}
      </section>
    </div>
  );
}

function SummaryCard({ label, value }: { label: string; value: string | number }) {
  return (
    <div className="rounded-lg border border-line bg-white p-4 shadow-sm">
      <p className="text-sm font-medium text-slate-500">{label}</p>
      <p className="mt-1 text-2xl font-bold capitalize">{value}</p>
    </div>
  );
}

function CompareColumn({ title, findings, tone }: { title: string; findings: ScanComparison["new_findings"]; tone: string }) {
  return (
    <div className={`rounded-md border p-3 ${tone}`}>
      <div className="mb-2 flex items-center justify-between">
        <h3 className="text-sm font-bold">{title}</h3>
        <span className="text-xs font-bold text-slate-600">{findings.length}</span>
      </div>
      {findings.length === 0 ? <p className="text-xs text-slate-500">None</p> : null}
      <div className="grid gap-2">
        {findings.slice(0, 6).map((finding) => (
          <div key={`${finding.endpoint_path}-${finding.check_name}-${finding.title}`} className="rounded-md bg-white/70 p-2 text-xs">
            <div className="mb-1"><SeverityBadge severity={finding.severity} /></div>
            <p className="font-semibold">{finding.title}</p>
            <p className="mt-1 font-mono text-slate-500">{finding.endpoint_path}</p>
          </div>
        ))}
      </div>
    </div>
  );
}
