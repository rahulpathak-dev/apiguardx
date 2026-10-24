"use client";

import { ArrowLeft, Save, Trash2 } from "lucide-react";
import Link from "next/link";
import { useParams, useRouter } from "next/navigation";
import { FormEvent, useEffect, useMemo, useState } from "react";

import { Button } from "@/components/Button";
import { DownloadReportButton } from "@/components/DownloadReportButton";
import { Input } from "@/components/Input";
import { ProtectedRoute } from "@/components/ProtectedRoute";
import { RiskGradeBadge } from "@/components/RiskGrade";
import { SeverityBadge } from "@/components/SeverityBadge";
import { Shell } from "@/components/Shell";
import { EmptyState, ErrorState, LoadingState } from "@/components/Status";
import { Endpoint, Scan, Target, apiFetch, gradeForScore } from "@/lib/api";

export default function ProjectDetailsPage() {
  return (
    <ProtectedRoute>
      <Shell>
        <ProjectDetailsContent />
      </Shell>
    </ProtectedRoute>
  );
}

function ProjectDetailsContent() {
  const params = useParams<{ id: string }>();
  const router = useRouter();
  const projectId = Number(params.id);
  const [project, setProject] = useState<Target | null>(null);
  const [endpoints, setEndpoints] = useState<Endpoint[]>([]);
  const [scans, setScans] = useState<Scan[]>([]);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState("");
  const [message, setMessage] = useState("");

  async function loadProject() {
    setError("");
    const [projectData, endpointData, scanData] = await Promise.all([
      apiFetch<Target>(`/targets/${projectId}`),
      apiFetch<Endpoint[]>(`/endpoints?target_id=${projectId}`),
      apiFetch<Scan[]>("/scans")
    ]);
    setProject(projectData);
    setEndpoints(endpointData);
    setScans(scanData.filter((scan) => scan.target_id === projectId));
  }

  useEffect(() => {
    if (!Number.isFinite(projectId)) {
      router.replace("/dashboard");
      return;
    }
    loadProject()
      .catch((err) => setError(err instanceof Error ? err.message : "Unable to load project"))
      .finally(() => setLoading(false));
  }, [projectId]);

  async function updateProject(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!project) return;
    setSaving(true);
    setError("");
    setMessage("");
    const form = new FormData(event.currentTarget);
    try {
      const updated = await apiFetch<Target>(`/targets/${project.id}`, {
        method: "PATCH",
        body: JSON.stringify({
          name: form.get("name"),
          base_url: form.get("base_url"),
          authorization_ack: form.get("authorization_ack") === "on"
        })
      });
      setProject(updated);
      setMessage("Project updated.");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unable to update project");
    } finally {
      setSaving(false);
    }
  }

  async function deleteProject() {
    if (!project) return;
    const confirmed = window.confirm(`Delete ${project.name}? This also removes its endpoints and scan history.`);
    if (!confirmed) return;
    setSaving(true);
    setError("");
    try {
      await apiFetch<void>(`/targets/${project.id}`, { method: "DELETE" });
      router.push("/dashboard");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unable to delete project");
      setSaving(false);
    }
  }

  const findingCount = useMemo(() => scans.reduce((total, scan) => total + scan.findings.length, 0), [scans]);
  const projectGrade = gradeForScore(project?.risk_score ?? 0);
  const latestScan = scans[0];
  const highRiskCount = useMemo(
    () => scans.flatMap((scan) => scan.findings).filter((finding) => finding.severity === "High" || finding.severity === "Critical").length,
    [scans]
  );

  if (loading) {
    return <LoadingState title="Loading project" message="Fetching project details, endpoints, and scan history." />;
  }

  if (!project) {
    return <ErrorState message={error || "Project not found"} onRetry={loadProject} />;
  }

  return (
    <div className="grid gap-6">
      <section className="flex flex-col gap-3 sm:flex-row sm:items-end sm:justify-between">
        <div>
          <Link className="focus-ring mb-3 inline-flex items-center gap-2 rounded-md text-sm font-semibold text-brand" href="/dashboard">
            <ArrowLeft size={16} />
            Dashboard
          </Link>
          <h1 className="text-2xl font-bold tracking-normal">{project.name}</h1>
          <p className="mt-1 break-all text-sm text-slate-600">{project.base_url}</p>
        </div>
        <Button variant="danger" onClick={deleteProject} disabled={saving}>
          <Trash2 size={16} />
          Delete
        </Button>
      </section>

      {error ? <ErrorState message={error} onRetry={loadProject} /> : null}
      {message ? <p className="rounded-md border border-line bg-white px-4 py-3 text-sm text-slate-600 shadow-sm">{message}</p> : null}

      <section className="grid gap-4 md:grid-cols-5">
        <SummaryCard label="Endpoints" value={endpoints.length} />
        <SummaryCard label="Scans" value={scans.length} />
        <SummaryCard label="Findings" value={findingCount} />
        <SummaryCard label="High risk" value={highRiskCount} />
        <div className="rounded-lg border border-line bg-white p-4 shadow-sm">
          <p className="text-sm font-medium text-slate-500">Risk grade</p>
          <div className="mt-2 flex items-center gap-2">
            <RiskGradeBadge grade={projectGrade} />
            <span className="text-sm font-semibold text-slate-600">{project.risk_score}/100</span>
          </div>
          <p className="mt-2 text-xs text-slate-500">{latestScan?.risk_explanation ?? "Run a scan to generate a detailed score explanation."}</p>
        </div>
      </section>

      <section className="grid gap-6 xl:grid-cols-[380px_1fr]">
        <form onSubmit={updateProject} className="grid gap-4 rounded-lg border border-line bg-white p-4 shadow-sm">
          <div>
            <h2 className="text-base font-bold">Project Settings</h2>
            <p className="mt-1 text-xs text-slate-500">Update the display name or authorized API base URL.</p>
          </div>
          <Input label="Name" name="name" defaultValue={project.name} required />
          <Input label="Base URL" name="base_url" type="url" defaultValue={project.base_url} required />
          <label className="flex gap-2 text-sm text-slate-700">
            <input name="authorization_ack" type="checkbox" defaultChecked={project.authorization_ack} required className="mt-1 size-4 accent-teal-700" />
            Written authorization is confirmed for this API.
          </label>
          <Button disabled={saving}>
            <Save size={16} />
            Save changes
          </Button>
        </form>

        <div className="grid gap-4">
          <section className="rounded-lg border border-line bg-white p-4 shadow-sm">
            <h2 className="mb-3 text-base font-bold">Endpoints</h2>
            {endpoints.length === 0 ? (
              <EmptyState title="No endpoints" message="Add endpoints from the dashboard to include them in low-risk scans." />
            ) : (
              <div className="overflow-x-auto rounded-md border border-line">
                <table className="w-full min-w-[560px] text-left text-sm">
                  <thead className="bg-panel text-xs uppercase text-slate-500">
                    <tr>
                      <th className="p-3">Method</th>
                      <th className="p-3">Path</th>
                      <th className="p-3">Description</th>
                    </tr>
                  </thead>
                  <tbody>
                    {endpoints.map((endpoint) => (
                      <tr key={endpoint.id} className="border-t border-line">
                        <td className="p-3 font-semibold">{endpoint.method}</td>
                        <td className="p-3 font-mono text-xs">{endpoint.path}</td>
                        <td className="p-3 text-slate-600">{endpoint.description ?? ""}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </section>

          <section className="rounded-lg border border-line bg-white p-4 shadow-sm">
            <h2 className="mb-3 text-base font-bold">Project Scan History</h2>
            {scans.length === 0 ? (
              <EmptyState title="No scans" message="Run a scan from the dashboard to generate findings and reports for this project." />
            ) : (
              <div className="grid gap-3">
                {scans.map((scan) => (
                  <article key={scan.id} className="rounded-md border border-line p-3">
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <div>
                        <p className="font-semibold">Scan #{scan.id}</p>
                        <p className="text-xs text-slate-500">{new Date(scan.created_at).toLocaleString()}</p>
                      </div>
                      <div className="flex items-center gap-2">
                        <RiskGradeBadge grade={scan.risk_grade} />
                        <DownloadReportButton scanId={scan.id} compact />
                      </div>
                    </div>
                    <p className="mt-3 rounded-md bg-panel px-3 py-2 text-xs text-slate-600">{scan.risk_explanation}</p>
                    <div className="mt-3 flex flex-wrap items-center gap-2 text-sm">
                      <span className="rounded-md bg-slate-100 px-2 py-1 font-semibold">{scan.total_risk_score}/100</span>
                      {scan.findings.slice(0, 4).map((finding) => (
                        <SeverityBadge key={finding.id} severity={finding.severity} />
                      ))}
                    </div>
                  </article>
                ))}
              </div>
            )}
          </section>
        </div>
      </section>
    </div>
  );
}

function SummaryCard({ label, value }: { label: string; value: string | number }) {
  return (
    <div className="rounded-lg border border-line bg-white p-4 shadow-sm">
      <p className="text-sm font-medium text-slate-500">{label}</p>
      <p className="mt-1 text-2xl font-bold">{value}</p>
    </div>
  );
}


