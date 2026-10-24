"use client";

import { AlertTriangle, Play, Plus, RefreshCw } from "lucide-react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { FormEvent, useEffect, useMemo, useState } from "react";
import { Bar, BarChart, CartesianGrid, Line, LineChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";

import { Button } from "@/components/Button";
import { DownloadReportButton } from "@/components/DownloadReportButton";
import { EmptyState, ErrorState, LoadingState } from "@/components/Status";
import { Input } from "@/components/Input";
import { MetricCard } from "@/components/MetricCard";
import { ProtectedRoute } from "@/components/ProtectedRoute";
import { RiskGradeBadge } from "@/components/RiskGrade";
import { SeverityBadge } from "@/components/SeverityBadge";
import { Shell } from "@/components/Shell";
import { Analytics, Endpoint, EndpointImportResult, Finding, Scan, Target, apiFetch, clearToken, getToken, gradeForScore } from "@/lib/api";

const severities: Finding["severity"][] = ["Low", "Medium", "High", "Critical"];

export default function DashboardPage() {
  return (
    <ProtectedRoute>
      <Shell>
        <DashboardContent />
      </Shell>
    </ProtectedRoute>
  );
}

function DashboardContent() {
  const router = useRouter();
  const [targets, setTargets] = useState<Target[]>([]);
  const [allEndpoints, setAllEndpoints] = useState<Endpoint[]>([]);
  const [endpoints, setEndpoints] = useState<Endpoint[]>([]);
  const [scans, setScans] = useState<Scan[]>([]);
  const [analytics, setAnalytics] = useState<Analytics | null>(null);
  const [selectedTarget, setSelectedTarget] = useState<number | null>(null);
  const [selectedEndpointIds, setSelectedEndpointIds] = useState<number[]>([]);
  const [historyProjectFilter, setHistoryProjectFilter] = useState<number | "all">("all");
  const [historySeverityFilter, setHistorySeverityFilter] = useState<Finding["severity"] | "All">("All");
  const [openApiJson, setOpenApiJson] = useState("");
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");
  const [pageLoading, setPageLoading] = useState(true);
  const [actionLoading, setActionLoading] = useState(false);

  async function loadEndpointsForTargets(targetData: Target[]): Promise<Endpoint[]> {
    const endpointGroups = await Promise.all(targetData.map((target) => apiFetch<Endpoint[]>(`/endpoints?target_id=${target.id}`)));
    return endpointGroups.flat();
  }

  async function refresh(targetOverride?: number | null) {
    if (!getToken()) {
      clearToken();
      router.push("/login");
      return;
    }

    setError("");
    const [targetData, scanData, analyticsData] = await Promise.all([
      apiFetch<Target[]>("/targets"),
      apiFetch<Scan[]>("/scans"),
      apiFetch<Analytics>("/scans/analytics")
    ]);
    const endpointData = await loadEndpointsForTargets(targetData);

    setTargets(targetData);
    setScans(scanData);
    setAnalytics(analyticsData);
    setAllEndpoints(endpointData);

    const nextTarget = targetOverride ?? selectedTarget ?? targetData[0]?.id ?? null;
    setSelectedTarget(nextTarget);
    setEndpoints(nextTarget ? endpointData.filter((endpoint) => endpoint.target_id === nextTarget) : []);
  }

  useEffect(() => {
    refresh()
      .catch((err) => {
        setError(err instanceof Error ? err.message : "Unable to load dashboard");
      })
      .finally(() => setPageLoading(false));
  }, []);

  async function selectTarget(targetId: number) {
    setSelectedTarget(targetId);
    setSelectedEndpointIds([]);
    setError("");
    try {
      const projectEndpoints = await apiFetch<Endpoint[]>(`/endpoints?target_id=${targetId}`);
      setEndpoints(projectEndpoints);
      setAllEndpoints((current) => [...current.filter((endpoint) => endpoint.target_id !== targetId), ...projectEndpoints]);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unable to load endpoints");
    }
  }

  async function createTarget(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setMessage("");
    setError("");
    setActionLoading(true);
    const form = new FormData(event.currentTarget);
    try {
      const target = await apiFetch<Target>("/targets", {
        method: "POST",
        body: JSON.stringify({
          name: form.get("name"),
          base_url: form.get("base_url"),
          authorization_ack: form.get("authorization_ack") === "on"
        })
      });
      event.currentTarget.reset();
      setMessage("API project added.");
      await refresh(target.id);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unable to create project");
    } finally {
      setActionLoading(false);
    }
  }

  async function createEndpoint(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!selectedTarget) return;
    setError("");
    setActionLoading(true);
    const form = new FormData(event.currentTarget);
    try {
      await apiFetch<Endpoint>("/endpoints", {
        method: "POST",
        body: JSON.stringify({
          target_id: selectedTarget,
          method: form.get("method"),
          path: form.get("path"),
          description: form.get("description")
        })
      });
      event.currentTarget.reset();
      setMessage("Endpoint added.");
      await refresh(selectedTarget);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unable to create endpoint");
    } finally {
      setActionLoading(false);
    }
  }

  async function importOpenApiSpec(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!selectedTarget) return;
    setError("");
    setMessage("");
    setActionLoading(true);
    try {
      const spec = JSON.parse(openApiJson);
      const result = await apiFetch<EndpointImportResult>("/endpoints/import-openapi", {
        method: "POST",
        body: JSON.stringify({ target_id: selectedTarget, spec })
      });
      setOpenApiJson("");
      setMessage(`Imported ${result.imported_count} safe endpoint${result.imported_count === 1 ? "" : "s"}. Skipped ${result.skipped_count}.`);
      await refresh(selectedTarget);
    } catch (err) {
      setError(err instanceof SyntaxError ? "OpenAPI import must be valid JSON." : err instanceof Error ? err.message : "Unable to import OpenAPI endpoints");
    } finally {
      setActionLoading(false);
    }
  }
  async function runSelectedScan() {
    if (!selectedTarget) return;
    setActionLoading(true);
    setMessage("Running low-risk scan...");
    setError("");
    try {
      await apiFetch<Scan>("/scans", {
        method: "POST",
        body: JSON.stringify({ target_id: selectedTarget, endpoint_ids: selectedEndpointIds })
      });
      setMessage("Scan completed.");
      await refresh(selectedTarget);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Scan failed");
    } finally {
      setActionLoading(false);
    }
  }

  const severityDistribution = useMemo(() => {
    const counts = analytics?.severity_counts ?? {};
    return severities.map((severity) => ({ severity, count: counts[severity] ?? 0 }));
  }, [analytics]);

  const riskTrend = useMemo(() => {
    return scans
      .slice(0, 8)
      .reverse()
      .map((scan) => ({ scan: `#${scan.id}`, risk: scan.total_risk_score }));
  }, [scans]);

  const highRiskEndpoints = useMemo(() => {
    const grouped = new Map<string, { endpoint: string; count: number; highest: Finding["severity"]; titles: Set<string> }>();
    scans.flatMap((scan) => scan.findings).forEach((finding) => {
      if (finding.severity !== "High" && finding.severity !== "Critical") return;
      const current = grouped.get(finding.endpoint_path) ?? {
        endpoint: finding.endpoint_path,
        count: 0,
        highest: finding.severity,
        titles: new Set<string>()
      };
      current.count += 1;
      current.titles.add(finding.title);
      if (finding.severity === "Critical") current.highest = "Critical";
      grouped.set(finding.endpoint_path, current);
    });
    return Array.from(grouped.values())
      .sort((a, b) => (a.highest === b.highest ? b.count - a.count : a.highest === "Critical" ? -1 : 1))
      .slice(0, 5);
  }, [scans]);

  const recentScans = scans.slice(0, 6);
  const apisScanned = new Set(scans.map((scan) => scan.target_id)).size;
  const latestRiskScore = scans[0]?.total_risk_score ?? Math.round(analytics?.average_risk_score ?? 0);
  const latestRiskGrade = scans[0]?.risk_grade ?? gradeForScore(latestRiskScore);
  const latestRiskExplanation = scans[0]?.risk_explanation ?? `Grade ${latestRiskGrade}: based on average observed risk across completed scans.`;
  const totalVulnerabilities = analytics?.finding_count ?? 0;
  const filteredScans = useMemo(() => {
    return scans.filter((scan) => {
      const projectMatches = historyProjectFilter === "all" || scan.target_id === historyProjectFilter;
      const severityMatches = historySeverityFilter === "All" || scan.findings.some((finding) => finding.severity === historySeverityFilter);
      return projectMatches && severityMatches;
    });
  }, [historyProjectFilter, historySeverityFilter, scans]);

  if (pageLoading) {
    return <LoadingState title="Loading dashboard" message="Fetching projects, scan history, and risk analytics." />;
  }

  return (
    <div className="grid gap-6">
      <section className="flex flex-col gap-3 sm:flex-row sm:items-end sm:justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-normal">Security Dashboard</h1>
          <p className="mt-1 text-sm text-slate-600">Track API coverage, vulnerabilities, risk trends, and report-ready scan history.</p>
        </div>
        <Button variant="secondary" onClick={() => refresh(selectedTarget)} disabled={actionLoading}>
          <RefreshCw size={16} />
          Refresh
        </Button>
      </section>

      {error ? <ErrorState message={error} onRetry={() => refresh(selectedTarget)} /> : null}
      {message ? <p className="rounded-md border border-line bg-white px-4 py-3 text-sm text-slate-600 shadow-sm">{message}</p> : null}

      <section className="grid gap-4 sm:grid-cols-2 xl:grid-cols-6">
        <MetricCard label="APIs scanned" value={apisScanned} helper="Projects with scan history" />
        <MetricCard label="Total endpoints" value={allEndpoints.length} helper="Managed safe endpoints" />
        <MetricCard label="Vulnerabilities" value={totalVulnerabilities} helper="Findings across scans" />
        <MetricCard label="Risk score" value={`${latestRiskScore}/100`} helper={latestRiskExplanation} />
        <MetricCard label="Risk grade" value={latestRiskGrade} helper="A is lowest observed risk; F needs urgent review" />
        <MetricCard label="Scans" value={analytics?.scan_count ?? 0} helper="Total scan runs" />
      </section>

      <section className="grid gap-4 xl:grid-cols-[1.1fr_0.9fr]">
        <div className="rounded-lg border border-line bg-white p-4 shadow-sm">
          <div className="mb-4 flex items-center justify-between">
            <div>
              <h2 className="text-base font-bold">Severity Distribution</h2>
              <p className="mt-1 text-xs text-slate-500">Finding volume by severity across scan history.</p>
            </div>
          </div>
          <div className="h-72">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={severityDistribution}>
                <CartesianGrid strokeDasharray="3 3" />
                <XAxis dataKey="severity" />
                <YAxis allowDecimals={false} />
                <Tooltip />
                <Bar dataKey="count" fill="#0f766e" radius={[4, 4, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        <div className="rounded-lg border border-line bg-white p-4 shadow-sm">
          <div className="mb-4">
            <h2 className="text-base font-bold">Risk Trend</h2>
            <p className="mt-1 text-xs text-slate-500">Latest scan scores in chronological order.</p>
          </div>
          <div className="h-72">
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={riskTrend}>
                <CartesianGrid strokeDasharray="3 3" />
                <XAxis dataKey="scan" />
                <YAxis domain={[0, 100]} />
                <Tooltip />
                <Line type="monotone" dataKey="risk" stroke="#0f766e" strokeWidth={3} dot={{ r: 4 }} />
              </LineChart>
            </ResponsiveContainer>
          </div>
        </div>
      </section>

      <section className="grid gap-4 2xl:grid-cols-[1fr_420px]">
        <div className="rounded-lg border border-line bg-white p-4 shadow-sm">
          <div className="mb-4 flex items-center justify-between">
            <div>
              <h2 className="text-base font-bold">Recent Scans</h2>
              <p className="mt-1 text-xs text-slate-500">Newest scan runs with risk, findings, and report exports.</p>
            </div>
            <span className="text-xs font-semibold text-slate-500">{recentScans.length} shown</span>
          </div>
          {recentScans.length === 0 ? (
            <EmptyState title="No scans yet" message="Add endpoints and run a scan to populate the recent scan table." />
          ) : (
            <div className="overflow-x-auto rounded-md border border-line">
              <table className="w-full min-w-[720px] text-left text-sm">
                <thead className="bg-panel text-xs uppercase text-slate-500">
                  <tr>
                    <th className="p-3">Scan</th>
                    <th className="p-3">Status</th>
                    <th className="p-3">Risk</th>
                    <th className="p-3">Grade</th>
                    <th className="p-3">Findings</th>
                    <th className="p-3">Completed</th>
                    <th className="p-3">Details</th>
                    <th className="p-3">Report</th>
                  </tr>
                </thead>
                <tbody>
                  {recentScans.map((scan) => (
                    <tr key={scan.id} className="border-t border-line">
                      <td className="p-3 font-semibold">#{scan.id}</td>
                      <td className="p-3 capitalize text-slate-600">{scan.status}</td>
                      <td className="p-3 font-semibold">{scan.total_risk_score}/100</td>
                      <td className="p-3"><RiskGradeBadge grade={scan.risk_grade} /></td>
                      <td className="p-3">{scan.findings.length}</td>
                      <td className="p-3 text-slate-600">{scan.completed_at ? new Date(scan.completed_at).toLocaleString() : "In progress"}</td>
                      <td className="p-3">
                        <Link className="focus-ring inline-flex h-9 items-center rounded-md border border-line px-3 text-sm font-semibold hover:bg-slate-50" href={`/scans/${scan.id}`}>View</Link>
                      </td>
                      <td className="p-3">
                        <DownloadReportButton scanId={scan.id} compact />
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>

        <div className="rounded-lg border border-line bg-white p-4 shadow-sm">
          <div className="mb-4 flex items-start gap-3">
            <span className="flex size-9 items-center justify-center rounded-md bg-red-50 text-risk-high">
              <AlertTriangle size={18} />
            </span>
            <div>
              <h2 className="text-base font-bold">High-Risk Endpoints</h2>
              <p className="mt-1 text-xs text-slate-500">Endpoints with high or critical findings.</p>
            </div>
          </div>
          {highRiskEndpoints.length === 0 ? (
            <EmptyState title="No high-risk endpoints" message="High and critical endpoint findings will appear here after scans." />
          ) : (
            <div className="grid gap-3">
              {highRiskEndpoints.map((item) => (
                <div key={item.endpoint} className="rounded-md border border-line p-3">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <p className="font-mono text-xs font-semibold">{item.endpoint}</p>
                    <SeverityBadge severity={item.highest} />
                  </div>
                  <p className="mt-2 text-sm text-slate-600">{item.count} high-risk finding{item.count === 1 ? "" : "s"}</p>
                  <p className="mt-1 truncate text-xs text-slate-500">{Array.from(item.titles).join(", ")}</p>
                </div>
              ))}
            </div>
          )}
        </div>
      </section>

      <section id="projects" className="grid gap-6 xl:grid-cols-[360px_1fr]">
        <div className="grid gap-4">
          <form onSubmit={createTarget} className="grid gap-3 rounded-lg border border-line bg-white p-4 shadow-sm">
            <div>
              <h2 className="text-base font-bold">Add API Project</h2>
              <p className="mt-1 text-xs text-slate-500">Base URLs require written authorization before scanning.</p>
            </div>
            <Input label="Name" name="name" placeholder="Payments API" required />
            <Input label="Base URL" name="base_url" type="url" placeholder="https://api.example.com" required />
            <label className="flex gap-2 text-sm text-slate-700">
              <input name="authorization_ack" type="checkbox" required className="mt-1 size-4 accent-teal-700" />
              I confirm written authorization to scan this API.
            </label>
            <Button disabled={actionLoading}>
              <Plus size={16} />
              Add API
            </Button>
          </form>

          <div className="rounded-lg border border-line bg-white p-4 shadow-sm">
            <h2 className="mb-3 text-base font-bold">Projects</h2>
            {targets.length === 0 ? (
              <EmptyState title="No projects yet" message="Add an authorized API base URL to start managing endpoints and scans." />
            ) : (
              <div className="grid gap-2">
                {targets.map((target) => (
                  <div key={target.id} className={`rounded-md border transition ${selectedTarget === target.id ? "border-brand bg-teal-50" : "border-line bg-white hover:bg-slate-50"}`}>
                    <button className="focus-ring w-full px-3 py-2 text-left text-sm" onClick={() => selectTarget(target.id)}>
                      <span className="block font-semibold">{target.name}</span>
                      <span className="block truncate text-xs text-slate-500">{target.base_url}</span>
                      <span className="mt-2 inline-flex items-center gap-2 text-xs text-slate-600"><RiskGradeBadge grade={gradeForScore(target.risk_score)} /> {target.risk_score}/100</span>
                    </button>
                    <div className="border-t border-line px-3 py-2">
                      <Link className="focus-ring rounded-md text-xs font-semibold text-brand" href={`/projects/${target.id}`}>
                        View details
                      </Link>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>

        <div className="grid gap-4">
          <section className="rounded-lg border border-line bg-white p-4 shadow-sm">
            <div className="mb-4 flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
              <div>
                <h2 className="text-base font-bold">Endpoint Management</h2>
                <p className="mt-1 text-xs text-slate-500">Only GET, HEAD, and OPTIONS are available for low-risk scanning.</p>
              </div>
              <Button onClick={runSelectedScan} disabled={!selectedTarget || actionLoading || endpoints.length === 0}>
                <Play size={16} />
                Scan selected
              </Button>
            </div>

            <form onSubmit={createEndpoint} className="mb-4 grid gap-3 md:grid-cols-[110px_1fr_1fr_auto]">
              <select name="method" className="focus-ring h-10 rounded-md border border-line bg-white px-3 text-sm">
                <option>GET</option>
                <option>HEAD</option>
                <option>OPTIONS</option>
              </select>
              <Input label="Path" name="path" placeholder="/v1/users/me" required />
              <Input label="Description" name="description" placeholder="Current user" />
              <Button className="self-end" variant="secondary" disabled={!selectedTarget || actionLoading}>
                <Plus size={16} />
                Add
              </Button>
            </form>

            <form onSubmit={importOpenApiSpec} className="mb-4 grid gap-3 rounded-md border border-line bg-panel p-3">
              <div>
                <h3 className="text-sm font-bold">Import OpenAPI/Swagger JSON</h3>
                <p className="mt-1 text-xs text-slate-500">Only GET, HEAD, and OPTIONS operations are imported for safe scanning.</p>
              </div>
              <textarea
                className="focus-ring min-h-32 rounded-md border border-line bg-white px-3 py-2 font-mono text-xs text-ink"
                placeholder='{"openapi":"3.0.0","paths":{"/health":{"get":{"summary":"Health check"}}}}'
                value={openApiJson}
                onChange={(event) => setOpenApiJson(event.target.value)}
              />
              <Button className="justify-self-start" variant="secondary" disabled={!selectedTarget || actionLoading || openApiJson.trim().length === 0}>
                Import safe endpoints
              </Button>
            </form>

            {endpoints.length === 0 ? (
              <EmptyState title="No endpoints" message="Select a project and add safe endpoints to include in scans." />
            ) : (
              <div className="overflow-x-auto rounded-md border border-line">
                <table className="w-full min-w-[620px] text-left text-sm">
                  <thead className="bg-panel text-xs uppercase text-slate-500">
                    <tr>
                      <th className="w-12 p-3"></th>
                      <th className="p-3">Method</th>
                      <th className="p-3">Path</th>
                      <th className="p-3">Description</th>
                    </tr>
                  </thead>
                  <tbody>
                    {endpoints.map((endpoint) => (
                      <tr key={endpoint.id} className="border-t border-line">
                        <td className="p-3">
                          <input
                            type="checkbox"
                            className="size-4 accent-teal-700"
                            checked={selectedEndpointIds.includes(endpoint.id)}
                            onChange={(event) =>
                              setSelectedEndpointIds((ids) =>
                                event.target.checked ? [...ids, endpoint.id] : ids.filter((id) => id !== endpoint.id)
                              )
                            }
                          />
                        </td>
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

          <section id="scans" className="rounded-lg border border-line bg-white p-4 shadow-sm">
            <div className="mb-3 flex flex-col gap-3 lg:flex-row lg:items-center lg:justify-between">
              <div>
                <h2 className="text-base font-bold">Scan History</h2>
                <p className="mt-1 text-xs text-slate-500">Filter past scans by project or severity, then open details to manage findings.</p>
              </div>
              <span className="text-xs font-semibold text-slate-500">{filteredScans.length} shown</span>
            </div>
            <div className="mb-4 grid gap-3 sm:grid-cols-2">
              <select className="focus-ring h-10 rounded-md border border-line bg-white px-3 text-sm" value={historyProjectFilter} onChange={(event) => setHistoryProjectFilter(event.target.value === "all" ? "all" : Number(event.target.value))}>
                <option value="all">All projects</option>
                {targets.map((target) => <option key={target.id} value={target.id}>{target.name}</option>)}
              </select>
              <select className="focus-ring h-10 rounded-md border border-line bg-white px-3 text-sm" value={historySeverityFilter} onChange={(event) => setHistorySeverityFilter(event.target.value as Finding["severity"] | "All")}>
                <option value="All">All severities</option>
                {severities.map((item) => <option key={item} value={item}>{item}</option>)}
              </select>
            </div>
            {filteredScans.length === 0 ? (
              <EmptyState title="No scans yet" message="Run a scan to populate detailed history, risk scores, findings, and reports." />
            ) : (
              <div className="grid gap-3">
                {filteredScans.map((scan) => (
                  <article key={scan.id} className="rounded-md border border-line p-3">
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <div>
                        <p className="font-semibold">Scan #{scan.id}</p>
                        <p className="text-xs text-slate-500">{new Date(scan.created_at).toLocaleString()}</p>
                      </div>
                      <div className="flex items-center gap-2">
                        <span className="rounded-md bg-slate-100 px-2 py-1 text-sm font-semibold">{scan.total_risk_score}/100</span>
                        <RiskGradeBadge grade={scan.risk_grade} />
                        <Link className="focus-ring inline-flex h-9 items-center rounded-md border border-line px-3 text-sm font-semibold hover:bg-slate-50" href={`/scans/${scan.id}`}>Details</Link>
                        <DownloadReportButton scanId={scan.id} compact />
                      </div>
                    </div>
                    <p className="mt-3 rounded-md bg-panel px-3 py-2 text-xs text-slate-600">{scan.risk_explanation}</p>
                    <div className="mt-3 grid gap-2">
                      {scan.findings.length === 0 ? <p className="text-sm text-slate-500">No findings recorded.</p> : null}
                      {scan.findings.slice(0, 5).map((finding) => (
                        <div key={finding.id} className="flex flex-wrap items-center gap-2 text-sm">
                          <SeverityBadge severity={finding.severity} />
                          <span className="font-mono text-xs">{finding.endpoint_path}</span>
                          <span>{finding.title}</span>
                        </div>
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






