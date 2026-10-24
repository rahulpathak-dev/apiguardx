import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

const root = dirname(dirname(fileURLToPath(import.meta.url)));

function read(relativePath) {
  return readFileSync(join(root, relativePath), "utf8");
}

test("auth pages expose login and registration flows", () => {
  const login = read("src/app/login/page.tsx");
  const register = read("src/app/register/page.tsx");

  assert.match(login, /apiFetch<AuthToken>\("\/auth\/login"/);
  assert.match(login, /setToken\(result\.access_token\)/);
  assert.match(login, /router\.push\("\/dashboard"\)/);
  assert.match(register, /apiFetch\("\/auth\/register"/);
  assert.match(register, /router\.push\("\/login"\)/);
});

test("dashboard page is protected and renders expected analytics", () => {
  const dashboard = read("src/app/dashboard/page.tsx");

  assert.match(dashboard, /<ProtectedRoute>/);
  assert.match(dashboard, /Severity distribution/i);
  assert.match(dashboard, /Recent scans/i);
  assert.match(dashboard, /High-risk endpoints/i);
  assert.match(dashboard, /ResponsiveContainer/);
  assert.match(dashboard, /DownloadReportButton/);
});

test("project and scan detail pages call the expected backend APIs", () => {
  const projectDetail = read("src/app/projects/[id]/page.tsx");
  const scanDetail = read("src/app/scans/[id]/page.tsx");

  assert.match(projectDetail, /\/endpoints/);
  assert.match(projectDetail, /\/scans/);
  assert.match(scanDetail, /\/scans\/compare\/latest/);
  assert.match(scanDetail, /\/scans\/findings\/\$\{finding\.id\}/);
  assert.match(scanDetail, /DownloadReportButton/);
});

test("reusable components expose stable visual and loading contracts", () => {
  const riskGrade = read("src/components/RiskGrade.tsx");
  const severityBadge = read("src/components/SeverityBadge.tsx");
  const status = read("src/components/Status.tsx");
  const protectedRoute = read("src/components/ProtectedRoute.tsx");

  assert.match(riskGrade, /export function RiskGradeBadge/);
  assert.match(riskGrade, /border-red-200/);
  assert.match(severityBadge, /Critical/);
  assert.match(status, /LoadingState/);
  assert.match(status, /ErrorState/);
  assert.match(protectedRoute, /apiFetch<User>\("\/auth\/me"\)/);
  assert.match(protectedRoute, /router\.replace\("\/login"\)/);
});

test("Next.js proxies /api to the local backend on port 8000", () => {
  const config = read("next.config.mjs");

  assert.match(config, /source: "\/api\/:path\*"/);
  assert.match(config, /127\.0\.0\.1:8000/);
  assert.doesNotMatch(config, /8010/);
});

test("API service handles auth token storage, errors, and PDF download", () => {
  const api = read("src/lib/api.ts");

  assert.match(api, /localStorage\.getItem\("apiguardx_token"\)/);
  assert.match(api, /Authorization: `Bearer \$\{token\}`/);
  assert.match(api, /body\.error\?\.message/);
  assert.match(api, /reportUrl\(scanId: number\)/);
  assert.match(api, /apiguardx-security-report-scan-\$\{scanId\}\.pdf/);
  assert.match(api, /gradeForScore\(score: number\)/);
});
test("React node types are imported explicitly", () => {
  const layout = read("src/app/layout.tsx");
  const shell = read("src/components/Shell.tsx");
  const protectedRoute = read("src/components/ProtectedRoute.tsx");

  assert.match(layout, /import type \{ ReactNode \} from "react"/);
  assert.match(shell, /import type \{ ReactNode \} from "react"/);
  assert.match(protectedRoute, /import type \{ ReactNode \} from "react"/);
  assert.doesNotMatch(`${layout}\n${shell}\n${protectedRoute}`, /React\.ReactNode/);
});

