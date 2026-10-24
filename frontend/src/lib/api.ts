export type User = {
  id: number;
  email: string;
  full_name: string;
};

export type AuthToken = {
  access_token: string;
  token_type: "bearer";
  expires_in: number;
  expires_at: string;
  user: User;
};

export type Target = {
  id: number;
  name: string;
  base_url: string;
  authorization_ack: boolean;
  risk_score: number;
  last_scan_at: string | null;
  created_at: string;
  updated_at: string;
};

export type TargetUpdate = {
  name?: string;
  base_url?: string;
  authorization_ack?: boolean;
};

export type Endpoint = {
  id: number;
  target_id: number;
  method: string;
  path: string;
  description: string | null;
  created_at: string;
};


export type EndpointImportResult = {
  imported_count: number;
  skipped_count: number;
  endpoints: Endpoint[];
};
export type Finding = {
  id: number;
  endpoint_path: string;
  check_name: string;
  severity: "Low" | "Medium" | "High" | "Critical";
  title: string;
  evidence: string;
  recommendation: string;
  is_reviewed: boolean;
  review_notes: string | null;
  reviewed_at: string | null;
  reviewed_by_user_id: number | null;
};


export type ScanFindingCompare = {
  endpoint_path: string;
  check_name: string;
  severity: Finding["severity"];
  title: string;
};

export type ScanComparison = {
  target_id: number;
  latest_scan_id: number | null;
  previous_scan_id: number | null;
  new_findings: ScanFindingCompare[];
  resolved_findings: ScanFindingCompare[];
  persistent_findings: ScanFindingCompare[];
};

export type RiskGrade = "A" | "B" | "C" | "D" | "F";

export type Scan = {
  id: number;
  target_id: number;
  status: string;
  total_risk_score: number;
  risk_grade: RiskGrade;
  risk_explanation: string;
  summary: string | null;
  created_at: string;
  completed_at: string | null;
  findings: Finding[];
};

export type Analytics = {
  scan_count: number;
  finding_count: number;
  average_risk_score: number;
  severity_counts: Record<string, number>;
};

type ApiErrorBody = {
  detail?: string;
  error?: {
    code?: string;
    message?: string;
    details?: unknown;
  };
};

const API_URL = process.env.NEXT_PUBLIC_API_URL ?? "/api";

export function getToken(): string | null {
  if (typeof window === "undefined") return null;
  return window.localStorage.getItem("apiguardx_token");
}

export function setToken(token: string): void {
  window.localStorage.setItem("apiguardx_token", token);
}

export function clearToken(): void {
  if (typeof window !== "undefined") {
    window.localStorage.removeItem("apiguardx_token");
  }
}

export async function logout(): Promise<void> {
  try {
    await apiFetch<{ message: string }>("/auth/logout", { method: "POST" });
  } finally {
    clearToken();
  }
}

export async function apiFetch<T>(path: string, init: RequestInit = {}): Promise<T> {
  const token = getToken();
  let response: Response;
  try {
    response = await fetch(`${API_URL}${path}`, {
      ...init,
      headers: {
        "Content-Type": "application/json",
        ...(token ? { Authorization: `Bearer ${token}` } : {}),
        ...(init.headers ?? {})
      }
    });
  } catch {
    throw new Error("Cannot reach the API. Start the backend on http://localhost:8000 and try again.");
  }

  if (!response.ok) {
    const body = (await response.json().catch(() => ({ detail: "Request failed" }))) as ApiErrorBody;
    throw new Error(body.error?.message ?? body.detail ?? "Request failed");
  }

  if (response.status === 204) {
    return undefined as T;
  }

  return response.json() as Promise<T>;
}

export function reportUrl(scanId: number): string {
  return `${API_URL}/reports/${scanId}.pdf`;
}



export function gradeForScore(score: number): RiskGrade {
  if (score <= 10) return "A";
  if (score <= 30) return "B";
  if (score <= 55) return "C";
  if (score <= 75) return "D";
  return "F";
}


export async function downloadReport(scanId: number): Promise<void> {
  const token = getToken();
  const response = await fetch(reportUrl(scanId), {
    headers: token ? { Authorization: `Bearer ${token}` } : {}
  });

  if (!response.ok) {
    const body = (await response.json().catch(() => ({ detail: "Report download failed" }))) as ApiErrorBody;
    throw new Error(body.error?.message ?? body.detail ?? "Report download failed");
  }

  const blob = await response.blob();
  const url = window.URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = `apiguardx-security-report-scan-${scanId}.pdf`;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  window.URL.revokeObjectURL(url);
}

