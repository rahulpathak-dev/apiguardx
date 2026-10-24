import type { Finding } from "@/lib/api";

const severityClass: Record<Finding["severity"], string> = {
  Low: "bg-blue-50 text-risk-low ring-blue-100",
  Medium: "bg-amber-50 text-risk-medium ring-amber-100",
  High: "bg-red-50 text-risk-high ring-red-100",
  Critical: "bg-red-100 text-risk-critical ring-red-200"
};

export function SeverityBadge({ severity }: { severity: Finding["severity"] }) {
  return <span className={`rounded-md px-2 py-1 text-xs font-bold ring-1 ${severityClass[severity]}`}>{severity}</span>;
}
