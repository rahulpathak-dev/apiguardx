import { RiskGrade } from "@/lib/api";

const gradeStyles: Record<RiskGrade, string> = {
  A: "border-emerald-200 bg-emerald-50 text-emerald-700",
  B: "border-teal-200 bg-teal-50 text-teal-700",
  C: "border-amber-200 bg-amber-50 text-amber-700",
  D: "border-orange-200 bg-orange-50 text-orange-700",
  F: "border-red-200 bg-red-50 text-red-700"
};

export function RiskGradeBadge({ grade }: { grade: RiskGrade }) {
  return <span className={`inline-flex h-8 min-w-8 items-center justify-center rounded-md border px-2 text-sm font-bold ${gradeStyles[grade]}`}>{grade}</span>;
}
