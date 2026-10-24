import type { InputHTMLAttributes } from "react";

type Props = InputHTMLAttributes<HTMLInputElement> & {
  label: string;
};

export function Input({ label, className = "", ...props }: Props) {
  return (
    <label className="grid gap-1 text-sm font-medium text-slate-700">
      {label}
      <input
        className={`focus-ring h-10 rounded-md border border-line bg-white px-3 text-sm text-ink ${className}`}
        {...props}
      />
    </label>
  );
}

