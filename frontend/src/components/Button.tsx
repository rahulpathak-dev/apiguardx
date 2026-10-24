import type { ButtonHTMLAttributes, ReactNode } from "react";

type Props = ButtonHTMLAttributes<HTMLButtonElement> & {
  children: ReactNode;
  variant?: "primary" | "secondary" | "danger";
};

export function Button({ children, variant = "primary", className = "", ...props }: Props) {
  const variants = {
    primary: "bg-brand text-white hover:bg-teal-800",
    secondary: "bg-white text-ink border border-line hover:bg-slate-50",
    danger: "bg-risk-high text-white hover:bg-red-700"
  };

  return (
    <button
      className={`focus-ring inline-flex h-10 items-center justify-center gap-2 rounded-md px-4 text-sm font-semibold transition disabled:cursor-not-allowed disabled:opacity-50 ${variants[variant]} ${className}`}
      {...props}
    >
      {children}
    </button>
  );
}


