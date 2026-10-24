"use client";

import { Activity, BarChart3, FileText, LogOut, Menu, ShieldCheck, Target, X } from "lucide-react";
import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import type { ReactNode } from "react";
import { useState } from "react";

import { logout } from "@/lib/api";
import { Button } from "./Button";

const navigation = [
  { label: "Dashboard", href: "/dashboard", icon: BarChart3 },
  { label: "Projects", href: "/dashboard#projects", icon: Target },
  { label: "Scans", href: "/dashboard#scans", icon: Activity },
  { label: "Reports", href: "/dashboard#reports", icon: FileText }
];

export function Shell({ children }: { children: ReactNode }) {
  const pathname = usePathname();
  const router = useRouter();
  const [open, setOpen] = useState(false);

  async function signOut() {
    await logout();
    router.push("/login");
  }

  return (
    <div className="min-h-screen bg-[#eef3f7] text-ink">
      <aside
        className={`fixed inset-y-0 left-0 z-40 w-72 border-r border-line bg-white transition-transform duration-200 lg:translate-x-0 ${open ? "translate-x-0" : "-translate-x-full"}`}
      >
        <div className="flex h-full flex-col">
          <div className="flex h-16 items-center justify-between border-b border-line px-5">
            <Link href="/dashboard" className="flex items-center gap-3">
              <span className="flex size-10 items-center justify-center rounded-md bg-ink text-white">
                <ShieldCheck size={22} />
              </span>
              <span>
                <span className="block text-base font-bold">APIGuardX</span>
                <span className="block text-xs text-slate-500">API security scanner</span>
              </span>
            </Link>
            <button className="focus-ring rounded-md p-2 lg:hidden" onClick={() => setOpen(false)} aria-label="Close navigation">
              <X size={18} />
            </button>
          </div>

          <nav className="grid gap-1 px-3 py-4">
            {navigation.map((item) => {
              const Icon = item.icon;
              const active = item.href === "/dashboard" && pathname === "/dashboard";
              return (
                <Link
                  key={item.href}
                  href={item.href}
                  onClick={() => setOpen(false)}
                  className={`focus-ring flex h-11 items-center gap-3 rounded-md px-3 text-sm font-semibold transition ${active ? "bg-teal-50 text-brand" : "text-slate-600 hover:bg-slate-50 hover:text-ink"}`}
                >
                  <Icon size={18} />
                  {item.label}
                </Link>
              );
            })}
          </nav>

          <div className="mt-auto border-t border-line p-4">
            <div className="mb-3 rounded-md bg-panel p-3 text-xs leading-5 text-slate-600">
              Authorized, low-risk API checks only. Keep written permission with the project record.
            </div>
            <Button variant="secondary" className="w-full" onClick={signOut}>
              <LogOut size={16} />
              Sign out
            </Button>
          </div>
        </div>
      </aside>

      {open ? <button className="fixed inset-0 z-30 bg-ink/30 lg:hidden" aria-label="Close navigation overlay" onClick={() => setOpen(false)} /> : null}

      <div className="lg:pl-72">
        <header className="sticky top-0 z-20 border-b border-line bg-white/95 backdrop-blur">
          <div className="flex h-16 items-center justify-between px-4 sm:px-6 lg:px-8">
            <button className="focus-ring rounded-md p-2 lg:hidden" onClick={() => setOpen(true)} aria-label="Open navigation">
              <Menu size={20} />
            </button>
            <div className="hidden lg:block">
              <p className="text-sm font-semibold">Enterprise API Security Scanner</p>
              <p className="text-xs text-slate-500">Monitor authorized APIs, findings, risk, and reports.</p>
            </div>
            <div className="ml-auto flex items-center gap-2 rounded-md border border-line bg-panel px-3 py-2 text-xs font-semibold text-slate-600">
              <span className="size-2 rounded-full bg-emerald-500" />
              Protected session
            </div>
          </div>
        </header>
        <main className="px-4 py-6 sm:px-6 lg:px-8">{children}</main>
      </div>
    </div>
  );
}




