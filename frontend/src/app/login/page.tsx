"use client";

import { ShieldCheck } from "lucide-react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { FormEvent, useState } from "react";

import { Button } from "@/components/Button";
import { Input } from "@/components/Input";
import { AuthToken, apiFetch, setToken } from "@/lib/api";

export default function LoginPage() {
  const router = useRouter();
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError("");
    setLoading(true);
    const form = new FormData(event.currentTarget);
    try {
      const result = await apiFetch<AuthToken>("/auth/login", {
        method: "POST",
        body: JSON.stringify({ email: form.get("email"), password: form.get("password") })
      });
      setToken(result.access_token);
      router.push("/dashboard");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unable to login");
    } finally {
      setLoading(false);
    }
  }

  return (
    <main className="grid min-h-screen bg-[#eef3f7] lg:grid-cols-[1fr_420px]">
      <section className="hidden border-r border-line bg-white px-10 py-12 lg:flex lg:flex-col lg:justify-between">
        <Link href="/login" className="flex items-center gap-3">
          <span className="flex size-11 items-center justify-center rounded-md bg-ink text-white">
            <ShieldCheck size={24} />
          </span>
          <span>
            <span className="block text-lg font-bold">APIGuardX</span>
            <span className="block text-xs text-slate-500">Enterprise API security scanner</span>
          </span>
        </Link>
        <div className="max-w-xl">
          <h1 className="text-4xl font-bold tracking-normal">Security reporting for APIs your team is authorized to assess.</h1>
          <p className="mt-4 text-base leading-7 text-slate-600">Track API projects, run low-risk scans, review risk trends, and export professional reports from a protected workspace.</p>
        </div>
        <p className="text-xs text-slate-500">Passive and low-risk checks only. No destructive testing.</p>
      </section>

      <section className="flex items-center justify-center px-5 py-10">
        <form onSubmit={submit} className="grid w-full max-w-sm gap-4 rounded-lg border border-line bg-white p-6 shadow-sm">
          <div>
            <div className="mb-4 flex items-center gap-3 lg:hidden">
              <span className="flex size-10 items-center justify-center rounded-md bg-ink text-white">
                <ShieldCheck size={22} />
              </span>
              <span className="font-bold">APIGuardX</span>
            </div>
            <h1 className="text-2xl font-bold">Sign in</h1>
            <p className="mt-1 text-sm text-slate-600">Access your protected scanning workspace.</p>
          </div>
          <Input label="Email" name="email" type="email" autoComplete="email" required />
          <Input label="Password" name="password" type="password" autoComplete="current-password" required />
          {error ? <p className="rounded-md bg-red-50 px-3 py-2 text-sm text-risk-high">{error}</p> : null}
          <Button disabled={loading}>{loading ? "Signing in" : "Sign in"}</Button>
          <p className="text-center text-sm text-slate-600">
            New workspace? <Link className="font-semibold text-brand" href="/register">Create account</Link>
          </p>
        </form>
      </section>
    </main>
  );
}
