import Link from "next/link";

export default function NotFound() {
  return (
    <main className="flex min-h-screen items-center justify-center bg-[#eef3f7] px-5">
      <div className="grid max-w-md justify-items-center gap-4 rounded-lg border border-line bg-white p-8 text-center shadow-sm">
        <p className="text-sm font-semibold text-brand">404</p>
        <h1 className="text-2xl font-bold">Page not found</h1>
        <p className="text-sm text-slate-600">The APIGuardX page you requested does not exist or is not available in this workspace.</p>
        <Link className="focus-ring inline-flex h-10 items-center justify-center rounded-md bg-brand px-4 text-sm font-semibold text-white hover:bg-teal-800" href="/dashboard">
          Back to dashboard
        </Link>
      </div>
    </main>
  );
}
