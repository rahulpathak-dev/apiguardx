import { AlertCircle, Loader2, SearchX } from "lucide-react";

import { Button } from "./Button";

export function LoadingState({ title = "Loading", message = "Fetching the latest data." }: { title?: string; message?: string }) {
  return (
    <div className="flex min-h-64 items-center justify-center rounded-lg border border-line bg-white p-8 text-center shadow-sm">
      <div className="grid justify-items-center gap-3">
        <Loader2 className="animate-spin text-brand" size={28} />
        <div>
          <p className="font-semibold">{title}</p>
          <p className="mt-1 text-sm text-slate-500">{message}</p>
        </div>
      </div>
    </div>
  );
}

export function ErrorState({ message, onRetry }: { message: string; onRetry?: () => void }) {
  return (
    <div className="rounded-lg border border-red-200 bg-white p-5 shadow-sm">
      <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
        <div className="flex items-start gap-3">
          <AlertCircle className="mt-0.5 text-risk-high" size={20} />
          <div>
            <p className="font-semibold text-risk-high">Request failed</p>
            <p className="mt-1 text-sm text-slate-600">{message}</p>
          </div>
        </div>
        {onRetry ? <Button variant="secondary" onClick={onRetry}>Retry</Button> : null}
      </div>
    </div>
  );
}

export function EmptyState({ title, message }: { title: string; message: string }) {
  return (
    <div className="grid justify-items-center gap-2 rounded-md border border-dashed border-line bg-panel p-8 text-center">
      <SearchX className="text-slate-400" size={28} />
      <p className="font-semibold">{title}</p>
      <p className="max-w-md text-sm text-slate-500">{message}</p>
    </div>
  );
}
