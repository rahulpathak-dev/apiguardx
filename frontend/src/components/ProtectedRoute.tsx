"use client";

import { useRouter } from "next/navigation";
import type { ReactNode } from "react";
import { useEffect, useState } from "react";

import { apiFetch, clearToken, User } from "@/lib/api";
import { LoadingState } from "./Status";

export function ProtectedRoute({ children }: { children: ReactNode }) {
  const router = useRouter();
  const [ready, setReady] = useState(false);

  useEffect(() => {
    let active = true;

    apiFetch<User>("/auth/me")
      .then(() => {
        if (active) setReady(true);
      })
      .catch(() => {
        clearToken();
        router.replace("/login");
      });

    return () => {
      active = false;
    };
  }, [router]);

  if (!ready) {
    return <LoadingState title="Checking session" message="Verifying your APIGuardX access token." />;
  }

  return <>{children}</>;
}

