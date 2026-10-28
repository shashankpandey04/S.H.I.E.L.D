"use client";

import { useEffect, useState } from "react";
import { checkBackendHealth } from "../lib/api";
import { RefreshCwIcon } from "./Icons";

interface TopNavProps {
  title: string;
  description?: string;
  onRefresh?: () => void;
  isRefreshing?: boolean;
}

export function TopNav({
  title,
  description,
  onRefresh,
  isRefreshing = false,
}: TopNavProps) {
  const [apiStatus, setApiStatus] = useState<"checking" | "connected" | "disconnected">("checking");
  const [apiVersion, setApiVersion] = useState<string | null>(null);

  async function verifyConnection() {
    try {
      setApiStatus("checking");
      const health = await checkBackendHealth();
      if (health && health.status === "healthy") {
        setApiStatus("connected");
        setApiVersion(health.version || "0.1.0");
      } else {
        setApiStatus("disconnected");
      }
    } catch {
      setApiStatus("disconnected");
    }
  }

  useEffect(() => {
    verifyConnection();
    const interval = setInterval(verifyConnection, 30000);
    return () => clearInterval(interval);
  }, []);

  return (
    <header className="h-16 border-b border-[#1e2230] bg-[#0c0e14]/90 backdrop-blur px-6 flex items-center justify-between shrink-0">
      <div className="flex flex-col justify-center">
        <h1 className="text-sm font-semibold tracking-wide text-white font-mono uppercase">
          {title}
        </h1>
        {description && (
          <p className="text-xs text-slate-400 font-sans">{description}</p>
        )}
      </div>

      <div className="flex items-center gap-3">
        {onRefresh && (
          <button
            onClick={onRefresh}
            disabled={isRefreshing}
            title="Refresh analysis data"
            className="p-1.5 rounded-md border border-[#1e2230] text-slate-400 hover:text-white hover:bg-slate-800 transition-colors disabled:opacity-50"
          >
            <RefreshCwIcon
              className={`w-3.5 h-3.5 ${isRefreshing ? "animate-spin text-emerald-400" : ""}`}
            />
          </button>
        )}

        {/* Real Backend API Status */}
        <div
          className={`flex items-center gap-2 px-2.5 py-1 rounded-full border text-xs font-mono transition-all ${
            apiStatus === "connected"
              ? "bg-emerald-950/40 border-emerald-800/60 text-emerald-300"
              : apiStatus === "disconnected"
              ? "bg-red-950/40 border-red-800/60 text-red-300"
              : "bg-slate-900 border-slate-700 text-slate-400"
          }`}
          title={
            apiStatus === "connected"
              ? `Connected to S.H.I.E.L.D. FastAPI backend (${apiVersion})`
              : apiStatus === "disconnected"
              ? "Backend API unreachable on configured port. Verify backend server is running."
              : "Checking backend API connectivity..."
          }
        >
          <span
            className={`w-2 h-2 rounded-full ${
              apiStatus === "connected"
                ? "bg-emerald-400 animate-pulse"
                : apiStatus === "disconnected"
                ? "bg-red-500"
                : "bg-amber-400"
            }`}
          />
          <span className="font-medium text-[11px] tracking-tight">
            {apiStatus === "connected"
              ? `API OPERATIONAL ${apiVersion ? `(v${apiVersion})` : ""}`
              : apiStatus === "disconnected"
              ? "API OFFLINE"
              : "CHECKING API..."}
          </span>
        </div>
      </div>
    </header>
  );
}
