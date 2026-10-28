import React from "react";

interface StatusBadgeProps {
  status?: string | null;
  label?: string;
  size?: "sm" | "md";
}

export function StatusBadge({ status, label, size = "md" }: StatusBadgeProps) {
  const norm = (status || "").toLowerCase().trim();
  const displayLabel = label || norm.toUpperCase() || "UNKNOWN";

  let styles = "bg-slate-900/60 border-slate-700 text-slate-300";

  if (norm === "pass" || norm === "verified" || norm === "analyzed" || norm === "healthy") {
    styles = "bg-emerald-950/40 border-emerald-700/60 text-emerald-300";
  } else if (norm === "fail" || norm === "failed" || norm === "critical") {
    styles = "bg-red-950/40 border-red-700/60 text-red-300";
  } else if (norm === "configured") {
    styles = "bg-sky-950/40 border-sky-700/60 text-sky-300";
  } else if (norm === "suspicious" || norm === "moderate" || norm === "high" || norm === "warning") {
    styles = "bg-amber-950/40 border-amber-700/60 text-amber-300";
  } else if (norm === "unverified" || norm === "signature_present") {
    styles = "bg-indigo-950/40 border-indigo-700/60 text-indigo-300";
  } else if (norm === "invalid") {
    styles = "bg-rose-950/40 border-rose-700/60 text-rose-300";
  } else if (norm === "missing" || norm === "unknown" || norm === "not_checked") {
    styles = "bg-slate-900 border-slate-700/80 text-slate-400";
  } else if (norm === "no_obvious_indicators" || norm === "clean") {
    styles = "bg-emerald-950/30 border-emerald-800/40 text-emerald-400/90";
  }

  const sizeClass =
    size === "sm"
      ? "text-[11px] px-2 py-0.5 font-mono"
      : "text-xs px-2.5 py-1 font-mono";

  return (
    <span
      className={`inline-flex items-center rounded border tracking-wider font-semibold uppercase ${sizeClass} ${styles}`}
    >
      {displayLabel}
    </span>
  );
}
