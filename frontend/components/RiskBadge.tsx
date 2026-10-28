import React from "react";

interface RiskBadgeProps {
  category?: string | null;
  score?: number | null;
  showScore?: boolean;
  size?: "sm" | "md" | "lg";
}

export function RiskBadge({
  category,
  score,
  showScore = true,
  size = "md",
}: RiskBadgeProps) {
  const normalized = (category || "").toLowerCase();

  let colorClasses = "bg-slate-800/80 border-slate-700 text-slate-300";
  let label = category ? category.toUpperCase() : "UNKNOWN";

  if (normalized === "critical") {
    colorClasses = "bg-red-950/40 border-red-800/80 text-red-300 shadow-sm shadow-red-950/50";
  } else if (normalized === "high") {
    colorClasses = "bg-orange-950/40 border-orange-800/80 text-orange-300 shadow-sm shadow-orange-950/50";
  } else if (normalized === "moderate") {
    colorClasses = "bg-amber-950/40 border-amber-800/80 text-amber-300 shadow-sm shadow-amber-950/50";
  } else if (normalized === "low") {
    colorClasses = "bg-emerald-950/40 border-emerald-800/80 text-emerald-300 shadow-sm shadow-emerald-950/50";
  }

  const sizeClasses =
    size === "sm"
      ? "text-xs px-2 py-0.5 gap-1.5"
      : size === "lg"
      ? "text-sm px-3.5 py-1.5 gap-2.5 font-semibold"
      : "text-xs px-2.5 py-1 gap-2 font-medium";

  return (
    <span
      className={`inline-flex items-center rounded-md border font-mono tracking-wider ${colorClasses} ${sizeClasses}`}
    >
      <span
        className={`w-1.5 h-1.5 rounded-full ${
          normalized === "critical"
            ? "bg-red-400 animate-pulse"
            : normalized === "high"
            ? "bg-orange-400"
            : normalized === "moderate"
            ? "bg-amber-400"
            : normalized === "low"
            ? "bg-emerald-400"
            : "bg-slate-400"
        }`}
      />
      <span>{label}</span>
      {showScore && typeof score === "number" && (
        <span className="opacity-70 font-sans">({score}/100)</span>
      )}
    </span>
  );
}
