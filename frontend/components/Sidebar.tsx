"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import {
  AnalyzeIcon,
  HistoryIcon,
  OverviewIcon,
  ShieldIcon,
} from "./Icons";

export function Sidebar() {
  const pathname = usePathname();

  const navItems = [
    {
      name: "Overview",
      href: "/",
      icon: OverviewIcon,
      active: pathname === "/",
    },
    {
      name: "Analyze Email",
      href: "/analyze",
      icon: AnalyzeIcon,
      active: pathname.startsWith("/analyze"),
    },
    {
      name: "Analysis History",
      href: "/history",
      icon: HistoryIcon,
      active: pathname.startsWith("/history") || pathname.startsWith("/reports"),
    },
  ];

  return (
    <aside className="w-64 border-r border-[#1e2230] bg-[#0c0e14] flex flex-col justify-between shrink-0 select-none">
      <div>
        {/* Brand Header */}
        <div className="p-5 border-b border-[#1e2230]/80">
          <Link href="/" className="flex items-center gap-3 group">
            <div className="w-9 h-9 rounded-lg bg-emerald-950/60 border border-emerald-500/40 flex items-center justify-center text-emerald-400 group-hover:border-emerald-400 transition-colors shadow-sm shadow-emerald-950/40">
              <ShieldIcon className="w-5 h-5 text-emerald-400" />
            </div>
            <div>
              <div className="flex items-center gap-1.5">
                <span className="font-mono text-base font-bold tracking-widest text-white">
                  S.H.I.E.L.D.
                </span>
                <span className="text-[10px] px-1.5 py-0.2 rounded bg-emerald-950/80 border border-emerald-700/50 text-emerald-400 font-mono">
                  v0.1
                </span>
              </div>
              <p className="text-[11px] text-slate-400 font-medium tracking-tight">
                Forensic Email Intelligence
              </p>
            </div>
          </Link>
        </div>

        {/* Navigation */}
        <nav className="p-3 space-y-1">
          <div className="px-3 pt-3 pb-1.5 text-[10px] font-mono font-semibold tracking-wider text-slate-400 uppercase">
            Investigation
          </div>
          {navItems.map((item) => {
            const Icon = item.icon;
            return (
              <Link
                key={item.href}
                href={item.href}
                className={`flex items-center gap-3 px-3 py-2.5 rounded-lg text-xs font-medium transition-all ${
                  item.active
                    ? "bg-slate-800/80 text-white border border-slate-700/80 shadow-sm"
                    : "text-slate-400 hover:text-slate-200 hover:bg-slate-900/60"
                }`}
              >
                <Icon
                  className={`w-4 h-4 ${
                    item.active ? "text-emerald-400" : "text-slate-400"
                  }`}
                />
                <span>{item.name}</span>
                {item.active && (
                  <span className="ml-auto w-1.5 h-1.5 rounded-full bg-emerald-400" />
                )}
              </Link>
            );
          })}
        </nav>
      </div>

      {/* Product Identity Section */}
      <div className="p-4 border-t border-[#1e2230]/80 bg-[#08090d]/60">
        <div className="p-3 rounded-lg bg-[#0e1118] border border-[#1e2230] space-y-1.5">
          <div className="flex items-center justify-between">
            <span className="text-[10px] font-mono uppercase text-emerald-400/90 tracking-wider font-semibold">
              Platform Spec
            </span>
            <span className="text-[9px] text-slate-400 font-mono">SecOps</span>
          </div>
          <p className="text-[11px] leading-relaxed text-slate-300 font-sans">
            Security & Header Inspection for Email, Logging & Diagnostics
          </p>
          <div className="pt-1 border-t border-[#1e2230]/60">
            <p className="text-[10px] text-slate-400 italic font-mono">
              “Every email has a story. Uncover it.”
            </p>
          </div>
        </div>
      </div>
    </aside>
  );
}
