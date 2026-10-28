"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { TopNav } from "../../components/TopNav";
import { RiskBadge } from "../../components/RiskBadge";
import { StatusBadge } from "../../components/StatusBadge";
import {
  ChevronRightIcon,
  FileTextIcon,
  HistoryIcon,
  ShieldIcon,
} from "../../components/Icons";
import { listEmails } from "../../lib/api";
import { EmailListItem } from "../../types/email";

const PAGE_SIZE = 20;

export default function AnalysisHistoryPage() {
  const [emails, setEmails] = useState<EmailListItem[]>([]);
  const [total, setTotal] = useState<number>(0);
  const [skip, setSkip] = useState<number>(0);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  async function fetchHistory(currentSkip: number) {
    try {
      setLoading(true);
      setError(null);
      const res = await listEmails(PAGE_SIZE, currentSkip);
      setEmails(res.emails || []);
      setTotal(res.total || 0);
    } catch (err: unknown) {
      if (err instanceof Error) {
        setError(err.message);
      } else {
        setError("Failed to load email analysis history.");
      }
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    fetchHistory(skip);
  }, [skip]);

  const currentPage = Math.floor(skip / PAGE_SIZE) + 1;
  const totalPages = Math.ceil(total / PAGE_SIZE) || 1;

  return (
    <div className="flex-1 flex flex-col min-w-0 h-full overflow-y-auto">
      <TopNav
        title="Analysis History"
        description="Comprehensive audit trail of forensic email examinations"
        onRefresh={() => fetchHistory(skip)}
        isRefreshing={loading}
      />

      <main className="p-6 max-w-7xl w-full mx-auto space-y-6">
        <div className="rounded-xl border border-[#1e2230] bg-[#0f1117] overflow-hidden">
          {/* Header Bar */}
          <div className="p-4 border-b border-[#1e2230] flex flex-col sm:flex-row sm:items-center justify-between gap-3">
            <div className="flex items-center gap-2.5">
              <HistoryIcon className="w-4 h-4 text-emerald-400" />
              <h2 className="text-xs font-mono font-bold tracking-wider uppercase text-white">
                Archived Reports
              </h2>
              <span className="text-xs font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-300">
                {total} Total
              </span>
            </div>

            <Link
              href="/analyze"
              className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-medium transition-colors"
            >
              <ShieldIcon className="w-3.5 h-3.5" />
              <span>Analyze New Email</span>
            </Link>
          </div>

          {/* Table Container */}
          {loading ? (
            <div className="p-12 text-center text-xs text-slate-400 font-mono animate-pulse">
              Querying MongoDB email collections...
            </div>
          ) : error ? (
            <div className="p-8 text-center space-y-2">
              <p className="text-xs text-red-400 font-mono">{error}</p>
              <button
                onClick={() => fetchHistory(skip)}
                className="px-3 py-1 text-xs rounded bg-slate-800 border border-slate-700 text-slate-300 hover:text-white"
              >
                Retry Request
              </button>
            </div>
          ) : emails.length === 0 ? (
            <div className="p-16 text-center space-y-3">
              <div className="w-12 h-12 rounded-xl bg-slate-800/80 border border-slate-700 flex items-center justify-center text-slate-400 mx-auto">
                <FileTextIcon className="w-6 h-6" />
              </div>
              <p className="text-sm font-semibold text-white">No Analysis Records Found</p>
              <p className="text-xs text-slate-400 max-w-sm mx-auto">
                No emails have been processed yet. Submit an .eml file via the analyzer to populate the forensic audit log.
              </p>
              <div className="pt-2">
                <Link
                  href="/analyze"
                  className="inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-medium transition-colors"
                >
                  Go to Analyzer
                </Link>
              </div>
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-left border-collapse text-xs">
                <thead>
                  <tr className="border-b border-[#1e2230] bg-[#0c0e14]/80 text-slate-400 font-mono uppercase text-[10px] tracking-wider">
                    <th className="py-3 px-4">Subject & Filename</th>
                    <th className="py-3 px-4">Sender</th>
                    <th className="py-3 px-4">Ingested At</th>
                    <th className="py-3 px-4">Threat Risk</th>
                    <th className="py-3 px-4">Status</th>
                    <th className="py-3 px-4 text-right">Action</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[#1e2230]/70 font-sans">
                  {emails.map((item) => {
                    const subject = item.email?.headers?.subject || "No Subject";
                    const senderList = item.email?.headers?.sender || [];
                    const sender =
                      senderList.length > 0
                        ? senderList[0]
                        : item.email?.headers?.from || "Unknown";
                    const dateFormatted = item.uploaded_at
                      ? new Date(item.uploaded_at).toLocaleString()
                      : "Unknown Date";

                    return (
                      <tr
                        key={item.id}
                        className="hover:bg-slate-900/40 transition-colors group"
                      >
                        <td className="py-3.5 px-4 max-w-xs">
                          <Link
                            href={`/reports/${encodeURIComponent(item.id)}`}
                            className="block font-medium text-white group-hover:text-emerald-400 transition-colors truncate"
                          >
                            {subject}
                          </Link>
                          <span className="text-[11px] font-mono text-slate-400 truncate block">
                            {item.filename}
                          </span>
                        </td>

                        <td className="py-3.5 px-4 font-mono text-slate-300 max-w-[200px] truncate">
                          {sender}
                        </td>

                        <td className="py-3.5 px-4 font-mono text-slate-400 whitespace-nowrap text-[11px]">
                          {dateFormatted}
                        </td>

                        <td className="py-3.5 px-4 whitespace-nowrap">
                          <RiskBadge
                            category={item.risk_assessment?.category}
                            score={item.risk_assessment?.score}
                            size="sm"
                          />
                        </td>

                        <td className="py-3.5 px-4 whitespace-nowrap">
                          <StatusBadge status={item.status} size="sm" />
                        </td>

                        <td className="py-3.5 px-4 text-right whitespace-nowrap">
                          <Link
                            href={`/reports/${encodeURIComponent(item.id)}`}
                            className="inline-flex items-center gap-1 px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-200 hover:text-white font-mono text-[11px] transition-colors"
                          >
                            <span>Inspect</span>
                            <ChevronRightIcon className="w-3 h-3" />
                          </Link>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}

          {/* Pagination Controls */}
          {total > PAGE_SIZE && (
            <div className="p-4 border-t border-[#1e2230] bg-[#0c0e14]/50 flex items-center justify-between text-xs font-mono">
              <span className="text-slate-400">
                Page {currentPage} of {totalPages} ({total} items)
              </span>

              <div className="flex items-center gap-2">
                <button
                  onClick={() => setSkip(Math.max(0, skip - PAGE_SIZE))}
                  disabled={skip === 0 || loading}
                  className="px-3 py-1.5 rounded border border-[#1e2230] bg-slate-900 text-slate-300 hover:bg-slate-800 disabled:opacity-40 transition-colors"
                >
                  Previous
                </button>

                <button
                  onClick={() => setSkip(skip + PAGE_SIZE)}
                  disabled={skip + PAGE_SIZE >= total || loading}
                  className="px-3 py-1.5 rounded border border-[#1e2230] bg-slate-900 text-slate-300 hover:bg-slate-800 disabled:opacity-40 transition-colors"
                >
                  Next
                </button>
              </div>
            </div>
          )}
        </div>
      </main>
    </div>
  );
}
