"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { TopNav } from "../components/TopNav";
import { RiskBadge } from "../components/RiskBadge";
import { StatusBadge } from "../components/StatusBadge";
import {
  AlertTriangleIcon,
  ChevronRightIcon,
  FileTextIcon,
  HistoryIcon,
  ShieldAlertIcon,
  ShieldCheckIcon,
  UploadIcon,
} from "../components/Icons";
import { listEmails, uploadEmailFile } from "../lib/api";
import { EmailListItem } from "../types/email";

export default function OverviewDashboard() {
  const router = useRouter();
  const [emails, setEmails] = useState<EmailListItem[]>([]);
  const [totalCount, setTotalCount] = useState<number>(0);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  const [dragActive, setDragActive] = useState<boolean>(false);
  const [isUploading, setIsUploading] = useState<boolean>(false);
  const [uploadError, setUploadError] = useState<string | null>(null);

  async function loadRecentAnalyses() {
    try {
      setLoading(true);
      setError(null);
      const res = await listEmails(10, 0);
      setEmails(res.emails || []);
      setTotalCount(res.total || 0);
    } catch (err: unknown) {
      if (err instanceof Error) {
        setError(err.message);
      } else {
        setError("Failed to fetch historical analysis records.");
      }
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    loadRecentAnalyses();
  }, []);

  async function handleFileUpload(file: File) {
    if (!file.name.toLowerCase().endsWith(".eml")) {
      setUploadError("Invalid file type. Only standard RFC 822 (.eml) files are supported.");
      return;
    }
    if (file.size > 25 * 1024 * 1024) {
      setUploadError("File exceeds the maximum configured limit of 25 MB.");
      return;
    }

    try {
      setIsUploading(true);
      setUploadError(null);
      const record = await uploadEmailFile(file);
      router.push(`/reports/${encodeURIComponent(record.id)}`);
    } catch (err: unknown) {
      if (err instanceof Error) {
        setUploadError(err.message);
      } else {
        setUploadError("Failed to upload and analyze email.");
      }
      setIsUploading(false);
    }
  }

  const criticalAndHigh = emails.filter((e) => {
    const cat = e.risk_assessment?.category?.toLowerCase();
    return cat === "critical" || cat === "high";
  }).length;

  const moderate = emails.filter((e) => {
    return e.risk_assessment?.category?.toLowerCase() === "moderate";
  }).length;

  const lowOrClean = emails.filter((e) => {
    return e.risk_assessment?.category?.toLowerCase() === "low";
  }).length;

  return (
    <div className="flex-1 flex flex-col min-w-0 h-full overflow-y-auto">
      <TopNav
        title="Overview Dashboard"
        description="Forensic investigation queue and email threat diagnostics"
        onRefresh={loadRecentAnalyses}
        isRefreshing={loading}
      />

      <main className="p-6 space-y-6 max-w-7xl w-full mx-auto">
        {/* KPI Summary Cards */}
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          <div className="p-4 rounded-xl bg-[#0f1117] border border-[#1e2230] flex items-center justify-between">
            <div>
              <p className="text-xs font-mono uppercase tracking-wider text-slate-400">
                Total Ingested
              </p>
              <p className="text-2xl font-bold font-mono text-white mt-1">
                {loading ? "..." : totalCount}
              </p>
            </div>
            <div className="w-10 h-10 rounded-lg bg-slate-800/80 border border-slate-700 flex items-center justify-center text-slate-300">
              <HistoryIcon className="w-5 h-5" />
            </div>
          </div>

          <div className="p-4 rounded-xl bg-[#0f1117] border border-[#1e2230] flex items-center justify-between">
            <div>
              <p className="text-xs font-mono uppercase tracking-wider text-red-400">
                Critical & High Risk
              </p>
              <p className="text-2xl font-bold font-mono text-red-300 mt-1">
                {loading ? "..." : criticalAndHigh}
              </p>
            </div>
            <div className="w-10 h-10 rounded-lg bg-red-950/40 border border-red-800/60 flex items-center justify-center text-red-400">
              <ShieldAlertIcon className="w-5 h-5" />
            </div>
          </div>

          <div className="p-4 rounded-xl bg-[#0f1117] border border-[#1e2230] flex items-center justify-between">
            <div>
              <p className="text-xs font-mono uppercase tracking-wider text-amber-400">
                Moderate Risk
              </p>
              <p className="text-2xl font-bold font-mono text-amber-300 mt-1">
                {loading ? "..." : moderate}
              </p>
            </div>
            <div className="w-10 h-10 rounded-lg bg-amber-950/40 border border-amber-800/60 flex items-center justify-center text-amber-400">
              <AlertTriangleIcon className="w-5 h-5" />
            </div>
          </div>

          <div className="p-4 rounded-xl bg-[#0f1117] border border-[#1e2230] flex items-center justify-between">
            <div>
              <p className="text-xs font-mono uppercase tracking-wider text-emerald-400">
                Low Risk / Clean
              </p>
              <p className="text-2xl font-bold font-mono text-emerald-300 mt-1">
                {loading ? "..." : lowOrClean}
              </p>
            </div>
            <div className="w-10 h-10 rounded-lg bg-emerald-950/40 border border-emerald-800/60 flex items-center justify-center text-emerald-400">
              <ShieldCheckIcon className="w-5 h-5" />
            </div>
          </div>
        </div>

        {/* Quick Upload Drop Area */}
        <div
          onDragOver={(e) => {
            e.preventDefault();
            setDragActive(true);
          }}
          onDragLeave={() => setDragActive(false)}
          onDrop={(e) => {
            e.preventDefault();
            setDragActive(false);
            if (e.dataTransfer.files && e.dataTransfer.files[0]) {
              handleFileUpload(e.dataTransfer.files[0]);
            }
          }}
          className={`relative p-8 rounded-xl border-2 border-dashed transition-all text-center ${
            dragActive
              ? "border-emerald-500 bg-emerald-950/10 shadow-lg shadow-emerald-950/20"
              : "border-[#1e2230] bg-[#0c0e14] hover:border-slate-600 hover:bg-[#0f1118]"
          }`}
        >
          <input
            type="file"
            accept=".eml"
            id="quick-eml-upload"
            className="hidden"
            disabled={isUploading}
            onChange={(e) => {
              if (e.target.files && e.target.files[0]) {
                handleFileUpload(e.target.files[0]);
              }
            }}
          />

          <div className="flex flex-col items-center justify-center space-y-3">
            <div className="w-12 h-12 rounded-xl bg-slate-900 border border-slate-700 flex items-center justify-center text-slate-300">
              {isUploading ? (
                <div className="w-5 h-5 border-2 border-emerald-400 border-t-transparent rounded-full animate-spin" />
              ) : (
                <UploadIcon className="w-6 h-6 text-emerald-400" />
              )}
            </div>

            <div>
              <h3 className="text-sm font-semibold text-white tracking-wide">
                {isUploading ? "Uploading & Analyzing Email..." : "Ingest Email for Threat Inspection"}
              </h3>
              <p className="text-xs text-slate-400 mt-1">
                Drag and drop a <code className="text-emerald-400 font-mono">.eml</code> file here, or click to browse
              </p>
            </div>

            {uploadError && (
              <div className="px-3 py-1.5 rounded bg-red-950/60 border border-red-800 text-red-300 text-xs font-medium">
                {uploadError}
              </div>
            )}

            <label
              htmlFor="quick-eml-upload"
              className={`cursor-pointer inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-semibold tracking-wide transition-colors ${
                isUploading ? "opacity-50 pointer-events-none" : ""
              }`}
            >
              <FileTextIcon className="w-4 h-4" />
              <span>Select .EML File</span>
            </label>
          </div>
        </div>

        {/* Recent Analyses Queue */}
        <div className="rounded-xl border border-[#1e2230] bg-[#0f1117] overflow-hidden">
          <div className="p-4 border-b border-[#1e2230] flex items-center justify-between">
            <div className="flex items-center gap-2.5">
              <HistoryIcon className="w-4 h-4 text-emerald-400" />
              <h2 className="text-xs font-mono font-bold tracking-wider uppercase text-white">
                Recent Email Inspections
              </h2>
            </div>
            <Link
              href="/history"
              className="text-xs text-slate-400 hover:text-emerald-400 flex items-center gap-1 font-mono transition-colors"
            >
              <span>View Full History ({totalCount})</span>
              <ChevronRightIcon className="w-3.5 h-3.5" />
            </Link>
          </div>

          {loading ? (
            <div className="p-8 text-center text-xs text-slate-400 font-mono animate-pulse">
              Connecting to database & loading historical records...
            </div>
          ) : error ? (
            <div className="p-8 text-center space-y-2">
              <p className="text-xs text-red-400 font-mono">{error}</p>
              <button
                onClick={loadRecentAnalyses}
                className="px-3 py-1 text-xs rounded bg-slate-800 border border-slate-700 text-slate-300 hover:text-white"
              >
                Retry
              </button>
            </div>
          ) : emails.length === 0 ? (
            <div className="p-12 text-center space-y-3">
              <div className="w-10 h-10 rounded-full bg-slate-800/80 border border-slate-700 flex items-center justify-center text-slate-400 mx-auto">
                <FileTextIcon className="w-5 h-5" />
              </div>
              <p className="text-xs text-slate-300 font-medium">No email records ingested yet.</p>
              <p className="text-xs text-slate-400 max-w-sm mx-auto">
                Upload a suspicious or diagnostic <span className="font-mono text-slate-300">.eml</span> file above to begin forensic examination.
              </p>
            </div>
          ) : (
            <div className="divide-y divide-[#1e2230]/70">
              {emails.slice(0, 5).map((item) => {
                const subject = item.email?.headers?.subject || "No Subject";
                const senderList = item.email?.headers?.sender || [];
                const sender = senderList.length > 0 ? senderList[0] : item.email?.headers?.from || "Unknown Sender";
                const date = item.uploaded_at
                  ? new Date(item.uploaded_at).toLocaleString()
                  : "Unknown Date";

                return (
                  <Link
                    key={item.id}
                    href={`/reports/${encodeURIComponent(item.id)}`}
                    className="p-4 flex items-center justify-between hover:bg-slate-900/60 transition-colors group"
                  >
                    <div className="space-y-1 min-w-0 pr-4">
                      <div className="flex items-center gap-2">
                        <span className="text-xs font-semibold text-white group-hover:text-emerald-400 transition-colors truncate">
                          {subject}
                        </span>
                        <span className="text-[11px] font-mono text-slate-400 truncate max-w-[180px]">
                          ({item.filename})
                        </span>
                      </div>
                      <div className="flex items-center gap-3 text-[11px] text-slate-400 font-mono">
                        <span className="truncate">From: {sender}</span>
                        <span>•</span>
                        <span>{date}</span>
                      </div>
                    </div>

                    <div className="flex items-center gap-3 shrink-0">
                      <RiskBadge
                        category={item.risk_assessment?.category}
                        score={item.risk_assessment?.score}
                        size="sm"
                      />
                      <StatusBadge status={item.status} size="sm" />
                      <ChevronRightIcon className="w-4 h-4 text-slate-400 group-hover:text-slate-200 group-hover:translate-x-0.5 transition-all" />
                    </div>
                  </Link>
                );
              })}
            </div>
          )}
        </div>
      </main>
    </div>
  );
}
