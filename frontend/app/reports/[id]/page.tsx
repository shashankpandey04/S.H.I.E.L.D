"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { useParams } from "next/navigation";
import { TopNav } from "../../../components/TopNav";
import { RiskBadge } from "../../../components/RiskBadge";
import { StatusBadge } from "../../../components/StatusBadge";
import {
  AlertOctagonIcon,
  AlertTriangleIcon,
  ArrowLeftIcon,
  CheckCircleIcon,
  ChevronDownIcon,
  ChevronUpIcon,
  CopyIcon,
  FileTextIcon,
  InfoIcon,
  LinkIcon,
  MailIcon,
  PaperclipIcon,
  ServerIcon,
  ShieldAlertIcon,
  ShieldCheckIcon,
} from "../../../components/Icons";
import { getEmailAnalysis } from "../../../lib/api";
import { EmailAnalysisRecord } from "../../../types/email";

export default function AnalysisReportPage() {
  const params = useParams();
  const id = typeof params?.id === "string" ? params.id : Array.isArray(params?.id) ? params.id[0] : "";

  const [report, setReport] = useState<EmailAnalysisRecord | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  const [receivedExpanded, setReceivedExpanded] = useState<boolean>(false);
  const [activeTab, setActiveTab] = useState<"text" | "html" | "headers">("text");
  const [copiedUrl, setCopiedUrl] = useState<string | null>(null);

  async function fetchReport() {
    if (!id) return;
    try {
      setLoading(true);
      setError(null);
      const data = await getEmailAnalysis(id);
      setReport(data);
    } catch (err: unknown) {
      if (err instanceof Error) {
        setError(err.message);
      } else {
        setError("Failed to fetch email analysis record.");
      }
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    fetchReport();
  }, [id]);

  function copyToClipboard(text: string) {
    navigator.clipboard.writeText(text);
    setCopiedUrl(text);
    setTimeout(() => setCopiedUrl(null), 2000);
  }

  function formatBytes(bytes: number): string {
    if (!bytes || bytes === 0) return "0 Bytes";
    const k = 1024;
    const sizes = ["Bytes", "KB", "MB"];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + " " + sizes[i];
  }

  if (loading) {
    return (
      <div className="flex-1 flex flex-col min-w-0 h-full overflow-y-auto">
        <TopNav title="Forensic Report" description="Loading analysis..." />
        <div className="flex-1 flex items-center justify-center p-12">
          <div className="text-center space-y-3 font-mono text-xs text-slate-400">
            <div className="w-8 h-8 border-2 border-emerald-400 border-t-transparent rounded-full animate-spin mx-auto" />
            <p>Retrieving diagnostic records for ID: {id}...</p>
          </div>
        </div>
      </div>
    );
  }

  if (error || !report) {
    return (
      <div className="flex-1 flex flex-col min-w-0 h-full overflow-y-auto">
        <TopNav title="Forensic Report" description="Inspection retrieval failed" />
        <div className="flex-1 flex items-center justify-center p-12">
          <div className="max-w-md w-full p-6 rounded-xl border border-red-900/60 bg-red-950/20 text-center space-y-4">
            <div className="w-12 h-12 rounded-xl bg-red-950 border border-red-800 flex items-center justify-center text-red-400 mx-auto">
              <AlertOctagonIcon className="w-6 h-6" />
            </div>
            <div>
              <h2 className="text-sm font-semibold text-white font-mono">Report Not Found or Unreachable</h2>
              <p className="text-xs text-red-300 mt-1">{error || "No record matched the supplied analysis identifier."}</p>
            </div>
            <div className="flex items-center justify-center gap-3 pt-2">
              <Link
                href="/history"
                className="inline-flex items-center gap-2 px-3.5 py-1.5 rounded-lg border border-slate-700 bg-slate-900 text-slate-300 text-xs font-mono hover:text-white"
              >
                <ArrowLeftIcon className="w-3.5 h-3.5" />
                <span>Return to History</span>
              </Link>
              <button
                onClick={fetchReport}
                className="px-3.5 py-1.5 rounded-lg bg-red-900/60 hover:bg-red-800 border border-red-700 text-white text-xs font-mono"
              >
                Retry
              </button>
            </div>
          </div>
        </div>
      </div>
    );
  }

  const { email, authentication, urls, url_analysis, header_analysis, risk_assessment } = report;
  const headers = email?.headers || {};
  const senderAddresses = headers.sender || [];
  const senderPrimary = senderAddresses[0] || headers.from || "Unavailable";

  return (
    <div className="flex-1 flex flex-col min-w-0 h-full overflow-y-auto">
      <TopNav
        title={`Report: ${report.filename}`}
        description={`SHA-256: ${report.sha256.substring(0, 16)}...`}
        onRefresh={fetchReport}
        isRefreshing={loading}
      />

      <main className="p-6 max-w-7xl w-full mx-auto space-y-6">
        {/* Navigation Breadcrumb */}
        <div className="flex items-center gap-2 text-xs font-mono text-slate-400">
          <Link href="/history" className="hover:text-emerald-400 flex items-center gap-1 transition-colors">
            <ArrowLeftIcon className="w-3 h-3" />
            <span>Audit History</span>
          </Link>
          <span>/</span>
          <span className="text-slate-300 truncate max-w-md">{report.filename}</span>
        </div>

        {/* Section A: Executive Summary Banner */}
        <div className="rounded-xl border border-[#1e2230] bg-[#0f1117] p-6 space-y-6">
          <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-6 pb-6 border-b border-[#1e2230]">
            <div className="space-y-2">
              <div className="flex items-center gap-2.5 flex-wrap">
                <RiskBadge
                  category={risk_assessment?.category}
                  score={risk_assessment?.score}
                  size="lg"
                />
                <StatusBadge status={report.status} size="md" />
                <span className="text-xs font-mono text-slate-400">
                  ID: <span className="text-slate-300">{report.id}</span>
                </span>
              </div>
              <h1 className="text-lg font-bold text-white tracking-tight">
                {headers.subject || "(No Subject Header Provided)"}
              </h1>
              <p className="text-xs text-slate-400 font-mono">
                Ingested: {report.uploaded_at ? new Date(report.uploaded_at).toUTCString() : "Unknown"}
              </p>
            </div>

            {/* Score Metric Dial Box */}
            <div className="p-4 rounded-xl bg-[#0a0c10] border border-[#1e2230] flex items-center gap-5 shrink-0">
              <div className="text-right">
                <span className="text-[10px] font-mono uppercase tracking-wider text-slate-400 block">
                  Threat Risk Score
                </span>
                <span className="text-2xl font-bold font-mono text-white">
                  {risk_assessment?.score ?? "N/A"}{" "}
                  <span className="text-xs text-slate-400 font-normal">/ 100</span>
                </span>
                <span className="text-[11px] font-mono text-slate-400 block mt-0.5 capitalize">
                  {risk_assessment?.category ?? "Uncategorized"} Severity
                </span>
              </div>
              <div className="w-12 h-12 rounded-xl bg-slate-900 border border-slate-700 flex items-center justify-center">
                {risk_assessment?.category === "critical" || risk_assessment?.category === "high" ? (
                  <ShieldAlertIcon className="w-6 h-6 text-red-400" />
                ) : risk_assessment?.category === "moderate" ? (
                  <AlertTriangleIcon className="w-6 h-6 text-amber-400" />
                ) : (
                  <ShieldCheckIcon className="w-6 h-6 text-emerald-400" />
                )}
              </div>
            </div>
          </div>

          {/* Key Message Metadata Grid */}
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 text-xs font-mono">
            <div className="p-3 rounded-lg bg-[#090b0f] border border-[#1e2230]/70">
              <span className="text-[10px] text-slate-400 uppercase tracking-wider block">Sender (From)</span>
              <span className="text-white font-medium truncate block mt-0.5" title={senderPrimary}>
                {senderPrimary}
              </span>
            </div>

            <div className="p-3 rounded-lg bg-[#090b0f] border border-[#1e2230]/70">
              <span className="text-[10px] text-slate-400 uppercase tracking-wider block">Recipients (To)</span>
              <span className="text-white font-medium truncate block mt-0.5" title={(headers.to || headers.recipient || []).join(", ") || "None"}>
                {(headers.to || headers.recipient || []).join(", ") || "None"}
              </span>
            </div>

            <div className="p-3 rounded-lg bg-[#090b0f] border border-[#1e2230]/70">
              <span className="text-[10px] text-slate-400 uppercase tracking-wider block">Date Sent</span>
              <span className="text-white font-medium truncate block mt-0.5">
                {headers.date ? new Date(headers.date).toLocaleString() : "Missing"}
              </span>
            </div>

            <div className="p-3 rounded-lg bg-[#090b0f] border border-[#1e2230]/70">
              <span className="text-[10px] text-slate-400 uppercase tracking-wider block">SHA-256 File Hash</span>
              <div className="flex items-center justify-between mt-0.5">
                <span className="text-slate-300 font-mono text-[11px] truncate" title={report.sha256}>
                  {report.sha256.substring(0, 16)}...
                </span>
                <button
                  onClick={() => copyToClipboard(report.sha256)}
                  title="Copy SHA-256"
                  className="text-slate-400 hover:text-white ml-1"
                >
                  <CopyIcon className="w-3 h-3" />
                </button>
              </div>
            </div>
          </div>
        </div>

        {/* Section C: Authentication Analysis */}
        <div className="rounded-xl border border-[#1e2230] bg-[#0f1117] p-6 space-y-5">
          <div className="flex items-center justify-between border-b border-[#1e2230] pb-3">
            <div className="flex items-center gap-2.5">
              <ServerIcon className="w-4 h-4 text-emerald-400" />
              <h2 className="text-xs font-mono font-bold tracking-wider uppercase text-white">
                Email Authentication & Alignment (SPF / DKIM / DMARC)
              </h2>
            </div>
            <span className="text-[11px] font-mono text-slate-400">
              Sender Domain: <span className="text-emerald-400">{authentication?.domains?.sender_domain || "Unavailable"}</span>
            </span>
          </div>

          {/* Reported vs Independent Authentication Notice */}
          <div className="p-3 rounded-lg bg-[#090b0f] border border-[#1e2230] text-xs text-slate-400 flex items-start gap-2.5">
            <InfoIcon className="w-4 h-4 text-sky-400 shrink-0 mt-0.5" />
            <p className="text-[11px] leading-relaxed">
              <strong className="text-slate-200">Forensic Notice:</strong> Results extracted from message headers (<code className="text-sky-300">Authentication-Results</code>) represent observations from the receiving server and may be forged if the message was altered. Independent checks query published DNS records and cryptographic keys directly.
            </p>
          </div>

          {/* Authentication Cards Grid */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            {/* SPF Card */}
            <div className="p-4 rounded-xl bg-[#090b0f] border border-[#1e2230] space-y-3">
              <div className="flex items-center justify-between">
                <span className="font-mono text-xs font-bold text-white tracking-wider">SPF RECORD</span>
                <StatusBadge status={authentication?.spf?.status} size="sm" />
              </div>
              <p className="text-xs text-slate-300 leading-relaxed min-h-[36px]">
                {authentication?.spf?.details || "No details available."}
              </p>
              <div className="pt-2 border-t border-[#1e2230]/60 space-y-1 text-[11px] font-mono text-slate-400">
                <div>
                  Reported Header:{" "}
                  <span className="text-slate-200 font-semibold uppercase">
                    {authentication?.reported_results?.parsed?.spf?.result || "None"}
                  </span>
                </div>
                {authentication?.spf?.records && authentication.spf.records.length > 0 && (
                  <div className="truncate text-slate-400 text-[10px]" title={authentication.spf.records[0]}>
                    DNS: {authentication.spf.records[0]}
                  </div>
                )}
              </div>
            </div>

            {/* DKIM Card */}
            <div className="p-4 rounded-xl bg-[#090b0f] border border-[#1e2230] space-y-3">
              <div className="flex items-center justify-between">
                <span className="font-mono text-xs font-bold text-white tracking-wider">DKIM SIGNATURE</span>
                <StatusBadge status={authentication?.dkim?.status} size="sm" />
              </div>
              <p className="text-xs text-slate-300 leading-relaxed min-h-[36px]">
                {authentication?.dkim?.details || "No details available."}
              </p>
              <div className="pt-2 border-t border-[#1e2230]/60 space-y-1 text-[11px] font-mono text-slate-400">
                <div>
                  Reported Header:{" "}
                  <span className="text-slate-200 font-semibold uppercase">
                    {authentication?.reported_results?.parsed?.dkim?.result || "None"}
                  </span>
                </div>
                {authentication?.dkim?.signatures && authentication.dkim.signatures.length > 0 && (
                  <div className="text-[10px] text-slate-400 truncate">
                    Domain: <span className="text-slate-200">{authentication.dkim.signatures[0].domain}</span> (s={authentication.dkim.signatures[0].selector})
                  </div>
                )}
              </div>
            </div>

            {/* DMARC Card */}
            <div className="p-4 rounded-xl bg-[#090b0f] border border-[#1e2230] space-y-3">
              <div className="flex items-center justify-between">
                <span className="font-mono text-xs font-bold text-white tracking-wider">DMARC POLICY</span>
                <StatusBadge status={authentication?.dmarc_evaluation?.status || authentication?.dmarc?.status} size="sm" />
              </div>
              <p className="text-xs text-slate-300 leading-relaxed min-h-[36px]">
                {authentication?.dmarc_evaluation?.details || authentication?.dmarc?.details || "No details available."}
              </p>
              <div className="pt-2 border-t border-[#1e2230]/60 space-y-1 text-[11px] font-mono text-slate-400">
                <div>
                  Reported Header:{" "}
                  <span className="text-slate-200 font-semibold uppercase">
                    {authentication?.reported_results?.parsed?.dmarc?.result || "None"}
                  </span>
                </div>
                {authentication?.dmarc?.records && authentication.dmarc.records.length > 0 && (
                  <div className="truncate text-slate-400 text-[10px]" title={authentication.dmarc.records[0]}>
                    DNS: {authentication.dmarc.records[0]}
                  </div>
                )}
              </div>
            </div>
          </div>
        </div>

        {/* Section D: URL Intelligence */}
        <div className="rounded-xl border border-[#1e2230] bg-[#0f1117] p-6 space-y-5">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-[#1e2230] pb-3">
            <div className="flex items-center gap-2.5">
              <LinkIcon className="w-4 h-4 text-emerald-400" />
              <h2 className="text-xs font-mono font-bold tracking-wider uppercase text-white">
                URL Threat Intelligence & Lexical Analysis
              </h2>
            </div>
            <div className="flex items-center gap-2 font-mono text-xs">
              <span className="px-2 py-0.5 rounded bg-slate-800 text-slate-300">
                Total: {url_analysis?.total || 0}
              </span>
              <span className="px-2 py-0.5 rounded bg-amber-950/60 border border-amber-800 text-amber-300">
                Suspicious: {url_analysis?.suspicious_count || 0}
              </span>
              <span className="px-2 py-0.5 rounded bg-red-950/60 border border-red-800 text-red-300">
                Invalid: {url_analysis?.invalid_count || 0}
              </span>
            </div>
          </div>

          {(!url_analysis?.results || url_analysis.results.length === 0) ? (
            <div className="p-8 text-center text-xs font-mono text-slate-400">
              No HTTP, HTTPS, or web URLs detected in plain-text or HTML message bodies.
            </div>
          ) : (
            <div className="space-y-3">
              {url_analysis.results.map((item, idx) => {
                const hasFindings = item.findings && item.findings.length > 0;
                return (
                  <div
                    key={idx}
                    className={`p-4 rounded-xl border transition-all ${
                      item.status === "suspicious"
                        ? "bg-amber-950/10 border-amber-900/60"
                        : item.status === "invalid"
                        ? "bg-red-950/10 border-red-900/60"
                        : "bg-[#090b0f] border-[#1e2230]"
                    }`}
                  >
                    <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-3">
                      <div className="space-y-1 min-w-0 pr-4">
                        <div className="flex items-center gap-2 flex-wrap">
                          <StatusBadge status={item.status} size="sm" />
                          <span className="text-xs font-mono font-bold text-white truncate">
                            Host: {item.host || "(No Hostname)"}
                          </span>
                        </div>
                        <div className="flex items-center gap-2 font-mono text-[11px] text-slate-300 break-all">
                          <span className="bg-slate-900/80 px-2 py-0.5 rounded border border-[#1e2230]">
                            {item.url}
                          </span>
                          <button
                            onClick={() => copyToClipboard(item.url)}
                            className="p-1 rounded hover:bg-slate-800 text-slate-400 hover:text-white shrink-0"
                            title="Copy extracted URL"
                          >
                            <CopyIcon className="w-3.5 h-3.5" />
                          </button>
                          {copiedUrl === item.url && (
                            <span className="text-[10px] text-emerald-400 font-mono">Copied!</span>
                          )}
                        </div>
                      </div>
                    </div>

                    {/* Specific Findings List */}
                    {hasFindings && (
                      <div className="mt-3 pt-3 border-t border-[#1e2230]/70 space-y-1.5">
                        {item.findings.map((f, fIdx) => (
                          <div
                            key={fIdx}
                            className="flex items-start gap-2 text-xs font-mono text-slate-300"
                          >
                            <span
                              className={`px-1.5 py-0.2 rounded text-[10px] uppercase font-bold shrink-0 ${
                                f.severity === "critical" || f.severity === "high"
                                  ? "bg-red-950 text-red-300 border border-red-800"
                                  : f.severity === "medium"
                                  ? "bg-amber-950 text-amber-300 border border-amber-800"
                                  : "bg-slate-800 text-slate-300"
                              }`}
                            >
                              {f.type}
                            </span>
                            <span className="text-slate-300 text-[11px] leading-relaxed">
                              {f.description}
                            </span>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          )}
        </div>

        {/* Section E: Header Consistency & Spoofing Analysis */}
        <div className="rounded-xl border border-[#1e2230] bg-[#0f1117] p-6 space-y-5">
          <div className="flex items-center justify-between border-b border-[#1e2230] pb-3">
            <div className="flex items-center gap-2.5">
              <MailIcon className="w-4 h-4 text-emerald-400" />
              <h2 className="text-xs font-mono font-bold tracking-wider uppercase text-white">
                Header Consistency & Sender Provenance
              </h2>
            </div>
            <span
              className={`text-xs font-mono px-2 py-0.5 rounded ${
                header_analysis?.inconsistencies_detected
                  ? "bg-amber-950/60 border border-amber-800 text-amber-300"
                  : "bg-emerald-950/60 border border-emerald-800 text-emerald-300"
              }`}
            >
              {header_analysis?.inconsistencies_detected ? "Inconsistencies Detected" : "Clean Header Chain"}
            </span>
          </div>

          {/* Domain Relationship Matrix */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs font-mono">
            <div className="p-3 rounded-lg bg-[#090b0f] border border-[#1e2230]">
              <span className="text-[10px] text-slate-400 block uppercase">From Domain</span>
              <span className="text-white font-medium truncate block mt-0.5">
                {header_analysis?.domains?.from_domain || "Unavailable"}
              </span>
            </div>
            <div className="p-3 rounded-lg bg-[#090b0f] border border-[#1e2230]">
              <span className="text-[10px] text-slate-400 block uppercase">Reply-To Domain</span>
              <span className="text-white font-medium truncate block mt-0.5">
                {(header_analysis?.domains?.reply_to_domains || []).join(", ") || "Same as From"}
              </span>
            </div>
            <div className="p-3 rounded-lg bg-[#090b0f] border border-[#1e2230]">
              <span className="text-[10px] text-slate-400 block uppercase">Return-Path Domain</span>
              <span className="text-white font-medium truncate block mt-0.5">
                {header_analysis?.domains?.return_path_domain || "Unavailable"}
              </span>
            </div>
            <div className="p-3 rounded-lg bg-[#090b0f] border border-[#1e2230]">
              <span className="text-[10px] text-slate-400 block uppercase">DKIM Signing Domain</span>
              <span className="text-white font-medium truncate block mt-0.5">
                {(header_analysis?.domains?.dkim_domains || []).join(", ") || "None"}
              </span>
            </div>
          </div>

          {/* Findings List */}
          {header_analysis?.findings && header_analysis.findings.length > 0 ? (
            <div className="space-y-3">
              {header_analysis.findings.map((f, idx) => (
                <div
                  key={idx}
                  className={`p-4 rounded-xl border space-y-1.5 ${
                    f.severity === "high" || f.severity === "critical"
                      ? "bg-red-950/20 border-red-900/60"
                      : f.severity === "medium"
                      ? "bg-amber-950/20 border-amber-900/60"
                      : "bg-[#090b0f] border-[#1e2230]"
                  }`}
                >
                  <div className="flex items-center gap-2">
                    <StatusBadge status={f.severity} size="sm" label={`${f.severity}: ${f.type}`} />
                    <span className="text-xs font-semibold text-white font-sans">{f.evidence}</span>
                  </div>
                  <p className="text-xs text-slate-300 font-sans leading-relaxed pl-1">
                    {f.explanation}
                  </p>
                </div>
              ))}
            </div>
          ) : (
            <div className="p-4 rounded-lg bg-[#090b0f] border border-[#1e2230] text-center text-xs font-mono text-emerald-400">
              No deceptive display names, domain discrepancies, or anomalous relay hops detected.
            </div>
          )}

          {/* Forensic Received Relay Hop Chain (Collapsible) */}
          <div className="pt-2">
            <button
              onClick={() => setReceivedExpanded(!receivedExpanded)}
              className="flex items-center justify-between w-full p-3 rounded-lg bg-[#090b0f] border border-[#1e2230] hover:bg-slate-900 text-xs font-mono text-slate-300 transition-colors"
            >
              <div className="flex items-center gap-2">
                <ServerIcon className="w-4 h-4 text-slate-400" />
                <span>
                  Inspect Received Headers Chain ({headers.received?.length || 0} hops)
                </span>
              </div>
              {receivedExpanded ? <ChevronUpIcon className="w-4 h-4" /> : <ChevronDownIcon className="w-4 h-4" />}
            </button>

            {receivedExpanded && (
              <div className="mt-2 p-4 rounded-lg bg-black border border-[#1e2230] font-mono text-xs text-slate-300 space-y-3 max-h-80 overflow-y-auto">
                {headers.received && headers.received.length > 0 ? (
                  headers.received.map((hop, hIdx) => (
                    <div key={hIdx} className="p-2.5 rounded bg-slate-950/80 border border-slate-800/80">
                      <span className="text-emerald-400 text-[10px] uppercase font-bold block mb-1">
                        Hop #{headers.received.length - hIdx}
                      </span>
                      <pre className="whitespace-pre-wrap break-all text-[11px] leading-relaxed text-slate-300">
                        {hop}
                      </pre>
                    </div>
                  ))
                ) : (
                  <p className="text-slate-400 italic">No Received headers found in message.</p>
                )}
              </div>
            )}
          </div>
        </div>

        {/* Section F: Risk Assessment Explanations & Limitations */}
        <div className="rounded-xl border border-[#1e2230] bg-[#0f1117] p-6 space-y-5">
          <div className="flex items-center justify-between border-b border-[#1e2230] pb-3">
            <div className="flex items-center gap-2.5">
              <ShieldAlertIcon className="w-4 h-4 text-emerald-400" />
              <h2 className="text-xs font-mono font-bold tracking-wider uppercase text-white">
                Preliminary Threat-Risk Assessment Methodology
              </h2>
            </div>
            <RiskBadge
              category={risk_assessment?.category}
              score={risk_assessment?.score}
              size="sm"
            />
          </div>

          {/* Contributing Findings */}
          <div className="space-y-3">
            <h3 className="text-xs font-mono font-semibold text-slate-300 uppercase tracking-wider">
              Scoring Factors ({risk_assessment?.findings?.length || 0})
            </h3>
            {risk_assessment?.findings && risk_assessment.findings.length > 0 ? (
              <div className="divide-y divide-[#1e2230] rounded-xl border border-[#1e2230] bg-[#090b0f] overflow-hidden">
                {risk_assessment.findings.map((f, idx) => (
                  <div key={idx} className="p-3.5 flex items-start justify-between gap-4 text-xs font-mono">
                    <div className="space-y-1">
                      <div className="flex items-center gap-2">
                        <span className="text-emerald-400 uppercase text-[10px] font-bold px-1.5 py-0.2 rounded bg-slate-800">
                          {f.source}
                        </span>
                        <span className="font-semibold text-white">{f.type}</span>
                      </div>
                      <p className="text-slate-300 font-sans text-xs">{f.description}</p>
                    </div>
                    <span className="px-2 py-1 rounded bg-red-950/60 border border-red-800 text-red-300 font-bold shrink-0">
                      +{f.points} pts
                    </span>
                  </div>
                ))}
              </div>
            ) : (
              <div className="p-4 rounded-lg bg-[#090b0f] border border-[#1e2230] text-center text-xs font-mono text-emerald-400">
                No adversarial threat indicators contributed to the preliminary risk score.
              </div>
            )}
          </div>

          {/* Limitations Notice */}
          <div className="p-4 rounded-xl bg-slate-900/50 border border-slate-800/80 space-y-2 text-xs">
            <span className="font-mono text-[10px] font-bold text-slate-400 uppercase tracking-wider block">
              Forensic Operational Limitations
            </span>
            <ul className="list-disc list-inside space-y-1 text-slate-400 text-[11px] leading-relaxed font-sans">
              {(risk_assessment?.limitations || [
                "Preliminary heuristic assessment; does not guarantee safety or maliciousness.",
                "Attachments inspected for MIME metadata and file extensions only; active dynamic sandbox execution was not performed.",
                "URLs evaluated statically without active network connections or external reputation lookups.",
              ]).map((lim, lIdx) => (
                <li key={lIdx}>{lim}</li>
              ))}
            </ul>
          </div>
        </div>

        {/* Section G & H: Email Content & Attachments */}
        <div className="rounded-xl border border-[#1e2230] bg-[#0f1117] p-6 space-y-5">
          <div className="flex items-center justify-between border-b border-[#1e2230] pb-3">
            <div className="flex items-center gap-2">
              <button
                onClick={() => setActiveTab("text")}
                className={`px-3 py-1.5 rounded-lg text-xs font-mono font-medium transition-colors ${
                  activeTab === "text"
                    ? "bg-slate-800 text-white border border-slate-700"
                    : "text-slate-400 hover:text-white"
                }`}
              >
                Plain Text Body
              </button>
              <button
                onClick={() => setActiveTab("html")}
                className={`px-3 py-1.5 rounded-lg text-xs font-mono font-medium transition-colors ${
                  activeTab === "html"
                    ? "bg-slate-800 text-white border border-slate-700"
                    : "text-slate-400 hover:text-white"
                }`}
              >
                Sandboxed HTML Preview
              </button>
              <button
                onClick={() => setActiveTab("headers")}
                className={`px-3 py-1.5 rounded-lg text-xs font-mono font-medium transition-colors ${
                  activeTab === "headers"
                    ? "bg-slate-800 text-white border border-slate-700"
                    : "text-slate-400 hover:text-white"
                }`}
              >
                All Raw Headers
              </button>
            </div>

            <div className="flex items-center gap-2 font-mono text-xs text-slate-400">
              <PaperclipIcon className="w-3.5 h-3.5 text-emerald-400" />
              <span>Attachments ({email?.attachments?.length || 0})</span>
            </div>
          </div>

          {/* Active Tab Preview */}
          <div className="rounded-xl border border-[#1e2230] bg-black p-4 min-h-[240px] max-h-[500px] overflow-auto">
            {activeTab === "text" ? (
              <pre className="font-mono text-xs text-slate-300 whitespace-pre-wrap leading-relaxed select-text">
                {email?.body?.body_text || "(No plain-text body component found in message payload.)"}
              </pre>
            ) : activeTab === "html" ? (
              email?.body?.body_html ? (
                <div className="space-y-2">
                  <div className="p-2 rounded bg-amber-950/40 border border-amber-900/60 text-[11px] font-mono text-amber-300">
                    Sandboxed Preview Mode: JavaScript, forms, hyperlinks, and external navigation are strictly disabled.
                  </div>
                  <iframe
                    title="Sandboxed Email HTML Preview"
                    sandbox=""
                    srcDoc={email.body.body_html}
                    className="w-full h-96 rounded border border-slate-800 bg-white"
                  />
                </div>
              ) : (
                <p className="text-xs font-mono text-slate-400 italic">No HTML component found in message payload.</p>
              )
            ) : (
              <div className="space-y-2 font-mono text-xs">
                {Object.entries(headers).map(([key, val]) => (
                  <div key={key} className="border-b border-slate-900 pb-1">
                    <span className="text-emerald-400 font-bold uppercase">{key}: </span>
                    <span className="text-slate-300">{Array.isArray(val) ? val.join(", ") : String(val ?? "")}</span>
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* Attachments Metadata Table */}
          {email?.attachments && email.attachments.length > 0 && (
            <div className="pt-4 border-t border-[#1e2230] space-y-3">
              <h3 className="text-xs font-mono font-semibold text-slate-300 uppercase tracking-wider">
                Attachment Manifest (Passive Inspection)
              </h3>
              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs font-mono border-collapse">
                  <thead>
                    <tr className="border-b border-[#1e2230] text-slate-400 uppercase text-[10px]">
                      <th className="py-2 px-3">Filename</th>
                      <th className="py-2 px-3">MIME Type</th>
                      <th className="py-2 px-3 text-right">Size</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-[#1e2230]">
                    {email.attachments.map((att, aIdx) => (
                      <tr key={aIdx} className="hover:bg-slate-900/40">
                        <td className="py-2.5 px-3 font-semibold text-white flex items-center gap-2">
                          <FileTextIcon className="w-3.5 h-3.5 text-slate-400" />
                          <span>{att.filename}</span>
                        </td>
                        <td className="py-2.5 px-3 text-slate-400">{att.content_type}</td>
                        <td className="py-2.5 px-3 text-right text-slate-300">{formatBytes(att.size)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </div>
      </main>
    </div>
  );
}
