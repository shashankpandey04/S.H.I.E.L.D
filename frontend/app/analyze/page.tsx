"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { TopNav } from "../../components/TopNav";
import {
  AlertOctagonIcon,
  CheckCircleIcon,
  FileTextIcon,
  ShieldIcon,
  UploadIcon,
} from "../../components/Icons";
import { uploadEmailFile } from "../../lib/api";

const MAX_FILE_SIZE_MB = 25;
const MAX_FILE_SIZE_BYTES = MAX_FILE_SIZE_MB * 1024 * 1024;

export default function AnalyzeEmailPage() {
  const router = useRouter();
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [dragActive, setDragActive] = useState<boolean>(false);
  const [isAnalyzing, setIsAnalyzing] = useState<boolean>(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [stepStatus, setStepStatus] = useState<string>("");

  function validateAndSelectFile(file: File) {
    setErrorMessage(null);

    if (!file.name.toLowerCase().endsWith(".eml")) {
      setErrorMessage("Unsupported file extension. Only standard RFC 822 (.eml) files are permitted.");
      setSelectedFile(null);
      return;
    }

    if (file.size === 0) {
      setErrorMessage("The selected file is empty (0 bytes).");
      setSelectedFile(null);
      return;
    }

    if (file.size > MAX_FILE_SIZE_BYTES) {
      setErrorMessage(`File exceeds the configured ${MAX_FILE_SIZE_MB} MB size limit.`);
      setSelectedFile(null);
      return;
    }

    setSelectedFile(file);
  }

  async function handleAnalyze() {
    if (!selectedFile) {
      setErrorMessage("Please select a valid .eml file first.");
      return;
    }

    try {
      setIsAnalyzing(true);
      setErrorMessage(null);
      setStepStatus("Ingesting email payload & calculating SHA-256...");

      const record = await uploadEmailFile(selectedFile);
      setStepStatus("Analysis complete! Redirecting to forensic report...");
      router.push(`/reports/${encodeURIComponent(record.id)}`);
    } catch (err: unknown) {
      setIsAnalyzing(false);
      setStepStatus("");
      if (err instanceof Error) {
        setErrorMessage(err.message);
      } else {
        setErrorMessage("Email analysis request failed. Verify backend connectivity.");
      }
    }
  }

  function formatBytes(bytes: number): string {
    if (bytes === 0) return "0 Bytes";
    const k = 1024;
    const sizes = ["Bytes", "KB", "MB"];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + " " + sizes[i];
  }

  return (
    <div className="flex-1 flex flex-col min-w-0 h-full overflow-y-auto">
      <TopNav
        title="Analyze Email"
        description="Submit raw RFC 822 (.eml) messages for forensic threat inspection"
      />

      <main className="p-6 max-w-4xl w-full mx-auto space-y-6">
        {/* Upload Card */}
        <div className="rounded-xl border border-[#1e2230] bg-[#0f1117] overflow-hidden">
          <div className="p-5 border-b border-[#1e2230] flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div className="w-8 h-8 rounded-lg bg-emerald-950/60 border border-emerald-700/50 flex items-center justify-center text-emerald-400">
                <ShieldIcon className="w-4 h-4" />
              </div>
              <div>
                <h2 className="text-sm font-semibold text-white font-mono uppercase tracking-wider">
                  Email Ingestion Pipeline
                </h2>
                <p className="text-xs text-slate-400">
                  Headers, body URLs, SPF/DKIM/DMARC, and attachments will be parsed safely
                </p>
              </div>
            </div>
            <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-slate-800 border border-slate-700 text-slate-300">
              Max {MAX_FILE_SIZE_MB} MB
            </span>
          </div>

          <div className="p-6 space-y-6">
            {/* Drag and Drop Zone */}
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
                  validateAndSelectFile(e.dataTransfer.files[0]);
                }
              }}
              className={`p-10 rounded-xl border-2 border-dashed transition-all text-center flex flex-col items-center justify-center space-y-4 ${
                dragActive
                  ? "border-emerald-500 bg-emerald-950/20"
                  : selectedFile
                  ? "border-emerald-700/70 bg-[#0d1314]"
                  : "border-[#1e2230] bg-[#0c0e14] hover:border-slate-600 hover:bg-[#0e1118]"
              }`}
            >
              <input
                type="file"
                accept=".eml"
                id="eml-file-picker"
                className="hidden"
                disabled={isAnalyzing}
                onChange={(e) => {
                  if (e.target.files && e.target.files[0]) {
                    validateAndSelectFile(e.target.files[0]);
                  }
                }}
              />

              <div className="w-14 h-14 rounded-2xl bg-slate-900 border border-slate-700/80 flex items-center justify-center text-slate-300">
                {selectedFile ? (
                  <CheckCircleIcon className="w-7 h-7 text-emerald-400" />
                ) : (
                  <UploadIcon className="w-7 h-7 text-emerald-400" />
                )}
              </div>

              <div className="space-y-1">
                <p className="text-sm font-semibold text-white">
                  {selectedFile ? selectedFile.name : "Choose an .eml file or drag & drop"}
                </p>
                <p className="text-xs text-slate-400">
                  {selectedFile
                    ? `Payload Size: ${formatBytes(selectedFile.size)}`
                    : "Standard MIME / RFC 822 email exported from Outlook, Gmail, Thunderbird, etc."}
                </p>
              </div>

              {!selectedFile && (
                <label
                  htmlFor="eml-file-picker"
                  className="cursor-pointer inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-white text-xs font-mono font-medium border border-slate-700 transition-colors"
                >
                  <FileTextIcon className="w-4 h-4 text-emerald-400" />
                  <span>Browse Local File</span>
                </label>
              )}
            </div>

            {/* Error Message */}
            {errorMessage && (
              <div className="p-3.5 rounded-lg bg-red-950/40 border border-red-800/80 flex items-start gap-3 text-red-200 text-xs">
                <AlertOctagonIcon className="w-4 h-4 text-red-400 shrink-0 mt-0.5" />
                <div>
                  <p className="font-semibold text-red-300">Validation or Processing Failure</p>
                  <p className="mt-0.5 text-red-300/80">{errorMessage}</p>
                </div>
              </div>
            )}

            {/* Selected File Details & Action */}
            {selectedFile && (
              <div className="p-4 rounded-lg bg-[#0a0c10] border border-[#1e2230] flex flex-col sm:flex-row items-center justify-between gap-4">
                <div className="flex items-center gap-3">
                  <div className="w-9 h-9 rounded bg-emerald-950/60 border border-emerald-800 flex items-center justify-center text-emerald-400">
                    <FileTextIcon className="w-5 h-5" />
                  </div>
                  <div>
                    <p className="text-xs font-semibold text-white font-mono truncate max-w-sm">
                      {selectedFile.name}
                    </p>
                    <p className="text-[11px] text-slate-400 font-mono">
                      {formatBytes(selectedFile.size)} • Ready for analysis
                    </p>
                  </div>
                </div>

                <div className="flex items-center gap-2">
                  <button
                    onClick={() => {
                      setSelectedFile(null);
                      setErrorMessage(null);
                    }}
                    disabled={isAnalyzing}
                    className="px-3 py-1.5 rounded-lg border border-slate-700 text-xs text-slate-400 hover:text-white hover:bg-slate-800 transition-colors disabled:opacity-50"
                  >
                    Change File
                  </button>

                  <button
                    onClick={handleAnalyze}
                    disabled={isAnalyzing}
                    className="inline-flex items-center gap-2 px-5 py-2 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-semibold tracking-wide transition-all shadow-md shadow-emerald-950/50 disabled:opacity-50 disabled:pointer-events-none"
                  >
                    {isAnalyzing ? (
                      <>
                        <div className="w-3.5 h-3.5 border-2 border-white border-t-transparent rounded-full animate-spin" />
                        <span>Analyzing...</span>
                      </>
                    ) : (
                      <>
                        <ShieldIcon className="w-4 h-4" />
                        <span>Analyze Email</span>
                      </>
                    )}
                  </button>
                </div>
              </div>
            )}

            {/* Analysis Progress Indicator */}
            {isAnalyzing && (
              <div className="p-4 rounded-lg bg-slate-900/80 border border-slate-700/80 space-y-2">
                <div className="flex items-center justify-between text-xs font-mono">
                  <span className="text-emerald-400 flex items-center gap-2">
                    <span className="w-2 h-2 rounded-full bg-emerald-400 animate-ping" />
                    {stepStatus || "Running forensic checks..."}
                  </span>
                  <span className="text-slate-400">Processing Pipeline</span>
                </div>
                <div className="w-full h-1.5 bg-slate-800 rounded-full overflow-hidden">
                  <div className="h-full bg-emerald-500 rounded-full animate-pulse w-3/4" />
                </div>
              </div>
            )}
          </div>
        </div>

        {/* Forensic Safeguards Callout */}
        <div className="p-4 rounded-xl border border-[#1e2230] bg-[#0c0e14] text-xs text-slate-400 space-y-2">
          <p className="font-semibold text-slate-300 font-mono uppercase tracking-wider text-[11px]">
            Security & Integrity Protocols
          </p>
          <ul className="grid grid-cols-1 md:grid-cols-2 gap-2 text-[11px] leading-relaxed list-disc list-inside">
            <li>Original RFC 822 payloads preserved encrypted in Supabase object storage.</li>
            <li>Embedded URLs are evaluated syntactically; no HTTP requests or redirects are triggered.</li>
            <li>Attachments are audited for extension and MIME metadata; no scripts are executed.</li>
            <li>SPF, DKIM, and DMARC evaluate both reported reception logs and cryptographic public keys.</li>
          </ul>
        </div>
      </main>
    </div>
  );
}
