import type { Metadata } from "next";
import { Sidebar } from "../components/Sidebar";
import "./globals.css";

export const metadata: Metadata = {
  title: "S.H.I.E.L.D. — Forensic Email Threat Intelligence",
  description: "Security & Header Inspection for Email, Logging & Diagnostics",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" className="dark h-full antialiased">
      <body className="min-h-full h-full flex bg-[#08090c] text-slate-100 font-sans selection:bg-emerald-500/20 selection:text-emerald-300">
        <Sidebar />
        <div className="flex-1 flex flex-col min-w-0 h-full overflow-hidden">
          {children}
        </div>
      </body>
    </html>
  );
}
