import { Suspense } from "react";
import { DashboardPageHeader, DashboardSidebar, MobileDashboardNav, NewScanButton } from "@/components/dashboard/dashboard-components";
import { LiveFindingsView } from "@/components/live-findings-view";

export const metadata = {
  title: "Findings — ThreatLens",
  description: "Review persisted ThreatLens security findings and remediation guidance.",
};

export default function FindingsPage() {
  return <div className="min-h-screen bg-[#090b12] text-slate-200"><div className="flex min-h-screen"><DashboardSidebar activeSection="findings" /><div className="min-w-0 flex-1"><MobileDashboardNav demo={false} activeSection="findings" /><main className="mx-auto max-w-[1440px] px-5 py-8 sm:px-8 lg:px-10 lg:py-10"><DashboardPageHeader demo={false} eyebrow="Security findings" title="Understand what needs attention." description="Review persisted evidence, understand the likely cause, and move from finding to focused next step." action={<NewScanButton />} /><div className="mt-8"><Suspense fallback={<div className="rounded-2xl border border-dashed border-[#303953] p-8 text-sm text-slate-400">Loading assessment results…</div>}><LiveFindingsView /></Suspense></div></main></div></div></div>;
}
