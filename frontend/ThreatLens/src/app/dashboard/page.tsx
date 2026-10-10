import { Suspense } from "react";
import { DashboardPageHeader, DashboardSidebar, MobileDashboardNav, NewScanButton } from "@/components/dashboard/dashboard-components";
import { LiveDashboard } from "@/components/live-dashboard";

export const metadata = {
  title: "Dashboard — ThreatLens",
  description: "ThreatLens persisted security assessment dashboard.",
};

export default function DashboardPage() {
  return <div className="min-h-screen bg-[#090b12] text-slate-200"><div className="flex min-h-screen"><DashboardSidebar /><div className="min-w-0 flex-1"><MobileDashboardNav demo={false} /><main className="mx-auto max-w-[1440px] px-5 py-8 sm:px-8 lg:px-10 lg:py-10"><DashboardPageHeader demo={false} eyebrow="Security overview" title="Your persisted assessments." description="A focused view of the latest scan results and the next useful action." action={<NewScanButton />} /><div className="mt-8"><Suspense fallback={<div className="rounded-2xl border border-dashed border-[#303953] p-8 text-sm text-slate-400">Loading dashboard…</div>}><LiveDashboard /></Suspense></div></main></div></div></div>;
}
