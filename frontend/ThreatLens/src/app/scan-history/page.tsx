import { DashboardPageHeader, DashboardSidebar, MobileDashboardNav, NewScanButton } from "@/components/dashboard/dashboard-components";
import { LiveHistoryView } from "@/components/live-history-view";

export const metadata = {
  title: "Scan History — ThreatLens",
  description: "Review previous persisted security scans in ThreatLens.",
};

export default function ScanHistoryPage() {
  return <div className="min-h-screen bg-[#090b12] text-slate-200"><div className="flex min-h-screen"><DashboardSidebar activeSection="history" /><div className="min-w-0 flex-1"><MobileDashboardNav demo={false} activeSection="history" /><main className="mx-auto max-w-[1440px] px-5 py-8 sm:px-8 lg:px-10 lg:py-10"><DashboardPageHeader demo={false} eyebrow="Scan history" title="Review past assessments." description="Track previous persisted assessments and open related findings when a scan is complete." action={<NewScanButton />} /><div className="mt-8"><LiveHistoryView /></div></main></div></div></div>;
}
