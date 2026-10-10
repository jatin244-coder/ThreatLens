import { BrandMark } from "@/components/brand-mark";
import { FeatureCard } from "@/components/feature-card";
import { SectionHeading } from "@/components/section-heading";
import { SecurityScore } from "@/components/security-score";
import { ScanForm } from "@/components/scan-form";

const steps = [
  ["01", "Scan", "We look across the public surface of your website for meaningful security signals."],
  ["02", "Understand", "Translate technical findings into plain-language context and priority."],
  ["03", "Fix", "Get focused guidance that helps your team move from alert to action."],
  ["04", "Recheck", "Run the assessment again to see what changed and keep improving."],
];

const features = [
  { number: "01", title: "Security Checks", description: "A focused set of checks for the security basics that matter to a growing business.", icon: <ShieldIcon /> },
  { number: "02", title: "Security Score", description: "A simple signal that helps you understand your current security posture at a glance.", icon: <GaugeIcon /> },
  { number: "03", title: "Root Cause Analyzer", description: "See why an issue matters and where it originates, not just that it exists.", icon: <SearchIcon /> },
  { number: "04", title: "Remediation Guidance", description: "Clear next steps written for people who need to make progress, not decode jargon.", icon: <WrenchIcon /> },
  { number: "05", title: "Scan History", description: "Keep a lightweight record of assessments so improvements are easy to track over time.", icon: <HistoryIcon /> },
  { number: "06", title: "PDF Reports", description: "Share a concise, readable snapshot with teammates, owners, or your security partner.", icon: <DocumentIcon /> },
];

export default function Home() {
  return (
    <main className="overflow-hidden">
      <nav className="mx-auto flex max-w-7xl items-center justify-between px-5 py-5 sm:px-8 lg:px-10" aria-label="Main navigation">
        <a href="#top" className="rounded-lg focus-visible:outline-2 focus-visible:outline-offset-4 focus-visible:outline-violet-300"><BrandMark /></a>
        <div className="hidden items-center gap-7 text-sm text-slate-400 lg:flex">
          <a className="transition-colors hover:text-white" href="#product">Product</a>
          <a className="transition-colors hover:text-white" href="#how-it-works">How It Works</a>
          <a className="transition-colors hover:text-white" href="#checks">Security Checks</a>
          <a className="transition-colors hover:text-white" href="#sample-report">Sample Report</a>
        </div>
        <a href="#scan" className="hidden rounded-lg bg-violet-500 px-4 py-2.5 text-sm font-medium text-white shadow-[0_8px_24px_rgba(139,92,246,0.18)] transition-colors hover:bg-violet-400 focus-visible:outline-2 focus-visible:outline-offset-4 focus-visible:outline-violet-300 sm:inline-flex">Scan a Website</a>
        <details className="relative sm:hidden">
          <summary className="flex size-10 cursor-pointer list-none items-center justify-center rounded-lg border border-[#252C40] text-slate-300 focus-visible:outline-2 focus-visible:outline-offset-4 focus-visible:outline-violet-300 [&::-webkit-details-marker]:hidden" aria-label="Open navigation menu"><MenuIcon /></summary>
          <div className="absolute right-0 top-12 z-20 w-56 rounded-xl border border-[#252C40] bg-[#111522] p-2 shadow-2xl">
            <a className="block rounded-lg px-3 py-2.5 text-sm text-slate-300 hover:bg-[#171827] hover:text-white" href="#product">Product</a>
            <a className="block rounded-lg px-3 py-2.5 text-sm text-slate-300 hover:bg-[#171827] hover:text-white" href="#how-it-works">How It Works</a>
            <a className="block rounded-lg px-3 py-2.5 text-sm text-slate-300 hover:bg-[#171827] hover:text-white" href="#checks">Security Checks</a>
            <a className="block rounded-lg px-3 py-2.5 text-sm text-slate-300 hover:bg-[#171827] hover:text-white" href="#sample-report">Sample Report</a>
            <a className="mt-1 block rounded-lg bg-violet-500 px-3 py-2.5 text-sm font-medium text-white" href="#scan">Scan a Website</a>
          </div>
        </details>
      </nav>

      <section id="top" className="relative mx-auto grid max-w-7xl gap-14 px-5 pb-24 pt-16 sm:px-8 sm:pt-24 lg:grid-cols-[1.05fr_0.95fr] lg:items-center lg:px-10 lg:pb-32 lg:pt-28">
        <div className="pointer-events-none absolute -left-48 top-0 size-[28rem] rounded-full bg-violet-500/[0.06] blur-3xl" aria-hidden="true" />
        <div className="relative">
          <div className="mb-7 inline-flex items-center gap-2 rounded-full border border-teal-300/20 bg-teal-300/[0.06] px-3 py-1.5 text-xs font-medium text-teal-200"><span className="size-1.5 rounded-full bg-teal-300" />Security clarity for growing businesses</div>
          <h1 className="max-w-3xl text-5xl font-semibold leading-[1.04] tracking-[-0.065em] text-white sm:text-6xl lg:text-[4.5rem]">See the risk. <span className="text-slate-500">Understand the cause.</span> Fix with confidence.</h1>
          <p className="mt-7 max-w-xl text-lg leading-8 text-slate-400">ThreatLens turns a website security assessment into a clear, prioritized plan your team can actually use.</p>
          <ScanForm />
        </div>
        <DemoPreview />
      </section>

      <section id="product" className="border-y border-[#252C40]/80 bg-[#0c0f19] px-5 py-24 sm:px-8 lg:px-10 lg:py-28">
        <div className="mx-auto max-w-7xl">
          <SectionHeading eyebrow="A clearer security workflow" title="Less noise. Better decisions." description="ThreatLens gives non-specialist teams the context they need to prioritize their next best action." />
          <div id="how-it-works" className="mt-14 grid border-y border-[#252C40] md:grid-cols-4">
            {steps.map(([number, title, description], index) => <div key={title} className={`relative py-7 md:px-6 md:py-9 ${index < steps.length - 1 ? "border-b border-[#252C40] md:border-b-0 md:border-r" : ""}`}><span className="font-mono text-xs text-violet-300">{number}</span><h3 className="mt-6 text-xl font-medium text-white">{title}</h3><p className="mt-3 max-w-xs text-sm leading-6 text-slate-400">{description}</p>{index < steps.length - 1 ? <span className="absolute -right-2 top-1/2 hidden size-4 -translate-y-1/2 rotate-45 border-r border-t border-[#252C40] bg-[#0c0f19] md:block" aria-hidden="true" /> : null}</div>)}
          </div>
        </div>
      </section>

      <section id="checks" className="mx-auto max-w-7xl px-5 py-24 sm:px-8 lg:px-10 lg:py-32">
        <SectionHeading eyebrow="Built for action" title="The essentials, made understandable." description="A focused toolkit for seeing what needs attention, why it matters, and what to do next." />
        <div className="mt-12 grid gap-4 sm:grid-cols-2 lg:grid-cols-3">{features.map((feature) => <FeatureCard key={feature.title} {...feature} />)}</div>
      </section>

      <section id="sample-report" className="bg-[#0c0f19] px-5 py-24 sm:px-8 lg:px-10 lg:py-28">
        <div className="mx-auto grid max-w-7xl gap-12 lg:grid-cols-[0.8fr_1.2fr] lg:items-center"><SectionHeading eyebrow="Sample report" title="A report people will actually read." description="Share the signal without sending someone down a security rabbit hole. This illustrative report keeps the story focused." /><ReportPreview /></div>
      </section>

      <section id="responsible-use" className="mx-auto max-w-7xl px-5 py-24 sm:px-8 lg:px-10 lg:py-28">
        <div className="rounded-3xl border border-[#252C40] bg-[#111522] p-7 sm:p-10 lg:flex lg:items-center lg:justify-between lg:gap-14 lg:p-14"><div className="max-w-2xl"><p className="mb-4 text-xs font-semibold uppercase tracking-[0.2em] text-amber-300">Responsible by design</p><h2 className="text-3xl font-semibold tracking-[-0.04em] text-white sm:text-4xl">Only assess websites you own or have permission to test.</h2><p className="mt-5 text-base leading-7 text-slate-400">ThreatLens is made to help teams understand and improve their own web presence. Authorization and responsible use are part of every assessment.</p></div><div className="mt-9 flex shrink-0 items-center gap-3 text-sm text-slate-300 lg:mt-0"><span className="grid size-10 place-items-center rounded-full bg-amber-300/10 text-amber-300"><LockIcon /></span> Permission first. Always.</div></div>
      </section>

      <footer className="border-t border-[#252C40] px-5 py-10 sm:px-8 lg:px-10"><div className="mx-auto flex max-w-7xl flex-col gap-8 sm:flex-row sm:items-center sm:justify-between"><div><BrandMark /><p className="mt-3 text-sm text-slate-500">Security clarity for growing businesses.</p></div><div className="flex flex-wrap gap-x-6 gap-y-3 text-sm text-slate-500"><a className="hover:text-white" href="#product">Product</a><a className="hover:text-white" href="#responsible-use">Responsible use</a><a className="hover:text-white" href="#sample-report">Sample report</a></div><p className="text-xs text-slate-600">© 2026 ThreatLens</p></div></footer>
    </main>
  );
}

function DemoPreview() {
  return <div className="relative mx-auto w-full max-w-[31rem] lg:ml-auto"><div className="absolute -inset-4 rounded-[2rem] border border-violet-300/[0.08]" aria-hidden="true" /><div className="relative rounded-2xl border border-[#252C40] bg-[#111522] p-4 shadow-2xl shadow-black/20 sm:p-5"><div className="flex items-center justify-between border-b border-[#252C40] pb-4"><div><p className="text-xs font-medium text-slate-300">acme-workshop.com</p><p className="mt-1 text-[11px] text-slate-600">Illustrative assessment</p></div><span className="rounded-full border border-violet-300/20 bg-violet-300/10 px-2.5 py-1 text-[10px] font-medium text-violet-200">DEMO</span></div><div className="flex flex-col items-center gap-7 py-8 sm:flex-row sm:items-center sm:px-4"><SecurityScore /><div className="w-full"><p className="text-xs font-medium uppercase tracking-[0.15em] text-slate-500">Security posture</p><p className="mt-2 text-xl font-medium text-white">Good foundation</p><p className="mt-2 text-sm leading-6 text-slate-400">A few focused improvements can make a meaningful difference.</p></div></div><div className="space-y-2 border-t border-[#252C40] pt-4"><Finding color="bg-amber-400" label="Missing security header" severity="Medium" /><Finding color="bg-red-400" label="Outdated dependency detected" severity="High" /><Finding color="bg-teal-300" label="HTTPS configured correctly" severity="Passed" /></div></div></div>;
}

function Finding({ color, label, severity }: { color: string; label: string; severity: string }) { return <div className="flex items-center justify-between gap-3 rounded-lg bg-[#171827] px-3 py-2.5"><span className="flex min-w-0 items-center gap-2 text-xs text-slate-300"><span className={`size-1.5 shrink-0 rounded-full ${color}`} /><span className="truncate">{label}</span></span><span className="shrink-0 text-[10px] text-slate-500">{severity}</span></div>; }

function ReportPreview() {
  return <div className="rounded-2xl border border-[#252C40] bg-[#111522] p-5 shadow-2xl shadow-black/10 sm:p-7"><div className="flex items-center justify-between border-b border-[#252C40] pb-5"><div><p className="text-sm font-medium text-white">Website security report</p><p className="mt-1 text-xs text-slate-500">acme-workshop.com · Illustrative only</p></div><DocumentIcon /></div><div className="grid gap-5 py-6 sm:grid-cols-[0.7fr_1.3fr]"><div className="rounded-xl bg-[#171827] p-5"><p className="text-xs text-slate-500">Overall score</p><p className="mt-3 text-4xl font-semibold tracking-[-0.06em] text-teal-300">78<span className="text-lg text-slate-600">/100</span></p><div className="mt-4 h-1.5 overflow-hidden rounded-full bg-[#252C40]"><div className="h-full w-[78%] rounded-full bg-teal-300" /></div></div><div><p className="text-xs font-medium uppercase tracking-[0.15em] text-slate-500">Priority overview</p><div className="mt-4 grid grid-cols-3 gap-2 text-center"><Metric label="High" value="1" color="text-red-300" /><Metric label="Medium" value="2" color="text-amber-300" /><Metric label="Passed" value="14" color="text-teal-300" /></div><p className="mt-5 text-sm leading-6 text-slate-400">Illustrative report content helps your team understand what to address first.</p></div></div><div className="flex items-center justify-between border-t border-[#252C40] pt-4 text-xs text-slate-500"><span>Example finding</span><span className="text-violet-300">View guidance →</span></div></div>;
}

function Metric({ label, value, color }: { label: string; value: string; color: string }) { return <div className="rounded-lg border border-[#252C40] p-3"><p className={`text-xl font-semibold ${color}`}>{value}</p><p className="mt-1 text-[10px] text-slate-500">{label}</p></div>; }

function MenuIcon() { return <svg aria-hidden="true" className="size-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.7"><path d="M4 7h16M4 12h16M4 17h16" strokeLinecap="round" /></svg>; }
function LockIcon() { return <svg aria-hidden="true" className="size-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><rect x="5" y="10" width="14" height="10" rx="2" /><path d="M8 10V7a4 4 0 0 1 8 0v3" /></svg>; }
function ShieldIcon() { return <svg aria-hidden="true" className="size-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.7"><path d="m12 3 7 3v5c0 4.6-2.6 7.8-7 9.7C7.6 18.8 5 15.6 5 11V6l7-3Z" /><path d="m9 12 2 2 4-4" strokeLinecap="round" strokeLinejoin="round" /></svg>; }
function GaugeIcon() { return <svg aria-hidden="true" className="size-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.7"><path d="M4.9 16a8 8 0 1 1 14.2 0" /><path d="m12 12 4-4M5 19h14" strokeLinecap="round" /></svg>; }
function SearchIcon() { return <svg aria-hidden="true" className="size-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.7"><circle cx="10.8" cy="10.8" r="5.8" /><path d="m15.2 15.2 4 4" strokeLinecap="round" /></svg>; }
function WrenchIcon() { return <svg aria-hidden="true" className="size-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.7"><path d="m14.7 6.3 3-3 3 3-3 3M16.5 8.5 8.2 16.8a2.1 2.1 0 1 1-3-3l8.3-8.3" /><path d="m5.8 18.2-2 2M13 5l3 3" strokeLinecap="round" /></svg>; }
function HistoryIcon() { return <svg aria-hidden="true" className="size-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.7"><path d="M4 12a8 8 0 1 0 2.3-5.7L4 8.5" /><path d="M4 4v4.5h4.5M12 8v4l2.5 1.5" strokeLinecap="round" strokeLinejoin="round" /></svg>; }
function DocumentIcon() { return <svg aria-hidden="true" className="size-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.7"><path d="M7 3.5h7l3 3V20.5H7z" /><path d="M14 3.5v3h3M9.5 11h5M9.5 14.5h5" strokeLinecap="round" /></svg>; }
