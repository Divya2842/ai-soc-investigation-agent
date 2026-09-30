const LABELS: Record<string, string> = {
  pending: "Pending",
  completed: "Completed",
  failed: "Failed",
  not_available: "Not available",
};

const COLORS: Record<string, string> = {
  pending: "bg-slate-800 text-slate-400 border-slate-700 animate-pulse",
  completed: "bg-slate-800 text-slate-300 border-slate-700",
  failed: "bg-red-950 text-red-300 border-red-800",
  not_available: "bg-slate-900 text-slate-500 border-slate-800",
};

export default function EnrichmentStatusBadge({ status }: { status: string }) {
  const cls = COLORS[status] ?? COLORS.pending;
  return (
    <span className={`inline-block px-2 py-0.5 rounded border text-[11px] font-medium ${cls}`}>
      {LABELS[status] ?? status}
    </span>
  );
}
