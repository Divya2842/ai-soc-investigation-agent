const COLORS: Record<string, string> = {
  malicious: "bg-red-950 text-red-300 border-red-800",
  suspicious: "bg-amber-950 text-amber-300 border-amber-800",
  clean: "bg-emerald-950 text-emerald-300 border-emerald-800",
  unknown: "bg-slate-800 text-slate-400 border-slate-700",
};

export default function ReputationBadge({ reputation }: { reputation: string }) {
  const cls = COLORS[reputation.toLowerCase()] ?? COLORS.unknown;
  return (
    <span className={`inline-block px-2 py-0.5 rounded border text-xs font-medium ${cls}`}>
      {reputation}
    </span>
  );
}
