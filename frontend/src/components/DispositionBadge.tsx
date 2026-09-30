const LABELS: Record<string, string> = {
  true_positive: "TP",
  false_positive: "FP",
  benign_positive: "BP",
  suspicious: "Suspicious",
  inconclusive: "Inconclusive",
};

const COLORS: Record<string, string> = {
  true_positive: "bg-red-950 text-red-300 border-red-800",
  false_positive: "bg-emerald-950 text-emerald-300 border-emerald-800",
  benign_positive: "bg-blue-950 text-blue-300 border-blue-800",
  suspicious: "bg-amber-950 text-amber-300 border-amber-800",
  inconclusive: "bg-slate-800 text-slate-400 border-slate-700",
};

export default function DispositionBadge({ disposition }: { disposition: string }) {
  const label = LABELS[disposition] ?? disposition;
  const cls = COLORS[disposition] ?? COLORS.inconclusive;
  return (
    <span className={`inline-block px-2 py-0.5 rounded border text-xs font-medium ${cls}`}>{label}</span>
  );
}
