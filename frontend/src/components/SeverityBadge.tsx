const COLORS: Record<string, string> = {
  informational: "bg-slate-800 text-slate-400 border-slate-700",
  low: "bg-blue-950 text-blue-300 border-blue-800",
  medium: "bg-amber-950 text-amber-300 border-amber-800",
  high: "bg-orange-950 text-orange-300 border-orange-800",
  critical: "bg-red-950 text-red-300 border-red-800",
};

export default function SeverityBadge({ severity }: { severity: string }) {
  const cls = COLORS[severity.toLowerCase()] ?? "bg-slate-800 text-slate-300 border-slate-700";
  return (
    <span className={`inline-block px-2 py-0.5 rounded border text-xs font-medium uppercase ${cls}`}>
      {severity}
    </span>
  );
}
