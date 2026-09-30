export default function SourceBadge({ source }: { source: string }) {
  const isLocal = source === "local_mock";
  return (
    <span
      className={`inline-block px-2 py-0.5 rounded border text-[11px] font-medium ${
        isLocal
          ? "bg-slate-800 text-slate-400 border-slate-700"
          : "bg-purple-950 text-purple-300 border-purple-800"
      }`}
      title={isLocal ? "Local/mock enrichment (no external API used)" : "External threat-intel provider"}
    >
      {isLocal ? "local/mock" : source}
    </span>
  );
}
