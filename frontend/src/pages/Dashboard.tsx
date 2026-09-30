import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api } from "../services/api";
import type { Alert, AlertStats } from "../types/api";
import SeverityBadge from "../components/SeverityBadge";
import Panel from "../components/Panel";

export default function Dashboard() {
  const [stats, setStats] = useState<AlertStats | null>(null);
  const [recentAlerts, setRecentAlerts] = useState<Alert[]>([]);
  const [groqConfigured, setGroqConfigured] = useState<boolean | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api
      .getAlertStats()
      .then(setStats)
      .catch((e) => setError(String(e)));
    api
      .listAlerts({ limit: 8 })
      .then((r) => setRecentAlerts(r.items))
      .catch((e) => setError(String(e)));
    api
      .health()
      .then((h) => setGroqConfigured(h.groq_configured))
      .catch(() => setGroqConfigured(null));
  }, []);

  const stat = (label: string, value: number | string, accent = "text-slate-100") => (
    <div className="border border-slate-800 rounded-lg bg-slate-900/60 p-4">
      <div className="text-xs uppercase tracking-wide text-slate-500">{label}</div>
      <div className={`text-2xl font-semibold mt-1 ${accent}`}>{value}</div>
    </div>
  );

  return (
    <div className="space-y-6">
      {groqConfigured === false && (
        <div className="text-xs border border-amber-900 bg-amber-950/40 text-amber-300 rounded-md px-3 py-2">
          GROQ_API_KEY is not configured — investigations will use the deterministic-only
          fallback summary instead of an LLM-authored one. Every other capability
          (extraction, enrichment, MITRE mapping, risk scoring, disposition, and the
          structured report) is fully functional either way.
        </div>
      )}

      {error && (
        <div className="text-xs border border-red-900 bg-red-950/40 text-red-300 rounded-md px-3 py-2">
          Could not reach the backend API: {error}. Is the backend running on port 8000?
        </div>
      )}

      {/* All counts below come live from GET /api/alerts/stats -- never hardcoded. */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        {stat("Total Alerts", stats?.total ?? "—")}
        {stat("Critical", stats?.critical ?? "—", "text-red-400")}
        {stat("High", stats?.high ?? "—", "text-orange-400")}
        {stat("Medium", stats?.medium ?? "—", "text-amber-400")}
        {stat("Low", stats?.low ?? "—", "text-blue-400")}
        {stat("Informational", stats?.informational ?? "—", "text-slate-400")}
        {stat("Investigated", stats?.investigated ?? "—")}
      </div>

      <Panel title="Recent Alerts" right={<Link to="/alerts" className="text-xs text-blue-400 hover:underline">View all →</Link>}>
        <div className="divide-y divide-slate-800">
          {recentAlerts.map((a) => (
            <Link
              key={a.id}
              to={`/alerts/${a.id}`}
              className="flex items-center justify-between py-2.5 hover:bg-slate-800/40 -mx-4 px-4 rounded"
            >
              <div>
                <div className="text-sm font-medium">{a.alert_name}</div>
                <div className="text-xs text-slate-500">
                  {a.alert_id} · {a.hostname ?? "—"} · {a.user ?? "—"}
                </div>
              </div>
              <div className="flex items-center gap-2">
                <span className="text-xs text-slate-500">{a.status}</span>
                <SeverityBadge severity={a.severity} />
              </div>
            </Link>
          ))}
          {recentAlerts.length === 0 && !error && (
            <div className="text-sm text-slate-500 py-4">
              No alerts yet. Seed sample data with{" "}
              <code className="text-slate-300">python -m app.database.seed</code>.
            </div>
          )}
        </div>
      </Panel>
    </div>
  );
}
