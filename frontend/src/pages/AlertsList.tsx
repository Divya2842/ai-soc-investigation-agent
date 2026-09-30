import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api } from "../services/api";
import type { Alert } from "../types/api";
import SeverityBadge from "../components/SeverityBadge";

const PAGE_SIZE = 20;

export default function AlertsList() {
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [total, setTotal] = useState(0);
  const [severityFilter, setSeverityFilter] = useState<string>("");
  const [statusFilter, setStatusFilter] = useState<string>("");
  const [searchInput, setSearchInput] = useState("");
  const [search, setSearch] = useState("");
  const [startDate, setStartDate] = useState("");
  const [endDate, setEndDate] = useState("");
  const [page, setPage] = useState(0);
  const [loading, setLoading] = useState(true);

  // Debounce the search box so we don't hit the backend on every keystroke.
  useEffect(() => {
    const handle = setTimeout(() => {
      setPage(0);
      setSearch(searchInput);
    }, 300);
    return () => clearTimeout(handle);
  }, [searchInput]);

  useEffect(() => {
    setLoading(true);
    api
      .listAlerts({
        severity: severityFilter || undefined,
        status: statusFilter || undefined,
        search: search || undefined,
        start_date: startDate ? new Date(startDate).toISOString() : undefined,
        end_date: endDate ? new Date(endDate).toISOString() : undefined,
        limit: PAGE_SIZE,
        offset: page * PAGE_SIZE,
      })
      .then((r) => {
        setAlerts(r.items);
        setTotal(r.total);
      })
      .finally(() => setLoading(false));
  }, [severityFilter, statusFilter, search, startDate, endDate, page]);

  const from = total === 0 ? 0 : page * PAGE_SIZE + 1;
  const to = Math.min((page + 1) * PAGE_SIZE, total);
  const hasNext = to < total;
  const hasPrev = page > 0;

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <h2 className="text-lg font-semibold">Alerts</h2>
        <div className="flex gap-2 flex-wrap">
          <input
            value={searchInput}
            onChange={(e) => setSearchInput(e.target.value)}
            placeholder="Search alert ID, name, host, user, IP, domain, hash…"
            className="bg-slate-900 border border-slate-700 rounded px-3 py-1.5 text-sm w-72 placeholder:text-slate-600"
          />
          <select
            value={statusFilter}
            onChange={(e) => {
              setPage(0);
              setStatusFilter(e.target.value);
            }}
            className="bg-slate-900 border border-slate-700 rounded px-2 py-1.5 text-sm"
          >
            <option value="">All statuses</option>
            <option value="new">New</option>
            <option value="investigating">Investigating</option>
            <option value="investigated">Investigated</option>
            <option value="investigation_failed">Investigation failed</option>
            <option value="closed">Closed</option>
          </select>
          <select
            value={severityFilter}
            onChange={(e) => {
              setPage(0);
              setSeverityFilter(e.target.value);
            }}
            className="bg-slate-900 border border-slate-700 rounded px-2 py-1.5 text-sm"
          >
            <option value="">All severities</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
            <option value="informational">Informational</option>
          </select>
          <input
            type="date"
            value={startDate}
            onChange={(e) => {
              setPage(0);
              setStartDate(e.target.value);
            }}
            className="bg-slate-900 border border-slate-700 rounded px-2 py-1.5 text-sm"
            title="Detected on/after"
          />
          <input
            type="date"
            value={endDate}
            onChange={(e) => {
              setPage(0);
              setEndDate(e.target.value);
            }}
            className="bg-slate-900 border border-slate-700 rounded px-2 py-1.5 text-sm"
            title="Detected on/before"
          />
        </div>
      </div>

      <div className="border border-slate-800 rounded-lg overflow-hidden">
        <table className="w-full text-sm">
          <thead className="bg-slate-900 text-slate-400 text-xs uppercase">
            <tr>
              <th className="text-left px-4 py-2">Alert</th>
              <th className="text-left px-4 py-2">Host / User</th>
              <th className="text-left px-4 py-2">Source</th>
              <th className="text-left px-4 py-2">Status</th>
              <th className="text-left px-4 py-2">Severity</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800">
            {alerts.map((a) => (
              <tr key={a.id} className="hover:bg-slate-800/40">
                <td className="px-4 py-2.5">
                  <Link to={`/alerts/${a.id}`} className="font-medium hover:underline">
                    {a.alert_name}
                  </Link>
                  <div className="text-xs text-slate-500">{a.alert_id}</div>
                </td>
                <td className="px-4 py-2.5 text-slate-300">
                  {a.hostname ?? "—"} <span className="text-slate-600">/</span> {a.user ?? "—"}
                </td>
                <td className="px-4 py-2.5 text-slate-400">{a.source}</td>
                <td className="px-4 py-2.5 text-slate-400">{a.status}</td>
                <td className="px-4 py-2.5">
                  <SeverityBadge severity={a.severity} />
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        {!loading && alerts.length === 0 && (
          <div className="text-sm text-slate-500 p-4">No alerts match this filter.</div>
        )}
      </div>

      <div className="flex items-center justify-between text-sm text-slate-500">
        <span>
          {total === 0 ? "0 results" : `Showing ${from}–${to} of ${total}`}
        </span>
        <div className="flex gap-2">
          <button
            onClick={() => setPage((p) => Math.max(0, p - 1))}
            disabled={!hasPrev}
            className="px-3 py-1 rounded border border-slate-700 disabled:opacity-40 hover:bg-slate-800"
          >
            Previous
          </button>
          <button
            onClick={() => setPage((p) => p + 1)}
            disabled={!hasNext}
            className="px-3 py-1 rounded border border-slate-700 disabled:opacity-40 hover:bg-slate-800"
          >
            Next
          </button>
        </div>
      </div>
    </div>
  );
}
