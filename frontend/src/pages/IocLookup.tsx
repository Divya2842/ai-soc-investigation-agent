import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api } from "../services/api";
import type { IOC } from "../types/api";
import ReputationBadge from "../components/ReputationBadge";
import SourceBadge from "../components/SourceBadge";
import EnrichmentStatusBadge from "../components/EnrichmentStatusBadge";
import Panel from "../components/Panel";

const PAGE_SIZE = 25;

export default function IocLookup() {
  const [iocType, setIocType] = useState("");
  const [reputation, setReputation] = useState("");
  const [searchInput, setSearchInput] = useState("");
  const [q, setQ] = useState("");
  const [alertIdInput, setAlertIdInput] = useState("");
  const [alertDisplayId, setAlertDisplayId] = useState("");
  const [page, setPage] = useState(0);
  const [iocs, setIocs] = useState<IOC[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    const handle = setTimeout(() => {
      setPage(0);
      setQ(searchInput);
      setAlertDisplayId(alertIdInput);
    }, 300);
    return () => clearTimeout(handle);
  }, [searchInput, alertIdInput]);

  useEffect(() => {
    setLoading(true);
    api
      .listIocs({
        ioc_type: iocType || undefined,
        reputation: reputation || undefined,
        q: q || undefined,
        alert_display_id: alertDisplayId || undefined,
        limit: PAGE_SIZE,
        offset: page * PAGE_SIZE,
      })
      .then((r) => {
        setIocs(r.items);
        setTotal(r.total);
      })
      .finally(() => setLoading(false));
  }, [iocType, reputation, q, alertDisplayId, page]);

  const from = total === 0 ? 0 : page * PAGE_SIZE + 1;
  const to = Math.min((page + 1) * PAGE_SIZE, total);

  return (
    <div className="space-y-4">
      <h2 className="text-lg font-semibold">IOC Lookup</h2>
      <p className="text-xs text-slate-500">
        Every IOC is enriched automatically in the background as soon as its alert is ingested —
        there's nothing to trigger manually here.
      </p>

      <div className="flex flex-wrap gap-2 items-center">
        <input
          value={searchInput}
          onChange={(e) => setSearchInput(e.target.value)}
          placeholder="Search IOC value…"
          className="bg-slate-900 border border-slate-700 rounded px-3 py-1.5 text-sm w-56 placeholder:text-slate-600"
        />
        <input
          value={alertIdInput}
          onChange={(e) => setAlertIdInput(e.target.value)}
          placeholder="Filter by Alert ID…"
          className="bg-slate-900 border border-slate-700 rounded px-3 py-1.5 text-sm w-48 placeholder:text-slate-600"
        />
        <select
          value={iocType}
          onChange={(e) => {
            setPage(0);
            setIocType(e.target.value);
          }}
          className="bg-slate-900 border border-slate-700 rounded px-2 py-1.5 text-sm"
        >
          <option value="">All types</option>
          <option value="ipv4">IPv4</option>
          <option value="ipv6">IPv6</option>
          <option value="domain">Domain</option>
          <option value="url">URL</option>
          <option value="md5">MD5</option>
          <option value="sha1">SHA1</option>
          <option value="sha256">SHA256</option>
          <option value="email">Email</option>
        </select>
        <select
          value={reputation}
          onChange={(e) => {
            setPage(0);
            setReputation(e.target.value);
          }}
          className="bg-slate-900 border border-slate-700 rounded px-2 py-1.5 text-sm"
        >
          <option value="">All reputations</option>
          <option value="malicious">Malicious</option>
          <option value="suspicious">Suspicious</option>
          <option value="clean">Clean</option>
          <option value="unknown">Unknown</option>
        </select>
      </div>

      <Panel title={`Results (${total})`}>
        <div className="divide-y divide-slate-800">
          {iocs.map((ioc) => (
            <div key={ioc.id} className="py-3 flex items-center justify-between gap-4 flex-wrap">
              <div className="min-w-0">
                <div className="text-xs uppercase text-slate-500">{ioc.ioc_type}</div>
                <div className="font-mono text-sm truncate">{ioc.value}</div>
                {ioc.alert_display_id && (
                  <Link
                    to={`/alerts/${ioc.alert_id}`}
                    className="text-xs text-blue-400 hover:underline"
                  >
                    Related alert: {ioc.alert_display_id}
                  </Link>
                )}
              </div>
              <div className="flex items-center gap-2 shrink-0 text-xs text-slate-400 flex-wrap">
                <EnrichmentStatusBadge status={ioc.enrichment?.status ?? "pending"} />
                {ioc.enrichment && (
                  <>
                    <SourceBadge source={ioc.enrichment.source} />
                    <ReputationBadge reputation={ioc.enrichment.reputation} />
                    {ioc.enrichment.malicious_count !== null && (
                      <span>
                        M:{ioc.enrichment.malicious_count} / S:{ioc.enrichment.suspicious_count} / H:
                        {ioc.enrichment.harmless_count}
                      </span>
                    )}
                    <span>{Math.round(ioc.enrichment.confidence * 100)}% conf.</span>
                    {ioc.enrichment.last_seen && (
                      <span>{new Date(ioc.enrichment.last_seen).toLocaleString()}</span>
                    )}
                  </>
                )}
              </div>
            </div>
          ))}
          {!loading && iocs.length === 0 && (
            <div className="text-sm text-slate-500 py-4">
              No results — ingest/investigate an alert first, or adjust your filters.
            </div>
          )}
        </div>
      </Panel>

      <div className="flex items-center justify-between text-sm text-slate-500">
        <span>{total === 0 ? "0 results" : `Showing ${from}–${to} of ${total}`}</span>
        <div className="flex gap-2">
          <button
            onClick={() => setPage((p) => Math.max(0, p - 1))}
            disabled={page === 0}
            className="px-3 py-1 rounded border border-slate-700 disabled:opacity-40 hover:bg-slate-800"
          >
            Previous
          </button>
          <button
            onClick={() => setPage((p) => p + 1)}
            disabled={to >= total}
            className="px-3 py-1 rounded border border-slate-700 disabled:opacity-40 hover:bg-slate-800"
          >
            Next
          </button>
        </div>
      </div>
    </div>
  );
}

