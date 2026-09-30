import type {
  Alert,
  AlertDetail,
  AlertStats,
  IOC,
  IOCEnrichment,
  Investigation,
  InvestigationReport,
  ResponseAction,
} from "../types/api";

const BASE = ""; // proxied via vite.config.ts in dev; same-origin in prod build

async function requestWithHeaders<T>(
  path: string,
  init?: RequestInit
): Promise<{ data: T; headers: Headers }> {
  const token = localStorage.getItem("soc_access_token");
  const resp = await fetch(`${BASE}${path}`, {
    ...init,
    headers: {
      "Content-Type": "application/json",
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
      ...(init?.headers ?? {}),
    },
  });
  if (resp.status === 401) {
    localStorage.removeItem("soc_access_token");
    if (window.location.pathname !== "/login") window.location.href = "/login";
  }
  if (!resp.ok) {
    const body = await resp.text().catch(() => "");
    throw new Error(`${resp.status} ${resp.statusText}: ${body}`);
  }
  const data = (await resp.json()) as T;
  return { data, headers: resp.headers };
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const { data } = await requestWithHeaders<T>(path, init);
  return data;
}

function toQueryString(params: Record<string, string | number | undefined>): string {
  const filtered: Record<string, string> = {};
  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined && value !== "") filtered[key] = String(value);
  }
  const qs = new URLSearchParams(filtered).toString();
  return qs ? `?${qs}` : "";
}

export const api = {
  health: () =>
    request<{ status: string; groq_configured: boolean; log_source: string; note: string }>("/health"),

  getAlertStats: () => request<AlertStats>("/api/alerts/stats"),

  listAlerts: async (
    params: {
      status?: string;
      severity?: string;
      search?: string;
      start_date?: string;
      end_date?: string;
      limit?: number;
      offset?: number;
    } = {}
  ): Promise<{ items: Alert[]; total: number }> => {
    const { data, headers } = await requestWithHeaders<Alert[]>(`/api/alerts${toQueryString(params)}`);
    const total = Number(headers.get("X-Total-Count") ?? data.length);
    return { items: data, total };
  },
  getAlert: (id: string) => request<AlertDetail>(`/api/alerts/${id}`),

  listIocs: async (
    params: {
      ioc_type?: string;
      alert_id?: string;
      alert_display_id?: string;
      reputation?: string;
      q?: string;
      limit?: number;
      offset?: number;
    } = {}
  ): Promise<{ items: IOC[]; total: number }> => {
    const { data, headers } = await requestWithHeaders<IOC[]>(`/api/iocs${toQueryString(params)}`);
    const total = Number(headers.get("X-Total-Count") ?? data.length);
    return { items: data, total };
  },
  getIocEnrichment: (iocId: string) => request<IOCEnrichment>(`/api/iocs/${iocId}/enrichment`),

  investigateAlert: (alertId: string) =>
    request<Investigation>(`/api/alerts/${alertId}/investigate`, { method: "POST" }),
  getInvestigation: (id: string) => request<Investigation>(`/api/investigations/${id}`),
  getInvestigationReport: (id: string, format: "analyst" | "customer" = "analyst") =>
    request<InvestigationReport>(`/api/investigations/${id}/report?format=${format}`),

  listResponseActions: (investigationId: string) =>
    request<ResponseAction[]>(`/api/response/${investigationId}`),
  approveResponse: (investigationId: string, approvedBy = "analyst") =>
    request<ResponseAction[]>(`/api/response/${investigationId}/approve`, {
      method: "POST",
      body: JSON.stringify({ approved_by: approvedBy }),
    }),
  rejectResponse: (investigationId: string, approvedBy = "analyst") =>
    request<ResponseAction[]>(`/api/response/${investigationId}/reject`, {
      method: "POST",
      body: JSON.stringify({ approved_by: approvedBy }),
    }),
};
