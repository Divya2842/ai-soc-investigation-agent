export interface IOC {
  id: string;
  alert_id: string;
  alert_display_id: string | null;
  ioc_type: string;
  value: string;
  first_extracted_at: string;
  enrichment: IOCEnrichment | null;
}

export interface Alert {
  id: string;
  alert_id: string;
  alert_name: string;
  severity: string;
  timestamp: string;
  source: string;
  user: string | null;
  hostname: string | null;
  source_ip: string | null;
  destination_ip: string | null;
  command_line: string | null;
  file_hash: string | null;
  domain: string | null;
  url: string | null;
  description: string | null;
  status: string;
  created_at: string;
}

export interface AlertDetail extends Alert {
  iocs: IOC[];
}

export interface AlertStats {
  total: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  informational: number;
  investigated: number;
}

export interface IOCEnrichment {
  id: string;
  ioc_id: string;
  source: string;
  status: string; // "pending" | "completed" | "failed" | "not_available"
  reputation: string;
  confidence: number;
  malicious_count: number | null;
  suspicious_count: number | null;
  harmless_count: number | null;
  first_seen: string | null;
  last_seen: string | null;
  related_malware: string[];
  related_threat_actor: string | null;
  asn: string | null;
  isp: string | null;
  country: string | null;
  raw_response: Record<string, unknown>;
  enriched_at: string;
}

export interface MitreTechnique {
  technique_id: string;
  name: string;
  tactic: string;
  rationale: string;
  supporting_evidence: string[];
}

export interface Finding {
  statement: string;
  evidence: string[];
}

export interface Investigation {
  id: string;
  alert_id: string;
  verdict: string;
  status: string; // "in_progress" | "completed" | "failed"
  disposition: string; // "true_positive" | "false_positive" | "benign_positive" | "suspicious" | "inconclusive"
  requires_customer_validation: boolean;
  severity: string;
  risk_score: number;
  risk_factors: Record<string, number>;
  confidence: number;
  summary: string;
  findings: Finding[];
  evidence: string[];
  attack_techniques: MitreTechnique[];
  atlas_techniques: MitreTechnique[];
  recommended_actions: string[];
  // Note: RAG source documents/playbook references are intentionally never
  // returned by the API -- they're internal retrieval metadata, not
  // investigation findings.
  llm_used: boolean;
  created_at: string;
}

export interface InvestigationReport {
  format: "analyst" | "customer";
  report_markdown: string;
}

export interface ResponseAction {
  id: string;
  investigation_id: string;
  action_type: string;
  status: string;
  approved_by: string | null;
  approved_at: string | null;
  simulated_result: string | null;
  created_at: string;
}
