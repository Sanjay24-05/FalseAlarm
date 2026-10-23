import type { Report } from "./types";

export const PRIMARY_SCENARIOS = [
  {
    id: "account_compromise",
    title: "Account compromise",
    description: "Credential abuse and suspicious account activity.",
  },
  {
    id: "benign_vpn_login",
    title: "Benign VPN login",
    description: "A VPN sign-in that should resolve as likely benign.",
  },
] as const;

export const ALERT_JSON_FIELDS = [
  "id (optional)",
  "source",
  "name",
  "description",
  "severity",
  "detected_at",
  "src_ip",
  "dst_ip",
  "username",
  "hostname",
  "file_hashes",
  "domains",
  "urls",
  "mitre_techniques",
  "raw",
] as const;

export const ALERT_JSON_SAMPLE = `{
  "source": "sentinel",
  "name": "Suspicious sign-in",
  "description": "Failed sign-ins followed by a success from a new IP.",
  "severity": "high",
  "detected_at": "2026-10-23T12:00:00Z",
  "src_ip": "203.0.113.10",
  "dst_ip": "198.51.100.24",
  "username": "jsmith",
  "hostname": "WS-0142",
  "file_hashes": [],
  "domains": [],
  "urls": [],
  "mitre_techniques": ["T1078"],
  "raw": {}
}`;

export const REPORT_SECTIONS: ReadonlyArray<{ key: keyof Report; title: string }> = [
  { key: "incident_summary", title: "Incident summary" },
  { key: "alert_details", title: "Alert details" },
  { key: "triage", title: "Triage" },
  { key: "executive_explanation", title: "Executive explanation" },
  { key: "timeline", title: "Timeline" },
  { key: "evidence", title: "Evidence" },
  { key: "correlated_indicators", title: "Correlated indicators" },
  { key: "threat_intelligence", title: "Threat intelligence" },
  { key: "attack_sequence", title: "Attack sequence" },
  { key: "confidence_and_gaps", title: "Confidence and gaps" },
  { key: "recommended_actions", title: "Recommended actions" },
  { key: "escalation", title: "Escalation" },
  { key: "audit_trail", title: "Audit trail" },
];
