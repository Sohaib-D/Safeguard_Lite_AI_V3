export interface AuthResponse {
  access_token: string;
  token_type: string;
  username: string;
  role?: "admin" | "user";
}

export interface ModelInfo {
  version: string;
  model_name: string;
  framework: string;
  backend: string;
  feature_count: number;
  label_classes: string[];
  raw_input_schema: Record<string, any>;
}

export interface PredictionResult {
  prediction: string;
  probabilities: Record<string, number>;
  risk_level?: string;
  features: Record<string, any>;
  shap_values?: Record<string, number>;
  timestamp?: string;
}

export interface BatchPredictionResult {
  total: number;
  anomalies: number;
  normal: number;
  results: PredictionResult[];
  summary: Record<string, any>;
}

export interface ActiveScanResult {
  target: string;
  timestamp: string;
  dns: Record<string, any>;
  ports: Array<Record<string, any>>;
  ssl: Record<string, any> | null;
  http_headers: Record<string, any>;
  whois: Record<string, any> | null;
  latency_ms: number | null;
  security_configs?: Array<Record<string, any>>;
  error?: string | null;
}

export interface DeepScanResult {
  target: string;
  raw_target?: string;
  clean_target: string;
  ip_address?: string | null;
  resolved_ip?: string | null;
  quick_scan: boolean;
  scan_timestamp: string;
  scan_duration_ms?: number;
  score: number;
  grade: string;
  score_deductions?: Array<Record<string, any>>;
  summary?: Record<string, number>;
  overall_risk_score: number;
  risk_grade: string;
  severity_counts: Record<string, number>;
  critical_findings: string[];
  findings?: Array<Record<string, any>>;
  total_findings: number;
  ports: Record<string, any>;
  ssl: Record<string, any>;
  headers?: Record<string, any>;
  http_headers: Record<string, any>;
  dns: Record<string, any>;
  technologies: Record<string, any>;
  cves?: Array<Record<string, any>>;
  cors?: Record<string, any>;
  ssh_banner?: Record<string, any>;
  whois: Record<string, any>;
  cve_scan: Record<string, any>;
  remediation_roadmap?: Record<string, any>;
  trust_boundary?: string;
  raw_modules?: Record<string, any>;
}

export interface AnalysisResult {
  analysis: string;
}

export interface Alert {
  id: number;
  timestamp: string;
  type: string;
  severity: "critical" | "high" | "medium" | "low";
  source_ip: string;
  description: string;
  status: "active" | "acknowledged" | "resolved";
  acknowledged_by?: string;
  acknowledged_at?: string;
  notes?: string;
}

export interface LiveEvent {
  timestamp: string;
  type: string;
  details: string;
  severity: string;
}

export interface LogEntry {
  timestamp: string;
  level: string;
  message: string;
  source: string;
}

export interface Notification {
  id: string;
  timestamp: string;
  title: string;
  message: string;
  type: "info" | "warning" | "error" | "success";
  read: boolean;
}

export interface ScanHistoryEntry {
  id: string;
  timestamp: string;
  target: string;
  type: "active" | "deep";
  result: ActiveScanResult | DeepScanResult;
}

export interface StatsResult {
  model_stats: Record<string, any>;
  scan_stats: Record<string, any>;
  alert_stats: Record<string, any>;
}

export interface ExplainResult {
  explanation: string;
  shap_values?: Record<string, number>;
}

export interface SOCMessage {
  type: "alert" | "log" | "notification" | "status";
  data: any;
}
