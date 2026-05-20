"use client";

import { useState } from "react";
import { AuthGuard } from "../../../components/layout/AuthGuard";
import { useAppStore } from "../../../store/useAppStore";
import { scanAPI } from "../../../lib/api";
import { StatusBadge } from "../../../components/ui/StatusBadge";
import { DataTable } from "../../../components/ui/DataTable";
import {
  AlertTriangle,
  CheckCircle2,
  Download,
  FileJson,
  Globe2,
  Info,
  Lock,
  Search,
  Server,
  Shield,
  ShieldAlert,
} from "lucide-react";
import { cn } from "../../../lib/utils";

const gradeColor = (grade: string) => {
  if (grade === "A+" || grade === "A") return "text-emerald-400";
  if (grade === "B") return "text-accent-cyan";
  if (grade === "C") return "text-amber-400";
  if (grade === "D" || grade === "E") return "text-orange-400";
  return "text-rose-500";
};

const severityClass = (severity: string) => {
  const sev = severity?.toLowerCase();
  if (sev === "critical") return "bg-rose-500/15 text-rose-400 border-rose-500/30";
  if (sev === "high") return "bg-orange-500/15 text-orange-300 border-orange-500/30";
  if (sev === "medium") return "bg-amber-500/15 text-amber-300 border-amber-500/30";
  if (sev === "low") return "bg-accent-cyan/10 text-accent-cyan border-accent-cyan/25";
  return "bg-bg-tertiary text-text-secondary border-border-subtle";
};

const moduleLabel = (name: string) => ({
  ssl: "TLS/SSL",
  headers: "HTTP headers",
  http_headers: "HTTP headers",
  dns: "DNS",
  ports: "Port scan",
  cors: "CORS",
  whois: "WHOIS",
  technologies: "Technology fingerprinting",
}[name] || name);

export default function DeepScannerPage() {
  const [target, setTarget] = useState("");
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const { deepScanResult, setDeepScanResult, appendScanHistory, deepScanHistory } = useAppStore();
  const result = deepScanResult;
  const score = result?.score ?? result?.overall_risk_score ?? 0;
  const grade = result?.grade ?? result?.risk_grade ?? "F";
  const headers = result?.headers || result?.http_headers || {};
  const findings = result?.findings || [];
  const roadmap = result?.remediation_roadmap || {};
  const immediate = roadmap.immediate_7_days || [];
  const shortTerm = roadmap.short_term_30_days || [];
  const longTerm = roadmap.long_term_90_days || [];
  const cves = result?.cves || [];
  const sshBanner = result?.ssh_banner || {};
  const modules = result
    ? {
        ssl: result.ssl,
        headers,
        dns: result.dns,
        ports: result.ports,
        cors: result.cors,
        whois: result.whois,
        technologies: result.technologies,
      }
    : {};

  const handleScan = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!target.trim() || isLoading) return;

    setIsLoading(true);
    setError(null);
    try {
      const res = await scanAPI.deepScan(target.trim());
      setDeepScanResult(res, target.trim());
      appendScanHistory({
        id: Date.now().toString(),
        timestamp: res.scan_timestamp,
        target: res.target,
        type: "deep",
        result: res,
      });
    } catch (err: any) {
      const detail = err.response?.data?.detail;
      setError(detail?.message || detail || "Deep scan could not be completed.");
    } finally {
      setIsLoading(false);
    }
  };

  const handleExport = () => {
    if (!result) return;
    const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(result, null, 2));
    const link = document.createElement("a");
    link.setAttribute("href", dataStr);
    link.setAttribute("download", `deepscan_${result.clean_target || result.target}_${new Date().toISOString().split("T")[0]}.json`);
    link.click();
  };

  const renderRoadmap = (title: string, items: any[], empty: string) => (
    <div className="bg-bg-primary border border-border-subtle rounded-lg p-4">
      <h4 className="font-bold text-text-primary mb-3">{title}</h4>
      {items.length > 0 ? (
        <ul className="space-y-3">
          {items.map((item, index) => (
            <li key={`${title}-${index}`} className="text-sm">
              <div className="flex items-center gap-2 mb-1">
                <span className={cn("px-2 py-0.5 rounded border text-[11px] font-bold", severityClass(item.severity))}>{item.severity || "Info"}</span>
                <span className="font-semibold text-text-primary">{item.title || "Action"}</span>
              </div>
              <p className="text-text-secondary">{item.recommendation || "No recommendation available."}</p>
            </li>
          ))}
        </ul>
      ) : (
        <p className="text-sm text-text-secondary">{empty}</p>
      )}
    </div>
  );

  return (
    <AuthGuard>
      <div className="p-4 md:p-8 space-y-8">
        <div>
          <h1 className="text-2xl font-bold text-text-primary mb-2 flex items-center gap-2">
            <Shield className="w-6 h-6 text-accent-violet" /> Deep Security Scanner
          </h1>
          <p className="text-text-secondary">Enterprise-grade, non-intrusive reconnaissance with evidence-backed findings.</p>
        </div>

        <form onSubmit={handleScan} className="bg-bg-secondary border border-border-subtle p-6 rounded-xl flex gap-4 flex-col md:flex-row">
          <input
            type="text"
            value={target}
            onChange={(e) => setTarget(e.target.value)}
            placeholder="Enter IP or domain, e.g. scanme.nmap.org"
            className="flex-1 px-4 py-3 bg-bg-primary border border-border-subtle rounded-lg text-text-primary focus:outline-none focus:border-accent-violet"
          />
          <button
            type="submit"
            disabled={isLoading || !target.trim()}
            className="px-8 py-3 bg-accent-violet hover:bg-accent-violet/90 text-bg-primary font-bold rounded-lg disabled:opacity-50 flex justify-center items-center gap-2 transition-colors min-h-[48px]"
          >
            {isLoading ? (
              <><div className="w-5 h-5 border-2 border-bg-primary border-t-transparent rounded-full animate-spin" /> Analyzing...</>
            ) : (
              <><Search className="w-5 h-5" /> Launch Deep Scan</>
            )}
          </button>
        </form>

        {error && (
          <div className="p-4 bg-rose-500/10 border border-rose-500/20 text-rose-500 rounded-lg flex gap-3">
            <AlertTriangle className="w-5 h-5 shrink-0" />
            <p>{error}</p>
          </div>
        )}

        {result && !isLoading && (
          <div className="space-y-6 animate-in fade-in slide-in-from-bottom-4">
            <div className="flex flex-col lg:flex-row justify-between items-start lg:items-center gap-4 bg-bg-secondary p-6 rounded-xl border border-border-subtle">
              <div>
                <h2 className="text-sm text-text-secondary uppercase tracking-widest mb-1">Target Analysis Complete</h2>
                <div className="text-3xl font-bold text-text-primary">{result.target}</div>
                <div className="text-sm text-text-secondary mt-2">
                  Resolved IP: <span className="font-mono text-accent-cyan">{result.ip_address || result.resolved_ip || "Not resolved"}</span>
                </div>
              </div>
              <div className="flex flex-wrap items-center gap-5">
                <div className="text-center">
                  <div className="text-sm text-text-secondary uppercase tracking-wider mb-1">Security Score</div>
                  <div className={cn("text-xl font-bold", gradeColor(grade))}>{score} / 100 - Grade {grade}</div>
                </div>
                <StatusBadge grade={grade} className="text-xl px-4 py-1" />
                <button onClick={handleExport} className="p-2 bg-bg-tertiary hover:bg-bg-primary rounded-lg border border-border-subtle text-text-secondary" title="Export JSON">
                  <Download className="w-5 h-5" />
                </button>
              </div>
            </div>

            {Object.entries(modules).map(([name, moduleResult]: [string, any]) => (
              moduleResult?.status === "error" ? (
                <div key={name} className="p-4 bg-amber-500/10 border border-amber-500/20 text-amber-300 rounded-lg flex gap-3">
                  <AlertTriangle className="w-5 h-5 shrink-0" />
                  <p>{moduleLabel(name)} analysis could not be completed: {moduleResult.reason || "Unavailable"}</p>
                </div>
              ) : null
            ))}

            <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-4">
              {Object.entries(result.summary || result.severity_counts || {}).map(([severity, count]: [string, any]) => (
                <div key={severity} className="bg-bg-secondary border border-border-subtle p-4 rounded-xl flex flex-col items-center justify-center gap-2">
                  <span className="text-xs text-text-secondary uppercase tracking-wider">{severity}</span>
                  <span className={cn("text-2xl font-bold", severityClass(severity).split(" ")[1])}>{count}</span>
                </div>
              ))}
              <div className="bg-bg-secondary border border-border-subtle p-4 rounded-xl flex flex-col items-center justify-center gap-2">
                <span className="text-xs text-text-secondary uppercase tracking-wider">Missing Headers</span>
                <span className="text-2xl font-bold text-amber-400">{headers?.missing_count ?? 0}</span>
              </div>
              <div className="bg-bg-secondary border border-border-subtle p-4 rounded-xl flex flex-col items-center justify-center gap-2">
                <span className="text-xs text-text-secondary uppercase tracking-wider">Critical Missing</span>
                <span className="text-2xl font-bold text-rose-500">{headers?.critical_missing ?? 0}</span>
              </div>
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              <section className="bg-bg-secondary border border-border-subtle p-6 rounded-xl">
                <h3 className="text-lg font-bold text-text-primary mb-4 flex items-center gap-2">
                  <ShieldAlert className="w-5 h-5 text-rose-500" /> Findings
                </h3>
                {findings.length > 0 ? (
                  <div className="space-y-3 max-h-[520px] overflow-y-auto pr-2 scrollbar-thin">
                    {findings.map((finding, index) => (
                      <div key={index} className="bg-bg-primary border border-border-subtle rounded-lg p-4">
                        <div className="flex flex-wrap items-center gap-2 mb-2">
                          <span className={cn("px-2 py-1 rounded border text-xs font-bold", severityClass(finding.severity))}>{finding.severity || "Info"}</span>
                          <span className="font-bold text-text-primary">{finding.title || "Finding"}</span>
                        </div>
                        <p className="text-sm text-text-secondary">{finding.description || "No description available."}</p>
                        {finding.evidence && <p className="text-xs text-text-secondary mt-2">Evidence: {finding.evidence}</p>}
                        <p className="text-xs text-text-secondary mt-1">Recommendation: {finding.recommendation || finding.remediation || "No recommendation available."}</p>
                      </div>
                    ))}
                  </div>
                ) : (
                  <div className="flex items-center gap-2 text-emerald-400">
                    <CheckCircle2 className="w-5 h-5" /> No findings were produced by the completed checks.
                  </div>
                )}
              </section>

              <section className="bg-bg-secondary border border-border-subtle p-6 rounded-xl">
                <h3 className="text-lg font-bold text-text-primary mb-4 flex items-center gap-2">
                  <Info className="w-5 h-5 text-accent-cyan" /> Remediation Roadmap
                </h3>
                <div className="space-y-4">
                  {renderRoadmap("Immediate - 7 Days", immediate, "No immediate critical or high-priority actions.")}
                  {renderRoadmap("Short Term - 30 Days", shortTerm, "No medium-priority actions.")}
                  {renderRoadmap("Long Term - 90 Days", longTerm, "No low/informational hardening actions.")}
                </div>
              </section>
            </div>

            {cves.length > 0 && (
              <details className="bg-bg-secondary border border-border-subtle rounded-xl p-4">
                <summary className="cursor-pointer text-lg font-bold text-text-primary mb-4 list-none flex items-center justify-between gap-3">
                  <span>Known CVEs ({cves.length})</span>
                  <span className="text-text-secondary text-sm">Expand for details</span>
                </summary>
                <div className="mt-4 overflow-x-auto">
                  <table className="w-full text-sm">
                    <thead className="text-text-secondary border-b border-border-subtle">
                      <tr>
                        <th className="text-left py-2">CVE ID</th>
                        <th className="text-left py-2">CVSS</th>
                        <th className="text-left py-2">Severity</th>
                        <th className="text-left py-2">Description</th>
                        <th className="text-left py-2">Link</th>
                      </tr>
                    </thead>
                    <tbody>
                      {cves.map((cve, index) => (
                        <tr key={`${cve.cve_id}-${index}`} className="border-b border-border-subtle/60">
                          <td className="py-3 font-mono text-accent-cyan">{cve.cve_id}</td>
                          <td className="py-3 text-text-primary">{cve.cvss_score}</td>
                          <td className="py-3"><span className={cn("px-2 py-1 rounded border text-xs font-bold", severityClass(cve.severity))}>{cve.severity}</span></td>
                          <td className="py-3 text-text-secondary">{String(cve.description || "").slice(0, 120)}{String(cve.description || "").length > 120 ? "..." : ""}</td>
                          <td className="py-3"><a className="text-accent-cyan hover:underline" href={cve.url} target="_blank" rel="noreferrer">NVD</a></td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </details>
            )}

            <div className="grid grid-cols-1 xl:grid-cols-3 gap-6">
              <section className="bg-bg-secondary border border-border-subtle p-6 rounded-xl">
                <h3 className="text-lg font-bold text-text-primary mb-4 flex items-center gap-2">
                  <Server className="w-5 h-5 text-accent-cyan" /> Network Exposure
                </h3>
                {(result.ports?.open_ports || []).length > 0 ? (
                  <ul className="space-y-3">
                    {result.ports.open_ports.map((port: any) => (
                      <li key={port.port} className="bg-bg-primary border border-border-subtle rounded-lg p-3">
                        <div className="flex justify-between gap-3">
                          <span className="font-mono text-accent-cyan">Port {port.port}</span>
                          <span className="text-text-primary">{port.service}</span>
                        </div>
                        {port.banner && <p className="text-xs font-mono text-text-secondary mt-2 break-all">{port.banner}</p>}
                      </li>
                    ))}
                  </ul>
                ) : <p className="text-sm text-text-secondary">No open ports observed in the scanner scope.</p>}
              </section>

              <section className="bg-bg-secondary border border-border-subtle p-6 rounded-xl">
                <h3 className="text-lg font-bold text-text-primary mb-4 flex items-center gap-2">
                  <Lock className="w-5 h-5 text-emerald-400" /> TLS & Headers
                </h3>
                <div className="space-y-3 text-sm">
                  <div className="flex justify-between gap-3"><span className="text-text-secondary">TLS status</span><span className="text-text-primary">{result.ssl?.status || "N/A"}</span></div>
                  <div className="flex justify-between gap-3"><span className="text-text-secondary">TLS 1.0</span><span className="text-text-primary">{result.ssl?.protocols?.["TLS 1.0"] || "not checked"}</span></div>
                  <div className="flex justify-between gap-3"><span className="text-text-secondary">TLS 1.1</span><span className="text-text-primary">{result.ssl?.protocols?.["TLS 1.1"] || "not checked"}</span></div>
                  <div className="flex justify-between gap-3"><span className="text-text-secondary">TLS 1.2</span><span className="text-text-primary">{result.ssl?.protocols?.["TLS 1.2"] || "not checked"}</span></div>
                  <div className="flex justify-between gap-3"><span className="text-text-secondary">TLS 1.3</span><span className="text-text-primary">{result.ssl?.protocols?.["TLS 1.3"] || "not checked"}</span></div>
                  <div className="flex justify-between gap-3"><span className="text-text-secondary">Missing headers</span><span className="text-text-primary">{headers?.missing_count ?? 0}</span></div>
                </div>
              </section>

              <section className="bg-bg-secondary border border-border-subtle p-6 rounded-xl">
                <h3 className="text-lg font-bold text-text-primary mb-4 flex items-center gap-2">
                  <Globe2 className="w-5 h-5 text-accent-violet" /> DNS & Technology
                </h3>
                <div className="space-y-3 text-sm">
                  <div className="flex justify-between gap-3"><span className="text-text-secondary">SPF</span><span className="text-text-primary">{result.dns?.spf?.skipped ? "Skipped" : result.dns?.spf?.present ? "Present" : "Missing"}</span></div>
                  <div className="flex justify-between gap-3"><span className="text-text-secondary">DMARC</span><span className="text-text-primary">{result.dns?.dmarc?.skipped ? "Skipped" : result.dns?.dmarc?.present ? "Present" : "Missing"}</span></div>
                  <div className="flex justify-between gap-3"><span className="text-text-secondary">Web server</span><span className="text-text-primary text-right">{result.technologies?.web_server || result.technologies?.server || "Not disclosed"}</span></div>
                  {sshBanner.os && <div className="flex justify-between gap-3"><span className="text-text-secondary">SSH OS</span><span className="text-text-primary text-right">{sshBanner.os}</span></div>}
                </div>
                {sshBanner.eol && (
                  <div className="mt-4 p-3 bg-rose-500/10 border border-rose-500/20 text-rose-400 rounded-lg text-sm">
                    End-of-life OS detected from SSH banner. Upgrade planning is required.
                  </div>
                )}
              </section>
            </div>

            <section className="bg-bg-secondary border border-border-subtle rounded-xl p-6">
              <h3 className="text-lg font-bold text-text-primary mb-3 flex items-center gap-2">
                <FileJson className="w-5 h-5 text-accent-amber" /> Trust Boundary
              </h3>
              <p className="text-sm text-text-secondary">{result.trust_boundary || "Non-intrusive scan. Exploitability is not claimed without explicit evidence."}</p>
            </section>
          </div>
        )}

        {deepScanHistory.length > 0 && !isLoading && !result && (
          <div>
            <h2 className="text-lg font-bold text-text-primary mb-4">Deep Scan History</h2>
            <DataTable
              data={deepScanHistory}
              columns={[
                { header: "Date", cell: r => new Date(r.timestamp).toLocaleString(), className: "text-text-secondary text-sm" },
                { header: "Target", accessorKey: "target", className: "font-bold text-text-primary" },
                { header: "Grade", cell: r => <StatusBadge grade={(r.result as any).grade || (r.result as any).risk_grade} /> },
                { header: "Score", cell: r => (r.result as any).score ?? (r.result as any).overall_risk_score, className: "font-mono" },
              ]}
            />
          </div>
        )}
      </div>
    </AuthGuard>
  );
}

