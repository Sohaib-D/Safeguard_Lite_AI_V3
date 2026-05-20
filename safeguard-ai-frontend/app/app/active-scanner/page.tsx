"use client";

import { useState } from "react";
import { AuthGuard } from "../../../components/layout/AuthGuard";
import { useAppStore } from "../../../store/useAppStore";
import { scanAPI } from "../../../lib/api";
import { Search, Globe, ShieldAlert, CheckCircle2, Lock, FileJson, Network, Server } from "lucide-react";
import { cn } from "../../../lib/utils";

export default function ActiveScannerPage() {
  const [target, setTarget] = useState("");
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  
  const { scanResult, setActiveScanResult } = useAppStore();
  const findings = scanResult?.security_configs || [];
  const headers = scanResult?.http_headers || {};

  const handleScan = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!target.trim() || isLoading) return;
    
    setIsLoading(true);
    setError(null);
    try {
      const res = await scanAPI.activeScan(target.trim());
      setActiveScanResult(res, target.trim());
    } catch (err: any) {
      console.error(err);
      setError(err.response?.data?.detail || "Scan failed. Ensure target is reachable and valid.");
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <AuthGuard>
      <div className="p-4 md:p-8 space-y-8">
        <div>
          <h1 className="text-2xl font-bold text-text-primary mb-2">Active Scanner</h1>
          <p className="text-text-secondary">Perform non-intrusive reconnaissance on IP addresses or domains.</p>
        </div>

        <form onSubmit={handleScan} className="bg-bg-secondary border border-border-subtle p-6 rounded-xl flex gap-4 flex-col md:flex-row">
          <div className="flex-1 relative">
            <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
              <Globe className="h-5 w-5 text-text-secondary" />
            </div>
            <input 
              type="text" 
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              placeholder="Enter IP or Domain (e.g., example.com)"
              className="w-full pl-10 pr-4 py-3 bg-bg-primary border border-border-subtle rounded-lg text-text-primary focus:outline-none focus:border-accent-cyan"
            />
          </div>
          <button 
            type="submit"
            disabled={isLoading || !target.trim()}
            className="px-8 py-3 bg-accent-cyan hover:bg-accent-cyan/90 text-bg-primary font-bold rounded-lg disabled:opacity-50 flex justify-center items-center gap-2 transition-colors min-h-[48px] md:w-auto w-full"
          >
            {isLoading ? (
              <><div className="w-5 h-5 border-2 border-bg-primary border-t-transparent rounded-full animate-spin" /> Scanning...</>
            ) : (
              <><Search className="w-5 h-5" /> Launch Scan</>
            )}
          </button>
        </form>

        {error && (
          <div className="p-4 bg-rose-500/10 border border-rose-500/20 text-rose-500 rounded-lg flex gap-3">
            <ShieldAlert className="w-5 h-5 shrink-0" />
            <p>{error}</p>
          </div>
        )}

        {scanResult && !isLoading && (
          <div className="space-y-6 animate-in fade-in slide-in-from-bottom-4">
            <div className="flex flex-col lg:flex-row justify-between gap-4 bg-bg-secondary p-4 rounded-xl border border-border-subtle">
              <div className="flex flex-col sm:flex-row gap-4">
                <div>
                  <div className="text-xs text-text-secondary uppercase">Target</div>
                  <div className="font-bold text-text-primary text-lg">{scanResult.target}</div>
                </div>
                {scanResult.dns?.ip_address && (
                  <div>
                    <div className="text-xs text-text-secondary uppercase">Resolved IP</div>
                    <div className="font-mono text-accent-cyan">{scanResult.dns.ip_address}</div>
                  </div>
                )}
                <div>
                  <div className="text-xs text-text-secondary uppercase">Probe Type</div>
                  <div className="text-text-primary">Safe TCP/DNS/HTTP reconnaissance</div>
                </div>
              </div>
              <div className="text-xs text-text-secondary text-right">
                <div>Timestamp</div>
                <div>{new Date(scanResult.timestamp).toLocaleString()}</div>
                {scanResult.latency_ms !== null && <div>DNS latency: {scanResult.latency_ms} ms</div>}
              </div>
            </div>

            {scanResult.error && (
              <div className="p-4 bg-amber-500/10 border border-amber-500/20 text-amber-300 rounded-lg flex gap-3">
                <ShieldAlert className="w-5 h-5 shrink-0" />
                <p>{scanResult.error}</p>
              </div>
            )}

            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              {/* Open Ports */}
              <div className="bg-bg-secondary border border-border-subtle rounded-xl p-6">
                <h2 className="text-lg font-bold text-text-primary mb-4 border-b border-border-subtle pb-2 flex items-center gap-2">
                  <Network className="w-5 h-5 text-accent-cyan" /> Open Ports
                </h2>
                {(scanResult.ports || []).length === 0 ? (
                  <p className="text-text-secondary italic">No open ports were detected across the configured common-port set. This is not a full-port guarantee.</p>
                ) : (
                  <ul className="space-y-2">
                    {scanResult.ports.map((port: any) => (
                      <li key={port.port} className="p-3 bg-bg-primary border border-border-subtle rounded-lg">
                        <div className="flex justify-between items-center gap-3">
                          <span className="font-mono font-bold text-accent-cyan">Port {port.port}</span>
                          <span className="text-sm text-text-primary">{port.service || "Unknown"}</span>
                        </div>
                        <p className="text-xs text-text-secondary mt-1">{port.vulnerability_context || port.description}</p>
                        {port.banner && <p className="text-xs font-mono text-text-secondary mt-2 break-all">Banner: {port.banner}</p>}
                      </li>
                    ))}
                  </ul>
                )}
              </div>

              {/* SSL & Headers */}
              <div className="space-y-6">
                {scanResult.ssl && Object.keys(scanResult.ssl).length > 0 && (
                  <div className="bg-bg-secondary border border-border-subtle rounded-xl p-6">
                    <h2 className="text-lg font-bold text-text-primary mb-4 border-b border-border-subtle pb-2 flex gap-2"><Lock className="w-5 h-5 text-emerald-400" /> SSL/TLS Status</h2>
                    <ul className="space-y-1 text-sm">
                      <li className="flex justify-between gap-4"><span className="text-text-secondary">Status:</span> <span className="text-text-primary">{scanResult.ssl.status || "N/A"}</span></li>
                      <li className="flex justify-between gap-4"><span className="text-text-secondary">Issuer:</span> <span className="text-text-primary text-right">{scanResult.ssl.issuer || "N/A"}</span></li>
                      <li className="flex justify-between gap-4"><span className="text-text-secondary">Valid From:</span> <span className="text-text-primary">{scanResult.ssl.valid_from || "N/A"}</span></li>
                      <li className="flex justify-between gap-4"><span className="text-text-secondary">Valid To:</span> <span className="text-text-primary">{scanResult.ssl.expires || "N/A"}</span></li>
                      <li className="flex justify-between gap-4"><span className="text-text-secondary">Protocol:</span> <span className="text-text-primary">{scanResult.ssl.tls_version || "N/A"}</span></li>
                    </ul>
                    {scanResult.ssl.cdn_note && <p className="mt-3 text-xs text-amber-300">{scanResult.ssl.cdn_note}</p>}
                  </div>
                )}
                
                {Object.keys(headers).length > 0 && (
                  <div className="bg-bg-secondary border border-border-subtle rounded-xl p-6">
                    <h2 className="text-lg font-bold text-text-primary mb-4 border-b border-border-subtle pb-2 flex gap-2"><FileJson className="w-5 h-5 text-accent-amber" /> Security Headers</h2>
                    <div className="max-h-48 overflow-y-auto scrollbar-thin">
                      <ul className="space-y-2">
                        {Object.entries(headers).map(([key, val]: [string, any]) => (
                          <li key={key} className="text-sm">
                            <span className="font-semibold text-text-secondary block">{key}:</span>
                            <span className="text-text-primary font-mono text-xs break-all">{val}</span>
                          </li>
                        ))}
                      </ul>
                    </div>
                  </div>
                )}
              </div>
            </div>

            {/* Defensive Observations */}
            {findings.length > 0 && (
              <div className="bg-bg-secondary border border-border-subtle rounded-xl p-6">
                <h2 className="text-lg font-bold text-text-primary mb-4 border-b border-border-subtle pb-2 flex items-center gap-2">
                  <ShieldAlert className="w-5 h-5 text-accent-amber" /> Evidence-Backed Findings
                </h2>
                <ul className="grid grid-cols-1 lg:grid-cols-2 gap-3">
                  {findings.map((finding: any, i: number) => (
                    <li key={i} className="bg-bg-primary border border-border-subtle rounded-lg p-4">
                      <div className="flex items-center justify-between gap-3 mb-2">
                        <span className="font-semibold text-text-primary">{finding.type}</span>
                        <span className={cn(
                          "px-2 py-1 rounded text-xs font-bold",
                          finding.severity === "High" ? "bg-rose-500/10 text-rose-400" :
                          finding.severity === "Medium" ? "bg-amber-500/10 text-amber-300" :
                          "bg-accent-cyan/10 text-accent-cyan"
                        )}>{finding.severity}</span>
                      </div>
                      <p className="text-sm text-text-secondary">{finding.description}</p>
                      <p className="text-xs text-text-secondary mt-3">Evidence: {finding.evidence}</p>
                      <p className="text-xs text-text-secondary">Confidence: {Math.round((finding.confidence_score || 0) * 100)}% via {finding.detection_method}</p>
                    </li>
                  ))}
                </ul>
              </div>
            )}

            {findings.length === 0 && (
              <div className="bg-bg-secondary border border-border-subtle rounded-xl p-6 flex gap-3">
                <CheckCircle2 className="w-5 h-5 text-emerald-400 shrink-0" />
                <div>
                  <h2 className="font-bold text-text-primary">No evidence-backed issues in this safe scan</h2>
                  <p className="text-sm text-text-secondary mt-1">
                    The scanner did not observe exposed high-risk services or missing inspected web headers. This conclusion is limited to the configured non-intrusive checks.
                  </p>
                </div>
              </div>
            )}

            {scanResult.whois && (
              <div className="bg-bg-secondary border border-border-subtle rounded-xl p-6">
                <h2 className="text-lg font-bold text-text-primary mb-4 border-b border-border-subtle pb-2 flex gap-2">
                  <Server className="w-5 h-5 text-accent-violet" /> Domain Registration
                  {scanResult.whois.root_domain_queried && (
                    <span className="ml-2 text-xs font-normal text-text-secondary">(queried: {scanResult.whois.root_domain_queried})</span>
                  )}
                </h2>
                <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-sm">
                  <div><span className="text-text-secondary block">Registrar</span><span className="text-text-primary">{scanResult.whois.registrar || "N/A"}</span></div>
                  <div><span className="text-text-secondary block">Created</span><span className="text-text-primary">{scanResult.whois.creation_date || "N/A"}</span></div>
                  <div><span className="text-text-secondary block">Expires</span><span className="text-text-primary">{scanResult.whois.expiration_date || scanResult.whois.expiry_date || "N/A"}</span></div>
                </div>
              </div>
            )}
          </div>
        )}
      </div>
    </AuthGuard>
  );
}
