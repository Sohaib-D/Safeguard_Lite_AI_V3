"""
Deep Scanner Orchestrator — Safeguard-AI Lite.

Runs all scanner modules concurrently, normalizes results into a
standardized schema consumed by both the frontend and the
SecurityIntelligence AI analysis engine.
"""

import asyncio
import socket
import json
import whois
import httpx
from datetime import datetime, timezone
from urllib.parse import urlparse
from typing import Dict, Any, Optional

from backend.network.scanner_modules.port_scanner import scan_ports, COMMON_PORTS, CRITICAL_PORTS, HIGH_RISK_PORTS
from backend.network.scanner_modules.tls_scanner import scan_tls
from backend.network.scanner_modules.http_scanner import scan_http
from backend.network.scanner_modules.dns_scanner import scan_dns
from backend.network.scanner_modules.webapp_scanner import scan_webapp
from backend.network.scanner_modules.cve_scanner import scan_cve

from backend.services.ai_service import AIService


# ═══════════════════════════════════════════════════════════════════
# HELPERS
# ═══════════════════════════════════════════════════════════════════

async def safe_run(coro, timeout=60.0) -> dict:
    """Run a coroutine with a timeout; return error dict on failure."""
    try:
        return await asyncio.wait_for(coro, timeout=timeout)
    except Exception as e:
        return {"error": str(e), "failed": True, "findings": []}


def _clean_target(target: str) -> str:
    """Extract clean hostname from URL/domain input."""
    clean = target.strip()
    if clean.startswith("http://") or clean.startswith("https://"):
        parsed = urlparse(clean)
        clean = parsed.netloc
    if ":" in clean:
        clean = clean.split(":")[0]
    return clean.strip("/")


def _compute_risk_grade(score: int) -> str:
    """Map a 0–100 risk score to a letter grade (lower = safer)."""
    if score <= 10:
        return "A+"
    elif score <= 20:
        return "A"
    elif score <= 35:
        return "B"
    elif score <= 55:
        return "C"
    elif score <= 75:
        return "D"
    else:
        return "F"


# ═══════════════════════════════════════════════════════════════════
# WHOIS LOOKUP
# ═══════════════════════════════════════════════════════════════════

async def _fetch_whois(domain: str) -> dict:
    """Fetch WHOIS data for a domain."""
    def sync_whois():
        try:
            w = whois.whois(domain)
            creation = w.creation_date
            expiration = w.expiration_date
            if isinstance(creation, list):
                creation = creation[0]
            if isinstance(expiration, list):
                expiration = expiration[0]

            days_until_expiry = None
            domain_expiring_soon = False
            if expiration:
                delta = expiration - datetime.now()
                days_until_expiry = delta.days
                domain_expiring_soon = days_until_expiry < 30

            return {
                "status": "completed",
                "registrar": w.registrar or "N/A",
                "creation_date": str(creation) if creation else "N/A",
                "expiry_date": str(expiration) if expiration else "N/A",
                "days_until_expiry": days_until_expiry,
                "domain_expiring_soon": domain_expiring_soon,
                "name_servers": w.name_servers if w.name_servers else [],
                "org": w.org or "N/A",
                "country": w.country or "N/A",
            }
        except Exception as e:
            return {"status": "failed", "error": str(e)}

    return await asyncio.to_thread(sync_whois)


# ═══════════════════════════════════════════════════════════════════
# SCHEMA NORMALIZATION — Translates raw module dicts into the
# standardized shape expected by the frontend + SecurityIntelligence.
# ═══════════════════════════════════════════════════════════════════

def _normalize_ports(raw: dict) -> dict:
    """Normalize port_scanner output → `ports` section."""
    if raw.get("failed"):
        return {"status": "failed", "error": raw.get("error", "Unknown")}

    open_ports = raw.get("open_ports", [])
    banners = raw.get("banners", {})
    dangerous_open = []

    enriched = []
    for p in open_ports:
        port_num = p["port"]
        service = p.get("service", COMMON_PORTS.get(port_num, "Unknown"))
        banner = banners.get(port_num, "") if isinstance(banners.get(port_num), str) else banners.get(str(port_num), "")
        is_dangerous = port_num in CRITICAL_PORTS
        is_high_risk = port_num in HIGH_RISK_PORTS

        risk_desc = "Standard service port"
        if is_dangerous:
            risk_desc = f"CRITICAL — {service} is frequently targeted by attackers"
        elif is_high_risk:
            risk_desc = f"Elevated risk — {service} requires strong authentication"

        entry = {
            "port": port_num,
            "service": service,
            "banner": banner,
            "is_dangerous": is_dangerous,
            "is_high_risk": is_high_risk,
            "risk_description": risk_desc,
        }
        enriched.append(entry)
        if is_dangerous:
            dangerous_open.append(entry)

    return {
        "status": "completed",
        "open_ports": enriched,
        "open_count": len(enriched),
        "total_scanned": raw.get("total_scanned", 1024),
        "dangerous_open": dangerous_open,
        "scan_duration_seconds": raw.get("scan_duration_seconds", 0),
    }


def _normalize_ssl(raw: dict) -> dict:
    """Normalize tls_scanner output → `ssl` section."""
    if raw.get("failed") or raw.get("has_error"):
        return {
            "status": "failed",
            "error": raw.get("error_message") or raw.get("error", "TLS connection failed"),
        }

    # Compute health score
    health = 100
    findings = raw.get("findings", [])
    for f in findings:
        sev = f.get("severity", "").lower()
        if sev == "critical":
            health -= 30
        elif sev == "high":
            health -= 20
        elif sev == "medium":
            health -= 10
        elif sev == "low":
            health -= 5
    health = max(0, health)

    protocol_ver = raw.get("protocol_version", "Unknown")
    risk_level = "excellent"
    if "1.3" in protocol_ver:
        risk_level = "excellent"
    elif "1.2" in protocol_ver:
        risk_level = "ok"
    elif "1.1" in protocol_ver or "1.0" in protocol_ver:
        risk_level = "vulnerable"
    elif "SSL" in protocol_ver.upper():
        risk_level = "critical"

    cipher_name = raw.get("cipher_suite", "Unknown")

    return {
        "status": "completed",
        "health_score": health,
        "certificate": {
            "is_valid": raw.get("is_valid", False),
            "is_self_signed": raw.get("is_self_signed", False),
            "is_expired": raw.get("days_until_expiry", 1) <= 0,
            "days_remaining": raw.get("days_until_expiry", 0),
            "domain_match": raw.get("domain_match", False),
            "subject": {"commonName": "N/A"},
            "issuer": {"organizationName": "N/A"},
            "valid_from": "N/A",
            "valid_to": "N/A",
        },
        "protocol": {
            "version": protocol_ver,
            "risk_level": risk_level,
        },
        "cipher": {
            "name": cipher_name,
            "bits": 256 if "256" in cipher_name or "CHACHA" in cipher_name.upper() else 128,
            "strength": "strong" if health >= 70 else "weak",
        },
        "hsts_enabled": raw.get("hsts_enabled", False),
        "findings": findings,
    }


def _normalize_headers(raw: dict) -> dict:
    """Normalize http_scanner output → `http_headers` section."""
    if raw.get("failed"):
        return {"status": "failed", "error": raw.get("error", "Unknown")}

    EXPECTED_HEADERS = [
        "Content-Security-Policy",
        "X-Frame-Options",
        "X-Content-Type-Options",
        "Strict-Transport-Security",
        "Referrer-Policy",
        "Permissions-Policy",
    ]
    missing = raw.get("missing_security_headers", [])
    found = raw.get("headers_found", {})

    header_analysis = {}
    critical_missing = 0
    for h in EXPECTED_HEADERS:
        h_lower = h.lower()
        is_present = h not in missing
        risk = "Low"
        if h in ("Content-Security-Policy", "Strict-Transport-Security"):
            risk = "Critical"
        elif h in ("X-Frame-Options",):
            risk = "High"
        elif h in ("X-Content-Type-Options", "Referrer-Policy"):
            risk = "Medium"

        if not is_present and risk in ("Critical", "High"):
            critical_missing += 1

        header_analysis[h] = {
            "is_present": is_present,
            "value": found.get(h.lower()) or found.get(h, None),
            "risk_level": risk,
        }

    return {
        "status": "completed",
        "response_status": 200,
        "headers": header_analysis,
        "raw_headers": found,
        "total_missing": len(missing),
        "missing_critical_count": critical_missing,
        "cors_issues": raw.get("cors_issues", []),
        "cookie_issues": raw.get("cookie_issues", []),
        "dangerous_methods": raw.get("dangerous_methods", []),
        "sensitive_files": raw.get("sensitive_files_found", []),
        "findings": raw.get("findings", []),
    }


def _normalize_dns(raw: dict) -> dict:
    """Normalize dns_scanner output → `dns` section."""
    if raw.get("failed"):
        return {"status": "failed", "error": raw.get("error", "Unknown")}

    return {
        "status": "completed",
        "a_records": [],  # dns_scanner doesn't return A records explicitly
        "mx_records": raw.get("mx_records", []),
        "ns_records": raw.get("ns_records", []),
        "txt_records": [],
        "spf_status": raw.get("spf_status", "Unknown"),
        "dkim_found": raw.get("dkim_found", False),
        "dmarc_policy": raw.get("dmarc_policy", "Unknown"),
        "dnssec_enabled": raw.get("dnssec_enabled", False),
        "zone_transfer": {
            "successful": raw.get("zone_transfer_possible", False),
        },
        "subdomains_found": raw.get("subdomains_found", []),
        "takeover_risks": raw.get("takeover_risks", []),
        "findings": raw.get("findings", []),
    }


def _normalize_technologies(raw_http: dict, raw_webapp: dict) -> dict:
    """Build `technologies` section from HTTP + webapp scanner outputs."""
    if raw_webapp.get("failed") and raw_http.get("failed"):
        return {"status": "failed", "error": "Scan failed"}

    found_headers = raw_http.get("headers_found", {}) if not raw_http.get("failed") else {}
    server = None
    framework = None
    for k, v in found_headers.items():
        kl = k.lower()
        if kl == "server":
            server = v
        elif kl == "x-powered-by":
            framework = v

    cms = raw_webapp.get("cms_detected") if not raw_webapp.get("failed") else None

    # Detect CDN/WAF from headers
    cdn = None
    waf_detected = False
    waf_name = None
    for k, v in found_headers.items():
        kl = k.lower()
        vl = str(v).lower() if v else ""
        if "cf-ray" in kl or "cloudflare" in vl:
            cdn = "Cloudflare"
            waf_detected = True
            waf_name = "Cloudflare WAF"
        elif "x-cdn" in kl or "x-cache" in kl:
            cdn = v
        elif "x-sucuri" in kl:
            waf_detected = True
            waf_name = "Sucuri WAF"

    version_risks = []
    if server and any(c.isdigit() for c in server):
        version_risks.append({
            "component": "Server",
            "detail": f"Server header exposes version: {server}",
        })
    if framework:
        version_risks.append({
            "component": "Framework",
            "detail": f"X-Powered-By exposes technology: {framework}",
        })

    return {
        "status": "completed",
        "web_server": server,
        "backend_framework": framework,
        "cms": cms,
        "cdn": cdn,
        "waf_detected": waf_detected,
        "waf_name": waf_name,
        "version_risks": version_risks,
        "csrf_issues": raw_webapp.get("csrf_issues", []) if not raw_webapp.get("failed") else [],
        "error_disclosure": raw_webapp.get("error_disclosure", False) if not raw_webapp.get("failed") else False,
        "mixed_content": raw_webapp.get("mixed_content_found", False) if not raw_webapp.get("failed") else False,
        "dangerous_js": raw_webapp.get("dangerous_js_patterns", []) if not raw_webapp.get("failed") else [],
    }


def _normalize_full_result(
    target: str,
    clean_target: str,
    resolved_ip: Optional[str],
    quick: bool,
    raw_ports: dict,
    raw_tls: dict,
    raw_http: dict,
    raw_dns: dict,
    raw_webapp: dict,
    raw_cve: dict,
    raw_whois: dict,
) -> dict:
    """
    Translate all raw module outputs into the standardized schema
    consumed by the frontend and SecurityIntelligence engine.
    """
    ports = _normalize_ports(raw_ports)
    ssl = _normalize_ssl(raw_tls)
    http_headers = _normalize_headers(raw_http)
    dns = _normalize_dns(raw_dns)
    technologies = _normalize_technologies(raw_http, raw_webapp)
    whois_data = raw_whois

    # ── Aggregate all findings for scoring ──
    all_findings = []
    for section in [raw_ports, raw_tls, raw_http, raw_dns, raw_webapp, raw_cve]:
        if section and not section.get("failed"):
            all_findings.extend(section.get("findings", []))

    # ── Generate structural findings from normalized data ──
    # SSL failure — Confirmed observation
    if ssl.get("status") == "failed":
        all_findings.append({
            "severity": "High",
            "title": "SSL/TLS Not Properly Configured",
            "category": "Security Weakness",
            "description": f"SSL/TLS connection could not be established, indicating misconfiguration or missing certificate.",
            "technical_detail": f"Error: {ssl.get('error', 'Unknown')}",
            "confidence_score": 0.95,
            "evidence": "TLS handshake failed during passive connection attempt",
            "detection_method": "TLS connect probe",
            "severity_justification": "Without HTTPS, all traffic is susceptible to interception",
            "exploit_verified": False,
            "remediation": "Install and configure a valid SSL certificate. Use Let's Encrypt for free certificates.",
            "references": ["A02:2021 – Cryptographic Failures"],
        })

    # Dangerous open ports — Confirmed observation
    for dp in ports.get("dangerous_open", []):
        all_findings.append({
            "severity": "High",
            "title": f"Externally Accessible Service: {dp['port']} ({dp['service']})",
            "category": "Confirmed Finding",
            "description": f"Port {dp['port']} ({dp['service']}) is externally reachable. This service is frequently targeted in attacks.",
            "confidence_score": 0.95,
            "evidence": f"TCP connection to port {dp['port']} succeeded",
            "detection_method": "TCP connect scan",
            "severity_justification": dp.get("risk_description", "Service commonly targeted by automated scanners"),
            "exploit_verified": False,
            "remediation": f"Restrict access to port {dp['port']} via firewall rules or VPN if not publicly needed.",
        })

    # Missing critical security headers — Security Weakness
    if http_headers.get("status") == "completed":
        mc = http_headers.get("missing_critical_count", 0)
        if mc > 0:
            all_findings.append({
                "severity": "Medium",
                "title": f"{mc} Critical Security Header(s) Missing",
                "category": "Security Weakness",
                "description": "Absence of headers such as CSP or HSTS reduces browser-side mitigation against common attacks.",
                "confidence_score": 0.96,
                "evidence": "HTTP response headers inspected; critical headers absent",
                "detection_method": "HTTP header analysis",
                "severity_justification": "Risk depends on existence of exploitable vectors (e.g., XSS sinks)",
                "exploit_verified": False,
                "remediation": "Configure Content-Security-Policy, Strict-Transport-Security, and X-Frame-Options headers.",
                "references": ["A05:2021 – Security Misconfiguration"],
            })

    # Domain expiring soon — Informational
    if whois_data.get("status") == "completed" and whois_data.get("domain_expiring_soon"):
        all_findings.append({
            "severity": "High",
            "title": "Domain Registration Expiring Soon",
            "category": "Informational",
            "description": f"Domain registration expires in {whois_data.get('days_until_expiry', '?')} days. Failure to renew could lead to domain hijacking.",
            "confidence_score": 0.90,
            "evidence": "WHOIS expiry date queried",
            "detection_method": "WHOIS lookup",
            "severity_justification": "Expired domains can be re-registered by attackers",
            "exploit_verified": False,
            "remediation": "Renew the domain registration and enable auto-renewal.",
        })

    critical = sum(1 for f in all_findings if str(f.get("severity", "")).lower() == "critical")
    high = sum(1 for f in all_findings if str(f.get("severity", "")).lower() == "high")
    medium = sum(1 for f in all_findings if str(f.get("severity", "")).lower() == "medium")
    low = sum(1 for f in all_findings if str(f.get("severity", "")).lower() == "low")

    # Risk score with confidence weighting (higher = worse)
    raw_score = (critical * 25) + (high * 15) + (medium * 8) + (low * 3)
    # Apply average confidence as a weight — lower confidence = lower score
    avg_confidence = 0.85  # baseline for passive recon
    if all_findings:
        scores = [f.get("confidence_score", 0.7) for f in all_findings]
        avg_confidence = sum(scores) / len(scores)
    risk_score = min(100, int(raw_score * avg_confidence))
    risk_grade = _compute_risk_grade(risk_score)

    # Critical findings (human-readable)
    critical_findings = [
        f"[{f.get('severity')}] {f.get('title', 'Unknown')}: {f.get('description', '')[:120]}"
        for f in all_findings
        if str(f.get("severity", "")).lower() in ("critical", "high")
    ]

    return {
        "target": target,
        "clean_target": clean_target,
        "resolved_ip": resolved_ip,
        "quick_scan": quick,
        "scan_timestamp": datetime.now(timezone.utc).isoformat(),

        # ── Standardized top-level keys ──
        "overall_risk_score": risk_score,
        "risk_grade": risk_grade,
        "severity_counts": {
            "critical": critical,
            "high": high,
            "medium": medium,
            "low": low,
        },
        "critical_findings": critical_findings,
        "total_findings": len(all_findings),

        # ── Standardized sections ──
        "ports": ports,
        "ssl": ssl,
        "http_headers": http_headers,
        "dns": dns,
        "technologies": technologies,
        "whois": whois_data,
        "cve_scan": raw_cve if not raw_cve.get("failed") else {"findings": []},

        # ── Raw module data (for export / debugging) ──
        "raw_modules": {
            "port_scan": raw_ports,
            "tls_scan": raw_tls,
            "http_scan": raw_http,
            "dns_scan": raw_dns,
            "webapp_scan": raw_webapp,
            "cve_scan": raw_cve,
        },
    }


# ═══════════════════════════════════════════════════════════════════
# MAIN SCAN ORCHESTRATOR
# ═══════════════════════════════════════════════════════════════════

async def run_deep_scan(target: str, quick: bool = True) -> dict:
    """
    Run all scanner modules concurrently, normalize results,
    and return a standardized result dictionary.
    """
    clean_target = _clean_target(target)

    # Resolve IP
    resolved_ip = None
    try:
        resolved_ip = await asyncio.to_thread(socket.gethostbyname, clean_target)
    except Exception:
        pass

    # Run all modules concurrently
    # Use resolved IP for port scanning (bypasses CDN port filtering),
    # matching the Active Scanner's approach.  Fall back to domain if
    # DNS resolution failed.
    port_scan_target = resolved_ip if resolved_ip else clean_target
    port_task = safe_run(scan_ports(port_scan_target, quick=quick), timeout=90)
    tls_task = safe_run(scan_tls(clean_target, port=443))
    http_task = safe_run(scan_http(target))
    dns_task = safe_run(scan_dns(clean_target))
    webapp_task = safe_run(scan_webapp(target))
    whois_task = safe_run(_fetch_whois(clean_target), timeout=15)

    port_res, tls_res, http_res, dns_res, webapp_res, whois_res = await asyncio.gather(
        port_task, tls_task, http_task, dns_task, webapp_task, whois_task
    )

    # CVE scan needs banners + detected software (synchronous)
    banners = port_res.get("banners", {}) if not port_res.get("failed") else {}
    software = []
    if not webapp_res.get("failed"):
        cms = webapp_res.get("cms_detected")
        if cms:
            software.append(cms)
    if not http_res.get("failed"):
        headers = http_res.get("headers_found", {})
        for key in ("server", "x-powered-by", "x-aspnet-version"):
            val = headers.get(key)
            if val:
                software.append(val)

    cve_res = scan_cve(banners, software)

    # Normalize into standardized schema
    result = _normalize_full_result(
        target=target,
        clean_target=clean_target,
        resolved_ip=resolved_ip,
        quick=quick,
        raw_ports=port_res,
        raw_tls=tls_res,
        raw_http=http_res,
        raw_dns=dns_res,
        raw_webapp=webapp_res,
        raw_cve=cve_res,
        raw_whois=whois_res,
    )

    return result


def run_scan_sync(target: str, quick: bool = True) -> dict:
    return asyncio.run(run_deep_scan(target, quick))


class DeepScanner:
    """Backward-compatibility wrapper."""

    async def scan(self, target: str, quick: bool = True) -> dict:
        return await run_deep_scan(target, quick)