"""
Enterprise Deep Security Scanner for Safeguard-AI Lite.

The scanner performs non-intrusive reconnaissance only. Every module is
independent: DNS, ports, HTTP headers, TLS, CORS, WHOIS, technology
fingerprinting, SSH banner analysis, and NVD CVE cross-reference can fail
without blocking the rest of the report.
"""

from __future__ import annotations

import asyncio
import re
import socket
import ssl
import time
from datetime import datetime, timedelta
from typing import Any
from urllib.parse import urlparse

import dns.resolver
import httpx
import whois

from backend.network.scanner_modules.port_scanner import (
    COMMON_PORTS,
    CRITICAL_PORTS,
    HIGH_RISK_PORTS,
    scan_ports,
)


_CVE_CACHE: dict[str, tuple[datetime, list[dict[str, Any]]]] = {}

REQUIRED_HEADERS = {
    "strict-transport-security": (
        "High",
        "Missing HSTS",
        "Without HSTS, SSL stripping attacks are possible.",
        "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
        15,
    ),
    "content-security-policy": (
        "High",
        "Missing Content-Security-Policy",
        "Increases XSS impact because the browser has no content restrictions.",
        "Deploy CSP. Start with report-only mode, then enforce a policy tailored to the application.",
        12,
    ),
    "x-frame-options": (
        "Medium",
        "Missing X-Frame-Options",
        "Clickjacking may be possible via iframe embedding.",
        "Add: X-Frame-Options: DENY, or use CSP frame-ancestors.",
        8,
    ),
    "x-content-type-options": (
        "Medium",
        "Missing X-Content-Type-Options",
        "Browsers may MIME-sniff responses, increasing content confusion risk.",
        "Add: X-Content-Type-Options: nosniff",
        5,
    ),
    "referrer-policy": (
        "Low",
        "Missing Referrer-Policy",
        "URL data may leak to third parties through the Referer header.",
        "Add: Referrer-Policy: strict-origin-when-cross-origin",
        3,
    ),
    "permissions-policy": (
        "Low",
        "Missing Permissions-Policy",
        "Browser feature access by third-party scripts is not explicitly constrained.",
        "Add: Permissions-Policy: geolocation=(), camera=(), microphone=()",
        3,
    ),
}

DISCLOSURE_HEADERS = {
    "server": (
        "Medium",
        "Server Version Disclosed",
        "Reveals web server software/version and can help attackers target known CVEs.",
        "nginx: server_tokens off; Apache: ServerTokens Prod",
    ),
    "x-powered-by": (
        "Medium",
        "Technology Stack Disclosed via X-Powered-By",
        "Reveals backend technology and can help attackers target framework-specific weaknesses.",
        'PHP: expose_php=Off; Express: app.disable("x-powered-by")',
    ),
}


def _module_error(module: str, exc: Exception | str) -> dict[str, Any]:
    reason_key = exc if isinstance(exc, str) else type(exc).__name__
    friendly_map = {
        "ConnectError": "Connection refused",
        "ConnectTimeout": "Connection timed out",
        "ReadTimeout": "Read timed out",
        "TimeoutError": "Connection timed out",
        "gaierror": "DNS resolution failed",
        "SSLError": "TLS handshake failed",
        "HTTPError": "HTTP analysis could not be completed",
        "ProxyError": "Proxy connection failed",
        "TooManyRedirects": "Too many redirects encountered",
    }
    module_label = module.replace("_", " ").title()
    default_reason = f"{module_label} analysis could not be completed"
    friendly = friendly_map.get(str(reason_key), default_reason)
    return {"status": "error", "module": module, "reason": friendly, "findings": []}


def clean_target(raw_target: str) -> str:
    target = raw_target.strip()
    if target.startswith(("http://", "https://")):
        parsed = urlparse(target)
        target = parsed.netloc
    if "@" in target:
        target = target.rsplit("@", 1)[-1]
    target = target.rstrip("/").split("/")[0]
    if ":" in target and not re.match(r"^\d{1,3}(\.\d{1,3}){3}$", target):
        target = target.split(":", 1)[0]
    if target.startswith("www."):
        target = target[4:]
    return target


def is_ip_address(target: str) -> bool:
    try:
        socket.inet_aton(target)
        return bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", target))
    except OSError:
        return False


def compute_grade(score: int | float) -> str:
    score = int(score)
    if score >= 90:
        return "A+"
    if score >= 80:
        return "A"
    if score >= 70:
        return "B"
    if score >= 60:
        return "C"
    if score >= 50:
        return "D"
    if score >= 40:
        return "E"
    return "F"


assert compute_grade(20) == "F"
assert compute_grade(95) == "A+"


def _finding(
    severity: str,
    title: str,
    description: str,
    recommendation: str,
    evidence: str = "",
    confidence: int = 90,
    category: str = "configuration",
    detection_method: str = "passive reconnaissance",
) -> dict[str, Any]:
    return {
        "severity": severity,
        "title": title,
        "description": description,
        "recommendation": recommendation,
        "remediation": recommendation,
        "evidence": evidence,
        "confidence": confidence,
        "confidence_score": round(confidence / 100, 2),
        "category": category,
        "detection_method": detection_method,
        "exploit_verified": False,
        "passive_only": True,
    }


async def check_spf(domain: str, is_ip: bool = False) -> dict[str, Any]:
    if is_ip:
        return {"skipped": True, "reason": "Target is an IP, DNS checks skipped"}

    def resolve_spf() -> dict[str, Any]:
        try:
            answers = dns.resolver.resolve(domain, "TXT")
            records = [r.to_text().strip('"') for r in answers]
            record = next((r for r in records if "v=spf1" in r.lower()), None)
            return {"present": record is not None, "record": record}
        except Exception:
            return {"present": False, "record": None}

    return await asyncio.to_thread(resolve_spf)


async def check_dmarc(domain: str, is_ip: bool = False) -> dict[str, Any]:
    if is_ip:
        return {"skipped": True, "reason": "Target is an IP, DNS checks skipped"}

    def resolve_dmarc() -> dict[str, Any]:
        try:
            answers = dns.resolver.resolve(f"_dmarc.{domain}", "TXT")
            record = answers[0].to_text().strip('"')
            return {"present": True, "record": record}
        except Exception:
            return {"present": False, "record": None}

    return await asyncio.to_thread(resolve_dmarc)


async def dns_scan(domain: str, is_ip: bool = False) -> dict[str, Any]:
    if is_ip:
        skipped = {"skipped": True, "reason": "Target is an IP, DNS checks skipped"}
        return {
            "status": "completed",
            "module": "dns",
            "a_records": [],
            "mx_records": [],
            "ns_records": [],
            "spf": skipped,
            "dmarc": skipped,
            "findings": [],
        }

    def resolve_records(record_type: str) -> list[str]:
        try:
            return [r.to_text().strip('"') for r in dns.resolver.resolve(domain, record_type)]
        except Exception:
            return []

    try:
        a_task = asyncio.to_thread(resolve_records, "A")
        mx_task = asyncio.to_thread(resolve_records, "MX")
        ns_task = asyncio.to_thread(resolve_records, "NS")
        spf_task = check_spf(domain)
        dmarc_task = check_dmarc(domain)
        a_records, mx_records, ns_records, spf, dmarc = await asyncio.gather(
            a_task, mx_task, ns_task, spf_task, dmarc_task
        )
        findings: list[dict[str, Any]] = []
        if not spf.get("present"):
            findings.append(
                _finding(
                    "Low",
                    "Missing SPF Record",
                    "No SPF record was observed. SPF helps receiving mail servers identify authorized senders.",
                    "Publish an SPF TXT record that includes all legitimate outbound mail providers.",
                    evidence="TXT lookup did not return a v=spf1 record",
                    confidence=90,
                    category="dns",
                    detection_method="DNS TXT lookup",
                )
            )
        if not dmarc.get("present"):
            findings.append(
                _finding(
                    "Low",
                    "Missing DMARC Record",
                    "No DMARC policy was observed. DMARC helps reduce domain spoofing and phishing abuse.",
                    "Publish a DMARC TXT record at _dmarc with at least p=none, then move toward quarantine or reject.",
                    evidence="_dmarc TXT lookup did not return a policy",
                    confidence=90,
                    category="dns",
                    detection_method="DNS TXT lookup",
                )
            )

        return {
            "status": "completed",
            "module": "dns",
            "a_records": a_records,
            "mx_records": mx_records,
            "ns_records": ns_records,
            "spf": spf,
            "dmarc": dmarc,
            "findings": findings,
        }
    except Exception as exc:
        return _module_error("dns", exc)


async def port_scan(target: str, quick: bool = True) -> dict[str, Any]:
    try:
        raw = await scan_ports(target, quick=quick)
        banners = raw.get("banners", {})
        open_ports = []
        dangerous_ports = []
        findings = list(raw.get("findings", []))

        for port_info in raw.get("open_ports", []):
            port = int(port_info.get("port", 0))
            enriched = {
                "port": port,
                "service": port_info.get("service") or COMMON_PORTS.get(port, "Unknown"),
                "banner": banners.get(port) or banners.get(str(port), ""),
                "is_dangerous": port in CRITICAL_PORTS,
                "is_high_risk": port in HIGH_RISK_PORTS,
            }
            if enriched["is_dangerous"]:
                dangerous_ports.append(enriched)
            open_ports.append(enriched)

        return {
            "status": "completed",
            "module": "ports",
            "open_ports": open_ports,
            "dangerous_ports": dangerous_ports,
            "critical_ports": raw.get("critical_ports", []),
            "high_risk_ports": raw.get("high_risk_ports", []),
            "banners": banners,
            "open_count": len(open_ports),
            "total_open": len(open_ports),
            "total_scanned": raw.get("total_scanned", 0),
            "scan_duration_seconds": raw.get("scan_duration_seconds", 0),
            "findings": findings,
        }
    except Exception as exc:
        return _module_error("ports", exc)


async def http_headers_scan(url: str) -> dict[str, Any]:
    try:
        async with httpx.AsyncClient(timeout=10, follow_redirects=True, verify=False) as client:
            response = await client.get(url)
            headers_raw = dict(response.headers)
            headers = {k.lower(): v for k, v in headers_raw.items()}
            findings: list[dict[str, Any]] = []
            missing_count = 0
            critical_missing = 0
            score_deductions = 0

            for header, (severity, title, description, recommendation, weight) in REQUIRED_HEADERS.items():
                if header not in headers:
                    missing_count += 1
                    score_deductions += weight
                    if severity in ("Critical", "High"):
                        critical_missing += 1
                    findings.append(
                        _finding(
                            severity,
                            title,
                            description,
                            recommendation,
                            evidence=f"{header} header absent from {response.url}",
                            confidence=95,
                            category="headers",
                            detection_method="HTTP header inspection",
                        )
                    )

            for header, (severity, title, description, recommendation) in DISCLOSURE_HEADERS.items():
                value = headers.get(header)
                if value and (header != "server" or re.search(r"\d", value)):
                    findings.append(
                        _finding(
                            severity,
                            title,
                            description,
                            recommendation,
                            evidence=f"{header}: {value}",
                            confidence=95,
                            category="information_disclosure",
                            detection_method="HTTP header inspection",
                        )
                    )

            x_xss = headers.get("x-xss-protection")
            if x_xss and x_xss.strip() != "0":
                findings.append(
                    _finding(
                        "Info",
                        "Outdated X-XSS-Protection Header Present",
                        "X-XSS-Protection is obsolete and can introduce browser-specific issues.",
                        "Remove X-XSS-Protection and rely on a strong Content-Security-Policy.",
                        evidence=f"x-xss-protection: {x_xss}",
                        confidence=95,
                        category="headers",
                        detection_method="HTTP header inspection",
                    )
                )

            return {
                "status": "completed",
                "module": "http_headers",
                "headers_raw": headers_raw,
                "headers": headers_raw,
                "findings": findings,
                "missing_count": missing_count,
                "critical_missing": critical_missing,
                "score_deductions": score_deductions,
                "url_scanned": str(response.url),
                "response_status": response.status_code,
            }
    except Exception as exc:
        error = _module_error("http_headers", exc)
        error.update({"missing_count": 0, "critical_missing": 0, "score_deductions": 0})
        return error


async def cors_check(url: str) -> dict[str, Any]:
    evil = "https://evil-attacker.example.com"
    try:
        async with httpx.AsyncClient(timeout=8, follow_redirects=True, verify=False) as client:
            response = await client.get(url, headers={"Origin": evil})
            acao = response.headers.get("access-control-allow-origin", "")
            acac = response.headers.get("access-control-allow-credentials", "")
            issues: list[dict[str, Any]] = []
            if acao == "*":
                issues.append(
                    _finding(
                        "Medium",
                        "CORS Wildcard Origin",
                        "Any website can make cross-origin requests and read responses where CORS applies.",
                        "Replace wildcard origin with an explicit allowlist of trusted origins.",
                        evidence="Access-Control-Allow-Origin: *",
                        category="cors",
                        detection_method="CORS probe",
                    )
                )
            if acao == evil:
                issues.append(
                    _finding(
                        "High",
                        "CORS Reflects Arbitrary Origin",
                        "Server reflects the requesting Origin header verbatim.",
                        "Implement a strict origin whitelist and reject untrusted origins.",
                        evidence=f"Reflected Origin: {evil}",
                        category="cors",
                        detection_method="CORS probe",
                    )
                )
            if (acao == "*" or acao == evil) and "true" in acac.lower():
                issues.append(
                    _finding(
                        "Critical",
                        "CORS: Credentials Exposed to Arbitrary Origin",
                        "Allow-Credentials:true with permissive origin allows authenticated cross-origin requests.",
                        "Never combine Allow-Credentials:true with wildcard or reflected origins.",
                        evidence=f"ACAO: {acao}; ACAC: {acac}",
                        category="cors",
                        detection_method="CORS probe",
                    )
                )
            return {"status": "completed", "module": "cors", "acao": acao, "credentials": acac, "issues": issues}
    except Exception as exc:
        error = _module_error("cors", exc)
        error["issues"] = []
        return error


async def tls_deep_check(hostname: str) -> dict[str, Any]:
    results: dict[str, Any] = {
        "status": "completed",
        "module": "ssl",
        "protocols": {},
        "cipher": None,
        "cert": {},
        "issues": [],
        "findings": [],
    }

    protocol_versions = []
    if hasattr(ssl, "TLSVersion"):
        protocol_versions = [
            ("TLS 1.0", ssl.TLSVersion.TLSv1),
            ("TLS 1.1", ssl.TLSVersion.TLSv1_1),
            ("TLS 1.2", ssl.TLSVersion.TLSv1_2),
            ("TLS 1.3", ssl.TLSVersion.TLSv1_3),
        ]

    def test_protocol(name: str, version: ssl.TLSVersion) -> str:
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.maximum_version = version
            ctx.minimum_version = version
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((hostname, 443), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname):
                    return "supported"
        except Exception:
            return "not supported"

    for name, version in protocol_versions:
        status = await asyncio.to_thread(test_protocol, name, version)
        results["protocols"][name] = status
        if status == "supported" and name in ("TLS 1.0", "TLS 1.1"):
            results["issues"].append(
                _finding(
                    "High",
                    f"{name} Enabled - Deprecated Protocol",
                    f"{name} is deprecated per RFC 8996 and should be disabled.",
                    "nginx: ssl_protocols TLSv1.2 TLSv1.3; Apache: SSLProtocol -all +TLSv1.2 +TLSv1.3",
                    evidence=f"{name} handshake succeeded",
                    category="tls",
                    detection_method="TLS protocol negotiation",
                )
            )

    def get_certificate() -> dict[str, Any]:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((hostname, 443), timeout=8) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
                cert_info: dict[str, Any] = {}
                days_left = 999
                if cert and cert.get("notAfter"):
                    expiry = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
                    days_left = (expiry - datetime.utcnow()).days
                    cert_info = {
                        "issuer": dict(x[0] for x in cert.get("issuer", [])),
                        "expires": cert["notAfter"],
                        "days_until_expiry": days_left,
                        "san": [x[1] for x in cert.get("subjectAltName", [])],
                    }
                return {
                    "cipher": {"name": cipher[0], "protocol": cipher[1], "bits": cipher[2]} if cipher else None,
                    "cert": cert_info,
                    "days_left": days_left,
                }

    try:
        cert_data = await asyncio.to_thread(get_certificate)
        results["cipher"] = cert_data.get("cipher")
        results["cert"] = cert_data.get("cert", {})
        days_left = cert_data.get("days_left", 999)
        if days_left < 0:
            results["issues"].append(
                _finding(
                    "Critical",
                    "SSL Certificate Expired",
                    f"Certificate expired {abs(days_left)} days ago. Visitors will see browser errors.",
                    "Renew immediately: certbot renew --force-renewal",
                    evidence=f"days_until_expiry={days_left}",
                    category="tls",
                    detection_method="certificate inspection",
                )
            )
        elif days_left < 14:
            results["issues"].append(
                _finding(
                    "High",
                    f"Certificate Expiring in {days_left} Days",
                    "Imminent expiry will cause browser warnings and broken HTTPS.",
                    "Renew now: certbot renew --force-renewal",
                    evidence=f"days_until_expiry={days_left}",
                    category="tls",
                    detection_method="certificate inspection",
                )
            )
        elif days_left < 30:
            results["issues"].append(
                _finding(
                    "Medium",
                    f"Certificate Expiring in {days_left} Days",
                    "Certificate renewal is due soon.",
                    "Schedule renewal this week.",
                    evidence=f"days_until_expiry={days_left}",
                    category="tls",
                    detection_method="certificate inspection",
                )
            )
    except Exception as exc:
        results["status"] = "error"
        results["reason"] = "No valid SSL/TLS certificate"
        results["cert_error"] = type(exc).__name__
        results["issues"].append(
            _finding(
                "High",
                "No Valid SSL/TLS Certificate",
                "TLS certificate details could not be validated from port 443.",
                "Install and configure a valid certificate for the target hostname.",
                evidence="TLS certificate probe failed",
                category="tls",
                detection_method="TLS certificate probe",
            )
        )

    results["findings"] = results["issues"]
    return results


async def whois_scan(domain: str, is_ip: bool = False) -> dict[str, Any]:
    if is_ip:
        return {"status": "skipped", "module": "whois", "reason": "Target is an IP, WHOIS domain checks skipped"}

    def run_whois() -> dict[str, Any]:
        try:
            w = whois.whois(domain)
            creation = w.creation_date[0] if isinstance(w.creation_date, list) else w.creation_date
            expiry = w.expiration_date[0] if isinstance(w.expiration_date, list) else w.expiration_date
            days_until_expiry = None
            if expiry:
                days_until_expiry = (expiry - datetime.utcnow()).days
            return {
                "status": "completed",
                "module": "whois",
                "registrar": w.registrar or "N/A",
                "creation_date": str(creation) if creation else "N/A",
                "expiry_date": str(expiry) if expiry else "N/A",
                "days_until_expiry": days_until_expiry,
                "name_servers": w.name_servers or [],
                "org": w.org or "N/A",
                "country": w.country or "N/A",
            }
        except Exception as exc:
            return _module_error("whois", exc)

    return await asyncio.to_thread(run_whois)


async def tech_fingerprint(url: str) -> dict[str, Any]:
    try:
        async with httpx.AsyncClient(timeout=8, follow_redirects=True, verify=False) as client:
            response = await client.get(url)
            headers = {k.lower(): v for k, v in response.headers.items()}
            technologies: list[dict[str, Any]] = []
            server = headers.get("server")
            powered_by = headers.get("x-powered-by")
            if server:
                technologies.append({"name": "Web Server", "value": server, "version": _extract_first_version(server)})
            if powered_by:
                technologies.append({"name": "X-Powered-By", "value": powered_by, "version": _extract_first_version(powered_by)})
            return {
                "status": "completed",
                "module": "technologies",
                "server": server,
                "x_powered_by": powered_by,
                "technologies": technologies,
            }
    except Exception as exc:
        error = _module_error("technologies", exc)
        error["technologies"] = []
        return error


def _extract_first_version(value: str | None) -> str | None:
    if not value:
        return None
    match = re.search(r"(\d+(?:\.\d+){1,3})", value)
    return match.group(1) if match else None


def parse_ssh_banner(banner: str) -> dict[str, Any]:
    result: dict[str, Any] = {"raw": banner, "software": None, "version": None, "os": None, "eol": False}
    if "OpenSSH_" in banner:
        result["software"] = "OpenSSH"
        result["version"] = banner.split("OpenSSH_")[1].split(" ")[0]

    ubuntu_map = {
        "2ubuntu2": ("Ubuntu 14.04 LTS (Trusty)", True),
        "2ubuntu1": ("Ubuntu 16.04 LTS (Xenial)", True),
        "1ubuntu3": ("Ubuntu 18.04 LTS (Bionic)", True),
        "3ubuntu0": ("Ubuntu 20.04 LTS (Focal)", False),
        "3ubuntu13": ("Ubuntu 22.04 LTS (Jammy)", False),
    }
    for pkg, (name, eol) in ubuntu_map.items():
        if pkg in banner:
            result["os"] = name
            result["eol"] = eol
            break
    return result


async def fetch_cves(product: str, version: str) -> list[dict[str, Any]]:
    key = f"{product}:{version}"
    if key in _CVE_CACHE:
        ts, data = _CVE_CACHE[key]
        if datetime.utcnow() - ts < timedelta(hours=24):
            return data

    try:
        async with httpx.AsyncClient(timeout=10) as client:
            response = await client.get(
                "https://services.nvd.nist.gov/rest/json/cves/2.0",
                params={"keywordSearch": f"{product} {version}", "resultsPerPage": 10},
            )
            response.raise_for_status()
            data = response.json()
            cves = []
            for item in data.get("vulnerabilities", []):
                cve = item.get("cve", {})
                metrics = cve.get("metrics", {})
                cvss = (
                    metrics.get("cvssMetricV31", [{}])[0].get("cvssData", {})
                    or metrics.get("cvssMetricV30", [{}])[0].get("cvssData", {})
                    or metrics.get("cvssMetricV2", [{}])[0].get("cvssData", {})
                )
                score = float(cvss.get("baseScore", 0) or 0)
                if score >= 6.0:
                    cve_id = cve.get("id")
                    descriptions = cve.get("descriptions", [{}])
                    cves.append(
                        {
                            "cve_id": cve_id,
                            "cvss_score": score,
                            "severity": cvss.get("baseSeverity", "UNKNOWN"),
                            "description": descriptions[0].get("value", "") if descriptions else "",
                            "published": cve.get("published", ""),
                            "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                        }
                    )
            _CVE_CACHE[key] = (datetime.utcnow(), cves)
            return cves
    except Exception:
        return []


def calculate_security_score(all_results: dict[str, Any]) -> tuple[int, str, list[dict[str, Any]]]:
    score = 100
    deductions: list[dict[str, Any]] = []

    def deduct(points: int, reason: str) -> None:
        nonlocal score
        if points <= 0:
            return
        score -= points
        deductions.append({"reason": reason, "points": points})

    ssl_result = all_results.get("ssl", {})
    if ssl_result.get("status") == "error" or ssl_result.get("cert_error"):
        deduct(20, "No valid SSL/TLS certificate")
    if ssl_result.get("protocols", {}).get("TLS 1.0") == "supported":
        deduct(10, "TLS 1.0 enabled")
    if ssl_result.get("protocols", {}).get("TLS 1.1") == "supported":
        deduct(8, "TLS 1.1 enabled")
    days_left = ssl_result.get("cert", {}).get("days_until_expiry", 999)
    if days_left < 0:
        deduct(25, "SSL certificate expired")
    elif days_left < 14:
        deduct(15, "SSL certificate expiring < 14 days")
    elif days_left < 30:
        deduct(8, "SSL certificate expiring < 30 days")

    headers = all_results.get("headers", {})
    deduct(min(headers.get("score_deductions", 0), 40), "Missing security headers")

    dangerous_open = all_results.get("ports", {}).get("dangerous_ports", [])
    deduct(min(len(dangerous_open) * 12, 30), f"{len(dangerous_open)} dangerous port(s) open")

    dns_result = all_results.get("dns", {})
    if not dns_result.get("spf", {}).get("present") and not dns_result.get("spf", {}).get("skipped"):
        deduct(5, "Missing SPF record")
    if not dns_result.get("dmarc", {}).get("present") and not dns_result.get("dmarc", {}).get("skipped"):
        deduct(5, "Missing DMARC record")

    cves = all_results.get("cves", [])
    critical_cves = [c for c in cves if c.get("cvss_score", 0) >= 9.0]
    high_cves = [c for c in cves if 7.0 <= c.get("cvss_score", 0) < 9.0]
    if critical_cves:
        deduct(25, f"{len(critical_cves)} Critical CVE(s)")
    elif high_cves:
        deduct(12, f"{len(high_cves)} High CVE(s)")

    cors_issues = all_results.get("cors", {}).get("issues", [])
    if any(i.get("severity") == "Critical" for i in cors_issues):
        deduct(20, "Critical CORS misconfiguration")
    elif cors_issues:
        deduct(10, "CORS misconfiguration")

    if all_results.get("ssh_banner", {}).get("eol"):
        deduct(20, "End-of-life operating system")

    score = max(0, score)
    return score, compute_grade(score), deductions


def build_remediation_roadmap(findings: list[dict[str, Any]]) -> dict[str, Any]:
    order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
    sorted_findings = sorted(findings, key=lambda f: order.get(f.get("severity", "Info"), 4))
    immediate: list[dict[str, str]] = []
    short_term: list[dict[str, str]] = []
    long_term: list[dict[str, str]] = []

    for finding in sorted_findings:
        item = {
            "title": finding.get("title", "Unknown"),
            "recommendation": finding.get("recommendation") or finding.get("remediation") or "No recommendation.",
            "severity": finding.get("severity", "Info"),
        }
        severity = finding.get("severity", "Info")
        if severity in ("Critical", "High"):
            immediate.append(item)
        elif severity == "Medium":
            short_term.append(item)
        else:
            long_term.append(item)

    return {
        "immediate_7_days": immediate,
        "short_term_30_days": short_term,
        "long_term_90_days": long_term,
        "total_actions": len(findings),
    }


def _summary(findings: list[dict[str, Any]]) -> dict[str, int]:
    result = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for finding in findings:
        key = str(finding.get("severity", "Info")).lower()
        if key in result:
            result[key] += 1
    return result


def _critical_findings(findings: list[dict[str, Any]]) -> list[str]:
    return [
        f"[{f.get('severity')}] {f.get('title', 'Unknown')}: {f.get('description', '')[:140]}"
        for f in findings
        if f.get("severity") in ("Critical", "High")
    ]


async def run_deep_scan(raw_target: str, quick: bool = True) -> dict[str, Any]:
    start = time.time()
    target = clean_target(raw_target)
    is_ip = is_ip_address(target)

    try:
        ip_address = await asyncio.to_thread(socket.gethostbyname, target)
    except Exception:
        ip_address = None

    http_url = f"http://{target}"
    https_url = f"https://{target}"
    port_target = ip_address or target

    dns_r, port_r, http_r, https_r, whois_r, tech_http_r, tech_https_r, cors_r = await asyncio.gather(
        dns_scan(target, is_ip=is_ip),
        port_scan(port_target, quick=quick),
        http_headers_scan(http_url),
        http_headers_scan(https_url),
        whois_scan(target, is_ip=is_ip),
        tech_fingerprint(http_url),
        tech_fingerprint(https_url),
        cors_check(http_url),
    )

    headers_r = https_r if https_r.get("status") == "completed" else http_r
    tech_r = tech_https_r if tech_https_r.get("status") == "completed" else tech_http_r

    port_nums = [p.get("port") for p in port_r.get("open_ports", [])]
    if 443 in port_nums:
        ssl_r = await tls_deep_check(target)
    else:
        ssl_r = {
            "status": "error",
            "module": "ssl",
            "reason": "Port 443 not open",
            "protocols": {},
            "cipher": None,
            "cert": {},
            "issues": [
                _finding(
                    "High",
                    "No HTTPS/SSL Detected",
                    "Port 443 is not open. Encrypted HTTPS service was not observed.",
                    "Install an SSL certificate and serve HTTPS. Let's Encrypt with certbot is a practical starting point.",
                    evidence="TCP/443 was not open in the port scan",
                    category="tls",
                    detection_method="TCP connect scan",
                )
            ],
            "findings": [],
        }
        ssl_r["findings"] = ssl_r["issues"]

    ssh_banner: dict[str, Any] = {}
    for port in port_r.get("open_ports", []):
        if port.get("port") == 22 and port.get("banner"):
            ssh_banner = parse_ssh_banner(port["banner"])
            break

    cve_tasks = []
    server_header = headers_r.get("headers_raw", {}).get("server") or headers_r.get("headers_raw", {}).get("Server", "")
    if "Apache/" in server_header:
        version = server_header.split("Apache/")[1].split(" ")[0]
        cve_tasks.append(fetch_cves("Apache HTTP Server", version))
    if ssh_banner.get("software") == "OpenSSH" and ssh_banner.get("version"):
        cve_tasks.append(fetch_cves("OpenSSH", ssh_banner["version"]))
    for tech in tech_r.get("technologies", []):
        if tech.get("name") not in ("Web Server", "X-Powered-By") and tech.get("version"):
            cve_tasks.append(fetch_cves(tech["name"], tech["version"]))

    cves: list[dict[str, Any]] = []
    if cve_tasks:
        cve_batches = await asyncio.gather(*cve_tasks, return_exceptions=True)
        for batch in cve_batches:
            if isinstance(batch, list):
                cves.extend(batch)

    seen: set[str] = set()
    unique_cves = []
    for cve in cves:
        cve_id = cve.get("cve_id")
        if cve_id and cve_id not in seen:
            seen.add(cve_id)
            unique_cves.append(cve)

    all_findings: list[dict[str, Any]] = []
    all_findings.extend(headers_r.get("findings", []))
    all_findings.extend(ssl_r.get("issues", []))
    all_findings.extend(cors_r.get("issues", []))
    all_findings.extend(dns_r.get("findings", []))
    all_findings.extend(port_r.get("findings", []))

    if ssh_banner.get("eol"):
        all_findings.append(
            _finding(
                "Critical",
                f"End-of-Life OS Detected: {ssh_banner.get('os', 'Unknown')}",
                "This OS no longer receives security patches. Vulnerabilities discovered after EOL are permanently unpatched.",
                "Upgrade to Ubuntu 22.04 LTS or 24.04 LTS. Plan migration within 30 days.",
                evidence=ssh_banner.get("raw", ""),
                confidence=90,
                category="infrastructure",
                detection_method="SSH banner parsing",
            )
        )

    for cve in unique_cves:
        cvss = cve.get("cvss_score", 0)
        severity = "Critical" if cvss >= 9.0 else ("High" if cvss >= 7.0 else "Medium")
        all_findings.append(
            _finding(
                severity,
                f"{cve.get('cve_id')} - CVSS {cvss}",
                cve.get("description", ""),
                f"Apply the vendor patch or mitigation. See: {cve.get('url')}",
                evidence="Detected software version matched NVD CVE database",
                confidence=80,
                category="cve",
                detection_method="NIST NVD keyword cross-reference",
            )
        )

    all_scan_data = {
        "ssl": ssl_r,
        "headers": headers_r,
        "ports": port_r,
        "dns": dns_r,
        "cves": unique_cves,
        "cors": cors_r,
        "ssh_banner": ssh_banner,
    }
    score, grade, deductions = calculate_security_score(all_scan_data)
    summary = _summary(all_findings)
    timestamp = datetime.utcnow()

    web_server = server_header or tech_r.get("server")
    technologies = {
        "status": tech_r.get("status", "completed"),
        "web_server": web_server,
        "backend_framework": tech_r.get("x_powered_by"),
        "technologies": tech_r.get("technologies", []),
        "waf_detected": False,
        "waf_name": None,
    }

    result = {
        "target": target,
        "raw_target": raw_target,
        "clean_target": target,
        "ip_address": ip_address,
        "resolved_ip": ip_address,
        "quick_scan": quick,
        "scan_timestamp": timestamp.isoformat(),
        "scan_duration_ms": int((time.time() - start) * 1000),
        "score": score,
        "grade": grade,
        "score_deductions": deductions,
        "summary": summary,
        "severity_counts": summary,
        "findings": all_findings,
        "critical_findings": _critical_findings(all_findings),
        "total_findings": len(all_findings),
        "dns": dns_r,
        "ssl": ssl_r,
        "headers": headers_r,
        "http_headers": headers_r,
        "ports": port_r,
        "technologies": technologies,
        "cves": unique_cves,
        "cve_scan": {"status": "completed", "findings": [f for f in all_findings if f.get("category") == "cve"]},
        "cors": cors_r,
        "ssh_banner": ssh_banner,
        "whois": whois_r,
        "remediation_roadmap": build_remediation_roadmap(all_findings),
        "trust_boundary": (
            f"Non-intrusive passive reconnaissance only. Collected "
            f"{timestamp.strftime('%Y-%m-%d %H:%M:%S')} UTC. "
            "No credentials tested. No payloads injected. Findings are observations; "
            "exploitability is not claimed unless explicit evidence exists."
        ),
    }

    # Backward-compatible aliases for the current Next.js UI and history store.
    result["overall_risk_score"] = score
    result["risk_grade"] = grade
    return result


def run_scan_sync(target: str, quick: bool = True) -> dict[str, Any]:
    return asyncio.run(run_deep_scan(target, quick=quick))


class DeepScanner:
    """Backward-compatible wrapper used by older call sites."""

    async def scan(self, target: str, quick: bool = True) -> dict[str, Any]:
        return await run_deep_scan(target, quick=quick)

