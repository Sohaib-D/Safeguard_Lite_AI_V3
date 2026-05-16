# backend/services/security_intelligence.py
"""
Security Intelligence Engine for Safeguard-AI Lite.

Provides AI-powered analysis of deep scan results using Groq's Llama 3.1 models,
with intelligent Python-based fallbacks when AI is unavailable.
"""

import json
import uuid
import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import httpx


class SecurityIntelligence:
    """
    AI-powered security analysis engine that transforms raw scan data
    into actionable intelligence reports, compliance assessments, and
    client-facing deliverables.
    """

    GROQ_API_URL = "https://api.groq.com/openai/v1/chat/completions"
    MODEL = "llama-3.1-70b-versatile"

    SEVERITY_WEIGHTS = {
        "Critical": 10,
        "High": 7,
        "Medium": 4,
        "Low": 2,
        "Informational": 0,
    }

    def __init__(self):
        self.api_key = os.getenv("GROQ_API_KEY", "")

    # =========================================================================
    # METHOD 1: ANALYZE SCAN
    # =========================================================================
    async def analyze_scan(self, scan_result: dict) -> dict:
        """
        Build a focused prompt from scan_result and call Groq for AI analysis.
        Falls back to Python-derived analysis if Groq is unavailable.

        Args:
            scan_result: The full deep scan result dictionary.

        Returns:
            Structured analysis dictionary with vulnerabilities, compliance, and recommendations.
        """
        try:
            if not self.api_key:
                raise ValueError("GROQ_API_KEY not configured")

            # Build focused scan summary for the prompt (truncated to ~3000 tokens)
            scan_summary = self._build_scan_summary(scan_result)
            prompt = self._build_analysis_prompt(scan_summary)

            # Call Groq API
            async with httpx.AsyncClient(timeout=60) as client:
                response = await client.post(
                    self.GROQ_API_URL,
                    headers={
                        "Authorization": f"Bearer {self.api_key}",
                        "Content-Type": "application/json",
                    },
                    json={
                        "model": self.MODEL,
                        "messages": [
                            {
                                "role": "system",
                                "content": (
                                    "You are a senior cybersecurity analyst performing non-invasive defensive reconnaissance assessments. "
                                    "Do not claim exploitability is verified unless explicit exploit verification evidence is present. "
                                    "You MUST respond ONLY with valid JSON matching the exact structure requested. "
                                    "No markdown, no code blocks, no extra text. Just pure JSON."
                                ),
                            },
                            {"role": "user", "content": prompt},
                        ],
                        "response_format": {"type": "json_object"},
                        "temperature": 0.3,
                        "max_tokens": 4096,
                    },
                )

                if response.status_code != 200:
                    raise Exception(f"Groq API returned status {response.status_code}: {response.text[:500]}")

                result = response.json()
                content = result["choices"][0]["message"]["content"]
                analysis = json.loads(content)

                # Validate the response has required keys
                required_keys = [
                    "executive_summary", "technical_summary", "risk_level",
                    "attack_surface_score", "vulnerabilities", "compliance_gaps",
                    "attack_vectors", "security_posture_breakdown", "quick_wins",
                    "remediation_roadmap",
                ]
                for key in required_keys:
                    if key not in analysis:
                        raise ValueError(f"Missing required key in AI response: {key}")

                return analysis

        except Exception as e:
            # Intelligent Python-based fallback
            return self._build_fallback_analysis(scan_result, str(e))

    # =========================================================================
    # METHOD 2: GENERATE PDF REPORT DATA
    # =========================================================================
    async def generate_pdf_report_data(self, scan_result: dict, analysis: dict) -> dict:
        """
        Generate structured data ready for PDF report generation.

        Args:
            scan_result: The raw deep scan result.
            analysis: The AI-generated (or fallback) analysis.

        Returns:
            Structured dict for PDF rendering.
        """
        target = scan_result.get("target", "Unknown")
        risk_grade = scan_result.get("risk_grade", "N/A")
        risk_score = scan_result.get("overall_risk_score", 0)

        # Build sections
        sections = []

        # Executive Summary Section
        sections.append({
            "title": "Executive Summary",
            "content": analysis.get("executive_summary", "No executive summary available."),
            "severity_badge": analysis.get("risk_level", "Unknown"),
        })

        # Technical Summary
        sections.append({
            "title": "Technical Summary",
            "content": analysis.get("technical_summary", "No technical summary available."),
            "severity_badge": None,
        })

        # Vulnerabilities Section
        vulns = analysis.get("vulnerabilities", [])
        vuln_content_parts = []
        for vuln in vulns:
            vuln_content_parts.append(
                f"[{vuln.get('severity', 'Unknown')}] {vuln.get('id', 'N/A')}: "
                f"{vuln.get('title', 'Unknown')} - {vuln.get('description', '')}"
            )
        sections.append({
            "title": "Technical Findings",
            "content": "\n".join(vuln_content_parts) if vuln_content_parts else "No reportable technical findings identified.",
            "severity_badge": "High" if any(v.get("severity") in ("Critical", "High") for v in vulns) else "Medium",
        })

        # Network Security Section
        ports = scan_result.get("ports", {})
        open_ports = ports.get("open_ports", [])
        port_content = f"Total ports scanned: {ports.get('total_scanned', 0)}\n"
        port_content += f"Open ports found: {ports.get('open_count', 0)}\n"
        if open_ports:
            for p in open_ports[:10]:
                port_content += f"  - Port {p['port']} ({p['service']}): {p['risk_description']}\n"
        sections.append({
            "title": "Network Exposure",
            "content": port_content,
            "severity_badge": "Critical" if ports.get("dangerous_open") else "Low",
        })

        # SSL/TLS Section
        ssl_data = scan_result.get("ssl", {})
        if ssl_data.get("status") == "completed":
            cert = ssl_data.get("certificate", {})
            ssl_content = (
                f"Certificate Subject: {cert.get('subject', {}).get('commonName', 'N/A')}\n"
                f"Issuer: {cert.get('issuer', {}).get('organizationName', 'N/A')}\n"
                f"Valid Until: {cert.get('valid_to', 'N/A')}\n"
                f"Days Remaining: {cert.get('days_remaining', 'N/A')}\n"
                f"Protocol: {ssl_data.get('protocol', {}).get('version', 'N/A')}\n"
                f"Health Score: {ssl_data.get('health_score', 'N/A')}/100\n"
                f"Self-Signed: {cert.get('is_self_signed', 'N/A')}"
            )
            ssl_severity = "Critical" if cert.get("is_expired") else "Low"
        else:
            ssl_content = f"SSL audit failed: {ssl_data.get('error', 'Unknown error')}"
            ssl_severity = "High"
        sections.append({
            "title": "SSL/TLS Assessment",
            "content": ssl_content,
            "severity_badge": ssl_severity,
        })

        # Security Headers Section
        headers_data = scan_result.get("http_headers", {})
        if headers_data.get("status") == "completed":
            headers_content = f"Missing headers: {headers_data.get('total_missing', 0)}\n"
            headers_content += f"Critical missing: {headers_data.get('missing_critical_count', 0)}\n"
            headers_detail = headers_data.get("headers", {})
            for h_name, h_data in headers_detail.items():
                status = "✓" if h_data.get("is_present") else "✗"
                headers_content += f"  {status} {h_name}\n"
        else:
            headers_content = "Header analysis unavailable."
        sections.append({
            "title": "HTTP Security Headers",
            "content": headers_content,
            "severity_badge": "High" if headers_data.get("missing_critical_count", 0) > 0 else "Low",
        })

        # Compliance Section
        compliance = analysis.get("compliance_gaps", {})
        compliance_content = (
            f"OWASP Top 10 Gaps: {', '.join(compliance.get('owasp_top_10', ['None']))}\n"
            f"PCI DSS: {compliance.get('pci_dss', 'Not assessed')}\n"
            f"GDPR Relevant: {compliance.get('gdpr_relevant', 'Not assessed')}\n"
            f"ISO 27001 Gaps: {', '.join(compliance.get('iso27001_gaps', ['None']))}"
        )
        sections.append({
            "title": "Compliance Assessment",
            "content": compliance_content,
            "severity_badge": "Medium",
        })

        # Attack Vectors Section
        attack_vectors = analysis.get("attack_vectors", [])
        av_content_parts = []
        for av in attack_vectors:
            av_content_parts.append(
                f"[{av.get('likelihood', 'Unknown')} likelihood / {av.get('impact', 'Unknown')} impact] "
                f"{av.get('vector', 'Unknown')}: {av.get('description', '')}"
            )
        sections.append({
            "title": "Attack Vector Analysis",
            "content": "\n".join(av_content_parts) if av_content_parts else "No significant attack vectors identified.",
            "severity_badge": "High" if attack_vectors else "Low",
        })

        # Recommendations Section
        roadmap = analysis.get("remediation_roadmap", [])
        roadmap_content_parts = []
        for item in roadmap:
            roadmap_content_parts.append(
                f"Priority {item.get('priority', 'N/A')}: {item.get('action', 'N/A')} "
                f"[Effort: {item.get('effort', 'N/A')} | Impact: {item.get('impact', 'N/A')}]"
            )
        sections.append({
            "title": "Remediation Roadmap",
            "content": "\n".join(roadmap_content_parts) if roadmap_content_parts else "No remediation items.",
            "severity_badge": None,
        })

        # Build summary table
        posture = analysis.get("security_posture_breakdown", {})
        summary_table = {
            "target": target,
            "risk_grade": risk_grade,
            "risk_score": risk_score,
            "total_vulnerabilities": len(vulns),
            "critical_count": sum(1 for v in vulns if v.get("severity") == "Critical"),
            "high_count": sum(1 for v in vulns if v.get("severity") == "High"),
            "medium_count": sum(1 for v in vulns if v.get("severity") == "Medium"),
            "low_count": sum(1 for v in vulns if v.get("severity") == "Low"),
            "network_security_score": posture.get("network_security", 0),
            "application_security_score": posture.get("application_security", 0),
            "ssl_tls_score": posture.get("ssl_tls_hygiene", 0),
            "header_security_score": posture.get("header_security", 0),
            "information_disclosure_score": posture.get("information_disclosure", 0),
        }

        # Build remediation checklist
        remediation_checklist = []
        for vuln in vulns:
            remediation_checklist.append({
                "id": vuln.get("id", "N/A"),
                "title": vuln.get("title", "Unknown"),
                "severity": vuln.get("severity", "Unknown"),
                "remediation": vuln.get("remediation", "No remediation provided"),
                "status": "pending",
            })

        # Add quick wins
        quick_wins = analysis.get("quick_wins", [])
        for i, qw in enumerate(quick_wins):
            remediation_checklist.append({
                "id": f"QW-{i+1:03d}",
                "title": f"Quick Win: {qw}",
                "severity": "Medium",
                "remediation": qw,
                "status": "pending",
            })

        return {
            "report_id": str(uuid.uuid4()),
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "target": target,
            "classification": "CONFIDENTIAL",
            "sections": sections,
            "summary_table": summary_table,
            "remediation_checklist": remediation_checklist,
        }

    # =========================================================================
    # METHOD 3: ASSESS FOR CLIENT OFFERING
    # =========================================================================
    async def assess_for_client_offering(self, analysis: dict) -> dict:
        """
        Generate a sales/consulting angle based on the security analysis.

        Args:
            analysis: The AI-generated (or fallback) analysis dict.

        Returns:
            Client offering assessment for potential engagement.
        """
        risk_level = analysis.get("risk_level", "Unknown")
        vulns = analysis.get("vulnerabilities", [])
        posture = analysis.get("security_posture_breakdown", {})
        quick_wins = analysis.get("quick_wins", [])
        roadmap = analysis.get("remediation_roadmap", [])

        # Determine urgency level
        critical_count = sum(1 for v in vulns if v.get("severity") == "Critical")
        high_count = sum(1 for v in vulns if v.get("severity") == "High")

        if critical_count > 0 or risk_level == "Critical":
            urgency_level = "Immediate"
        elif high_count > 2 or risk_level == "High":
            urgency_level = "Soon"
        else:
            urgency_level = "Planned"

        # Identify appropriate services
        identified_services = []

        # Check network security needs
        network_score = posture.get("network_security", 100)
        if network_score < 50:
            identified_services.append("Network Penetration Testing")
            identified_services.append("Firewall Configuration Review")
        elif network_score < 75:
            identified_services.append("Network Security Assessment")

        # Check application security needs
        app_score = posture.get("application_security", 100)
        if app_score < 50:
            identified_services.append("Web Application Penetration Testing")
            identified_services.append("Secure Code Review")
        elif app_score < 75:
            identified_services.append("Application Security Audit")

        # Check SSL/TLS needs
        ssl_score = posture.get("ssl_tls_hygiene", 100)
        if ssl_score < 60:
            identified_services.append("SSL/TLS Configuration & Hardening")
            identified_services.append("Certificate Lifecycle Management")

        # Check header security needs
        header_score = posture.get("header_security", 100)
        if header_score < 60:
            identified_services.append("Security Headers Implementation")
            identified_services.append("Web Server Hardening")

        # Check information disclosure
        info_score = posture.get("information_disclosure", 100)
        if info_score < 60:
            identified_services.append("Information Leakage Assessment")
            identified_services.append("Security Configuration Audit")

        # General services based on vulnerability count
        if len(vulns) > 5:
            identified_services.append("Comprehensive Security Audit")
        if critical_count > 0:
            identified_services.append("Emergency Incident Response")
            identified_services.append("Vulnerability Remediation (Urgent)")

        # Always recommend ongoing services
        identified_services.append("Continuous Security Monitoring")
        if not identified_services:
            identified_services.append("Security Posture Validation")

        # Deduplicate
        identified_services = list(dict.fromkeys(identified_services))

        # Build risk exposure description
        risk_factors = []
        if critical_count > 0:
            risk_factors.append(f"{critical_count} critical vulnerabilities requiring immediate action")
        if high_count > 0:
            risk_factors.append(f"{high_count} high-severity issues that could be exploited")

        attack_vectors = analysis.get("attack_vectors", [])
        high_likelihood_vectors = [av for av in attack_vectors if av.get("likelihood") == "High"]
        if high_likelihood_vectors:
            risk_factors.append(
                f"{len(high_likelihood_vectors)} high-likelihood attack vectors identified"
            )

        compliance_gaps = analysis.get("compliance_gaps", {})
        owasp_gaps = compliance_gaps.get("owasp_top_10", [])
        if owasp_gaps:
            risk_factors.append(f"Fails {len(owasp_gaps)} OWASP Top 10 categories")

        estimated_risk_exposure = (
            "This target has " + "; ".join(risk_factors) + ". "
            if risk_factors
            else "Minimal risk exposure detected. "
        )
        estimated_risk_exposure += (
            "Without remediation, the organization faces potential data breaches, "
            "service disruption, and regulatory non-compliance."
            if urgency_level in ("Immediate", "Soon")
            else "Proactive security improvements can further strengthen the posture."
        )

        # Build pitch summary
        if urgency_level == "Immediate":
            pitch_summary = (
                f"Critical security gaps identified requiring immediate professional intervention. "
                f"Found {len(vulns)} vulnerabilities including {critical_count} critical issues. "
                f"Recommend emergency engagement to prevent active exploitation."
            )
        elif urgency_level == "Soon":
            pitch_summary = (
                f"Significant security weaknesses detected that need near-term attention. "
                f"Found {len(vulns)} vulnerabilities with {high_count} high-severity issues. "
                f"A structured security engagement would substantially reduce risk."
            )
        else:
            pitch_summary = (
                f"Security posture is acceptable but can be improved. "
                f"Found {len(vulns)} items to address. "
                f"A planned security review would optimize defenses and ensure compliance."
            )

        # Proposed engagement
        if urgency_level == "Immediate":
            proposed_engagement = (
                "Phase 1 (Week 1): Emergency vulnerability remediation for critical findings. "
                "Phase 2 (Weeks 2-3): Comprehensive penetration test and security audit. "
                "Phase 3 (Ongoing): Continuous monitoring and quarterly assessments."
            )
        elif urgency_level == "Soon":
            proposed_engagement = (
                "Phase 1 (Weeks 1-2): Security audit and vulnerability assessment. "
                "Phase 2 (Weeks 3-4): Remediation support and hardening. "
                "Phase 3 (Monthly): Ongoing monitoring and compliance checks."
            )
        else:
            proposed_engagement = (
                "Phase 1 (Week 1-2): Security posture validation and gap analysis. "
                "Phase 2 (Week 3): Implementation of quick wins and best practices. "
                "Phase 3 (Quarterly): Periodic security reviews and compliance audits."
            )

        return {
            "pitch_summary": pitch_summary,
            "identified_services": identified_services,
            "urgency_level": urgency_level,
            "estimated_risk_exposure": estimated_risk_exposure,
            "proposed_engagement": proposed_engagement,
        }

    # =========================================================================
    # PRIVATE HELPER METHODS
    # =========================================================================

    def _build_scan_summary(self, scan_result: dict) -> str:
        """Build a focused, truncated summary of scan results for the AI prompt."""
        parts = []

        # Target info
        parts.append(f"Target: {scan_result.get('target', 'Unknown')}")
        parts.append(f"Resolved IP: {scan_result.get('resolved_ip', 'N/A')}")
        parts.append(f"Risk Score: {scan_result.get('overall_risk_score', 'N/A')}/100")
        parts.append(f"Risk Grade: {scan_result.get('risk_grade', 'N/A')}")
        parts.append("")

        # Critical findings
        critical = scan_result.get("critical_findings", [])
        if critical:
            parts.append("CRITICAL FINDINGS:")
            for finding in critical[:10]:
                parts.append(f"  - {finding}")
            parts.append("")

        # Open ports
        ports = scan_result.get("ports", {})
        if ports.get("status") == "completed":
            open_ports = ports.get("open_ports", [])
            if open_ports:
                parts.append(f"OPEN PORTS ({len(open_ports)} found):")
                for p in open_ports[:15]:
                    banner_info = f" | Banner: {p['banner'][:50]}" if p.get("banner") else ""
                    danger = " [DANGEROUS]" if p.get("is_dangerous") else ""
                    parts.append(
                        f"  - {p['port']}/{p['service']}: {p['risk_description']}{danger}{banner_info}"
                    )
                parts.append("")

        # SSL/TLS
        ssl_data = scan_result.get("ssl", {})
        if ssl_data.get("status") == "completed":
            cert = ssl_data.get("certificate", {})
            protocol = ssl_data.get("protocol", {})
            parts.append("SSL/TLS STATUS:")
            parts.append(f"  Protocol: {protocol.get('version', 'N/A')} ({protocol.get('risk_level', 'N/A')})")
            parts.append(f"  Expired: {cert.get('is_expired', 'N/A')}")
            parts.append(f"  Days Remaining: {cert.get('days_remaining', 'N/A')}")
            parts.append(f"  Self-Signed: {cert.get('is_self_signed', 'N/A')}")
            parts.append(f"  Health Score: {ssl_data.get('health_score', 'N/A')}/100")
            parts.append(f"  Cipher: {ssl_data.get('cipher', {}).get('name', 'N/A')} ({ssl_data.get('cipher', {}).get('bits', 'N/A')} bits)")
            parts.append("")
        elif ssl_data.get("status") == "failed":
            parts.append(f"SSL/TLS: FAILED - {ssl_data.get('error', 'Unknown')}")
            parts.append("")

        # Security Headers
        headers_data = scan_result.get("http_headers", {})
        if headers_data.get("status") == "completed":
            parts.append(f"SECURITY HEADERS (Missing: {headers_data.get('total_missing', 0)}):")
            header_details = headers_data.get("headers", {})
            for h_name, h_data in header_details.items():
                status = "PRESENT" if h_data.get("is_present") else f"MISSING [{h_data.get('risk_level', 'N/A')}]"
                parts.append(f"  - {h_name}: {status}")
            parts.append("")

        # Technologies
        tech = scan_result.get("technologies", {})
        if tech.get("status") == "completed":
            parts.append("DETECTED TECHNOLOGIES:")
            if tech.get("web_server"):
                parts.append(f"  Server: {tech['web_server']}")
            if tech.get("backend_framework"):
                parts.append(f"  Framework: {tech['backend_framework']}")
            if tech.get("cms"):
                parts.append(f"  CMS: {tech['cms']}")
            if tech.get("cdn"):
                parts.append(f"  CDN: {tech['cdn']}")
            if tech.get("waf_detected"):
                parts.append(f"  WAF: {tech.get('waf_name', 'Detected')}")
            version_risks = tech.get("version_risks", [])
            if version_risks:
                for vr in version_risks:
                    parts.append(f"  [!] {vr['detail']}")
            parts.append("")

        # DNS
        dns_data = scan_result.get("dns", {})
        if dns_data.get("status") == "completed":
            parts.append("DNS RECONNAISSANCE:")
            parts.append(f"  A Records: {dns_data.get('a_records', [])}")
            parts.append(f"  MX Records: {len(dns_data.get('mx_records', []))} found")
            parts.append(f"  NS Records: {dns_data.get('ns_records', [])}")
            zone = dns_data.get("zone_transfer", {})
            if zone.get("successful"):
                parts.append("  [!] ZONE TRANSFER SUCCESSFUL - CRITICAL")
            parts.append("")

        # WHOIS
        whois_data = scan_result.get("whois", {})
        if whois_data.get("status") == "completed":
            parts.append("WHOIS INTELLIGENCE:")
            parts.append(f"  Registrar: {whois_data.get('registrar', 'N/A')}")
            parts.append(f"  Created: {whois_data.get('creation_date', 'N/A')}")
            parts.append(f"  Expires: {whois_data.get('expiry_date', 'N/A')}")
            parts.append(f"  Days Until Expiry: {whois_data.get('days_until_expiry', 'N/A')}")
            if whois_data.get("domain_expiring_soon"):
                parts.append("  [!] DOMAIN EXPIRING SOON - CRITICAL")
            parts.append("")

        # Content analysis
        content = scan_result.get("content_analysis", {})
        if content.get("status") == "completed":
            parts.append("CONTENT ANALYSIS:")
            if content.get("login_forms", {}).get("detected"):
                parts.append(f"  Login Forms: {content['login_forms']['count']} ({content['login_forms'].get('risk', 'N/A')})")
            if content.get("inline_scripts", {}).get("detected"):
                parts.append(f"  Inline Scripts: {content['inline_scripts']['count']}")
            if content.get("sensitive_comments", {}).get("detected"):
                parts.append("  [!] SENSITIVE DATA IN HTML COMMENTS - CRITICAL")
            ext_scripts = content.get("external_scripts", {})
            if ext_scripts.get("insecure_scripts"):
                parts.append(f"  [!] Insecure external scripts: {len(ext_scripts['insecure_scripts'])}")
            parts.append("")

        # Robots/Sitemap
        robots = scan_result.get("robots", {})
        if robots.get("status") == "completed":
            robots_txt = robots.get("robots_txt", {})
            if robots_txt.get("high_risk_paths"):
                parts.append("ROBOTS.TXT EXPOSURE:")
                for path in robots_txt["high_risk_paths"][:5]:
                    parts.append(f"  [!] {path.get('detail', 'N/A')}")
                parts.append("")

        # Truncate to approximately 3000 tokens (~12000 chars)
        summary = "\n".join(parts)
        if len(summary) > 12000:
            summary = summary[:12000] + "\n... [TRUNCATED]"

        return summary

    def _build_analysis_prompt(self, scan_summary: str) -> str:
        """Build the full analysis prompt for Groq."""
        return f"""Analyze the following security scan results and provide a comprehensive vulnerability assessment.

SCAN DATA:
{scan_summary}

You MUST respond with a JSON object containing EXACTLY these keys (no additional keys, no markdown formatting):

{{
  "executive_summary": "2-3 sentence plain-English overview for non-technical users",
  "technical_summary": "2-3 sentence technical overview for security engineers",
  "risk_level": "Critical|High|Medium|Low|Minimal",
  "attack_surface_score": <integer 0-100>,
  "vulnerabilities": [
    {{
      "id": "VULN-001",
      "title": "Short title",
      "category": "SSL/TLS|Headers|Network|DNS|Application|Configuration",
      "severity": "Critical|High|Medium|Low|Informational",
      "cvss_score": <float 0.0-10.0>,
      "description": "Plain-English description of the issue",
      "technical_detail": "Technical explanation",
      "affected_component": "affected service/control/asset",
      "exploitation_scenario": "Conservative risk scenario; state when exploitability is not verified",
      "remediation": "Exact steps to fix, with commands where applicable",
      "references": ["CVE/OWASP/CWE reference if applicable"],
      "confidence_score": <float 0.0-1.0>,
      "evidence": "Observed evidence snippet",
      "detection_method": "How the observation was detected",
      "exploit_verified": false,
      "passive_only": true
    }}
  ],
  "compliance_gaps": {{
    "owasp_top_10": ["list of OWASP Top 10 2021 categories this fails"],
    "pci_dss": "pass|fail|partial with brief reason",
    "gdpr_relevant": "yes|no with brief reason",
    "iso27001_gaps": ["list of relevant ISO 27001 control gaps"]
  }},
  "attack_vectors": [
    {{
      "vector": "Attack vector name",
      "likelihood": "High|Medium|Low",
      "impact": "High|Medium|Low",
      "description": "How this specific target could be attacked"
    }}
  ],
  "security_posture_breakdown": {{
    "network_security": <integer 0-100>,
    "application_security": <integer 0-100>,
    "ssl_tls_hygiene": <integer 0-100>,
    "header_security": <integer 0-100>,
    "information_disclosure": <integer 0-100>
  }},
  "competitive_benchmark": "How does this security posture compare to industry standard for this type of site",
  "quick_wins": ["List of fixes that take <1 hour with highest impact"],
  "remediation_roadmap": [
    {{"priority": 1, "action": "...", "effort": "Low|Medium|High", "impact": "Critical|High|Medium"}}
  ],
  "monitoring_recommendations": ["Ongoing monitoring steps"],
  "service_offering_angles": ["If offering security services, these are selling points based on findings"]
}}

Rules:
- Generate findings only from what the scan actually observed
- Open ports are exposure observations, not vulnerabilities by themselves
- Missing WAF/CDN does not prove DDoS vulnerability
- Missing CSP does not prove exploitable XSS
- Public SSH does not imply weak passwords
- Banner versions alone are only "potentially affected" CVE evidence
- Be specific about the target's actual issues, not generic advice
- CVSS scores should reflect real-world severity and uncertainty
- Remediation steps should be actionable with specific commands where possible
- Reference real CVEs, CWEs, or OWASP categories where applicable
- The attack_surface_score should reflect how exposed this target is (100 = completely exposed)
- Security posture scores: 100 = strongest observed posture, 0 = weakest observed posture"""

    def _build_fallback_analysis(self, scan_result: dict, error_reason: str) -> dict:
        """
        Build a structured analysis from raw scan data without AI.
        This is the intelligent Python-based fallback when Groq is unavailable.
        """
        target = scan_result.get("target", "Unknown")
        risk_score = scan_result.get("overall_risk_score", 50)
        risk_grade = scan_result.get("risk_grade", "C")
        critical_findings = scan_result.get("critical_findings", [])

        # Determine risk level from score
        if risk_score >= 81:
            risk_level = "Critical"
        elif risk_score >= 61:
            risk_level = "High"
        elif risk_score >= 41:
            risk_level = "Medium"
        elif risk_score >= 16:
            risk_level = "Low"
        else:
            risk_level = "Minimal"

        # Build vulnerabilities from scan data
        vulnerabilities = []
        vuln_counter = 1

        # Check ports
        ports = scan_result.get("ports", {})
        if ports.get("status") == "completed":
            dangerous = ports.get("dangerous_open", [])
            for port_info in dangerous:
                vulnerabilities.append({
                    "id": f"VULN-{vuln_counter:03d}",
                    "title": f"Externally Accessible Service: {port_info['port']} ({port_info['service']})",
                    "category": "Network",
                    "severity": "High",
                    "cvss_score": 7.5,
                    "description": f"Port {port_info['port']} ({port_info['service']}) is open and accessible. This is an exposure observation, not proof of compromise.",
                    "technical_detail": f"{port_info['risk_description']}. Banner: {port_info.get('banner', 'N/A')}",
                    "affected_component": f"TCP/{port_info['port']}",
                    "exploitation_scenario": f"The {port_info['service']} service increases attack surface if it is not intentionally exposed and hardened. Exploitability was not verified.",
                    "remediation": f"Restrict access to port {port_info['port']} if it is not intentionally public. Use VPN, firewall allowlists, MFA, and strong authentication for legitimate remote access.",
                    "references": ["CWE-200: Exposure of Sensitive Information"],
                })
                vuln_counter += 1

        # Check SSL
        ssl_data = scan_result.get("ssl", {})
        if ssl_data.get("status") == "completed":
            cert = ssl_data.get("certificate", {})
            protocol = ssl_data.get("protocol", {})

            if cert.get("is_expired"):
                vulnerabilities.append({
                    "id": f"VULN-{vuln_counter:03d}",
                    "title": "Expired SSL Certificate",
                    "category": "SSL/TLS",
                    "severity": "Critical",
                    "cvss_score": 9.0,
                    "description": "The SSL certificate has expired, meaning browsers will show security warnings and encrypted communications cannot be trusted.",
                    "technical_detail": f"Certificate expired. Valid until: {cert.get('valid_to', 'N/A')}",
                    "affected_component": "SSL/TLS Certificate",
                    "exploitation_scenario": "Users will bypass security warnings, and man-in-the-middle attacks become trivial.",
                    "remediation": "Immediately renew the SSL certificate. Consider using Let's Encrypt for automatic renewal: certbot renew",
                    "references": ["CWE-295: Improper Certificate Validation"],
                })
                vuln_counter += 1

            if cert.get("is_self_signed"):
                vulnerabilities.append({
                    "id": f"VULN-{vuln_counter:03d}",
                    "title": "Self-Signed Certificate",
                    "category": "SSL/TLS",
                    "severity": "High",
                    "cvss_score": 6.5,
                    "description": "The server uses a self-signed certificate that is not trusted by browsers.",
                    "technical_detail": "Certificate issuer matches subject, indicating self-signing.",
                    "affected_component": "SSL/TLS Certificate Chain",
                    "exploitation_scenario": "Users become accustomed to bypassing certificate warnings, making MITM attacks easier.",
                    "remediation": "Replace with a certificate from a trusted Certificate Authority. Free options: Let's Encrypt.",
                    "references": ["CWE-295: Improper Certificate Validation"],
                })
                vuln_counter += 1

            if protocol.get("risk_level") == "vulnerable":
                vulnerabilities.append({
                    "id": f"VULN-{vuln_counter:03d}",
                    "title": f"Deprecated TLS Protocol Observed: {protocol.get('version', 'N/A')}",
                    "category": "SSL/TLS",
                    "severity": "High",
                    "cvss_score": 7.0,
                    "description": "The server supports deprecated TLS protocols that have known vulnerabilities.",
                    "technical_detail": f"Protocol {protocol.get('version')} is deprecated or weak for modern internet-facing services.",
                    "affected_component": "TLS Protocol Configuration",
                    "exploitation_scenario": "Deprecated protocols can increase downgrade and cryptographic risk. This scan did not verify exploitability.",
                    "remediation": "Disable TLSv1.0 and TLSv1.1. Set minimum to TLSv1.2. In nginx: ssl_protocols TLSv1.2 TLSv1.3;",
                    "references": ["CVE-2014-3566 (POODLE)", "CWE-327: Use of Broken Crypto Algorithm"],
                })
                vuln_counter += 1
        elif ssl_data.get("status") == "failed":
            vulnerabilities.append({
                "id": f"VULN-{vuln_counter:03d}",
                "title": "SSL/TLS Not Properly Configured",
                "category": "SSL/TLS",
                "severity": "High",
                "cvss_score": 7.0,
                "description": "SSL/TLS connection could not be established, indicating misconfiguration or missing certificate.",
                "technical_detail": f"Error: {ssl_data.get('error', 'Unknown')}",
                "affected_component": "HTTPS Configuration",
                "exploitation_scenario": "Missing or failed HTTPS can expose users to interception depending on how the service is used. This scan did not verify exploitation.",
                "remediation": "Install and configure a valid SSL certificate. Use Let's Encrypt for free certificates.",
                "references": ["A02:2021 – Cryptographic Failures"],
            })
            vuln_counter += 1

        # Check headers
        headers_data = scan_result.get("http_headers", {})
        if headers_data.get("status") == "completed":
            header_details = headers_data.get("headers", {})
            missing_critical_headers = [
                h for h, d in header_details.items()
                if not d.get("is_present") and d.get("risk_level") in ("Critical", "High")
            ]
            if missing_critical_headers:
                vulnerabilities.append({
                    "id": f"VULN-{vuln_counter:03d}",
                    "title": "Missing Critical Security Headers",
                    "category": "Headers",
                    "severity": "Medium",
                    "cvss_score": 5.0,
                    "description": f"The server is missing {len(missing_critical_headers)} important security headers that protect against common web attacks.",
                    "technical_detail": f"Missing: {', '.join(missing_critical_headers)}",
                    "affected_component": "HTTP Response Headers",
                    "exploitation_scenario": "Missing headers reduce browser-side defenses. This does not prove exploitable XSS, clickjacking, or downgrade attacks.",
                    "remediation": "Add security headers to web server config. For nginx: add_header Strict-Transport-Security 'max-age=31536000; includeSubDomains';",
                    "references": ["A05:2021 – Security Misconfiguration"],
                })
                vuln_counter += 1

        # Check DNS zone transfer
        dns_data = scan_result.get("dns", {})
        if dns_data.get("status") == "completed":
            if dns_data.get("zone_transfer", {}).get("successful"):
                vulnerabilities.append({
                    "id": f"VULN-{vuln_counter:03d}",
                    "title": "DNS Zone Transfer Allowed (AXFR)",
                    "category": "DNS",
                    "severity": "Critical",
                    "cvss_score": 8.5,
                    "description": "The DNS server allows zone transfers, exposing all DNS records to anyone who requests them.",
                    "technical_detail": "AXFR query succeeded, revealing the complete DNS zone including internal hostnames.",
                    "affected_component": "DNS Nameserver Configuration",
                    "exploitation_scenario": "Attackers can enumerate all subdomains, internal services, and network topology.",
                    "remediation": "Restrict zone transfers to authorized secondary nameservers only. In BIND: allow-transfer { trusted-servers; };",
                    "references": ["CWE-200: Exposure of Sensitive Information"],
                })
                vuln_counter += 1

        # Check content analysis
        content = scan_result.get("content_analysis", {})
        if content.get("status") == "completed":
            if content.get("sensitive_comments", {}).get("detected"):
                vulnerabilities.append({
                    "id": f"VULN-{vuln_counter:03d}",
                    "title": "Sensitive Information in HTML Comments",
                    "category": "Application",
                    "severity": "Critical",
                    "cvss_score": 8.0,
                    "description": "HTML source code contains comments with sensitive information like passwords, API keys, or tokens.",
                    "technical_detail": f"Found keywords: {[f.get('keyword') for f in content['sensitive_comments'].get('findings', [])]}",
                    "affected_component": "HTML Source Code",
                    "exploitation_scenario": "Attackers viewing page source can find credentials or tokens for unauthorized access.",
                    "remediation": "Remove all comments containing sensitive data. Implement pre-deployment code review checks.",
                    "references": ["CWE-615: Inclusion of Sensitive Information in Source Code Comments", "A01:2021 – Broken Access Control"],
                })
                vuln_counter += 1

            if content.get("external_scripts", {}).get("insecure_scripts"):
                vulnerabilities.append({
                    "id": f"VULN-{vuln_counter:03d}",
                    "title": "External Scripts Loaded Over HTTP",
                    "category": "Application",
                    "severity": "High",
                    "cvss_score": 7.0,
                    "description": "External JavaScript files are loaded over unencrypted HTTP, creating a supply chain attack vector.",
                    "technical_detail": f"Insecure scripts: {content['external_scripts']['insecure_scripts'][:3]}",
                    "affected_component": "External Script References",
                    "exploitation_scenario": "An attacker performing MITM can inject malicious JavaScript by intercepting HTTP script requests.",
                    "remediation": "Change all script src attributes to use HTTPS. Add Subresource Integrity (SRI) hashes.",
                    "references": ["CWE-829: Inclusion of Functionality from Untrusted Control Sphere"],
                })
                vuln_counter += 1

        # Check robots.txt
        robots = scan_result.get("robots", {})
        if robots.get("status") == "completed":
            if robots.get("robots_txt", {}).get("high_risk_paths"):
                vulnerabilities.append({
                    "id": f"VULN-{vuln_counter:03d}",
                    "title": "Sensitive Paths Exposed in robots.txt",
                    "category": "Configuration",
                    "severity": "Medium",
                    "cvss_score": 4.5,
                    "description": "The robots.txt file reveals sensitive administrative or configuration paths.",
                    "technical_detail": f"Exposed paths: {[p.get('path') for p in robots['robots_txt']['high_risk_paths'][:5]]}",
                    "affected_component": "robots.txt",
                    "exploitation_scenario": "Attackers use robots.txt as a roadmap to find admin panels, backups, and config files.",
                    "remediation": "Remove sensitive paths from robots.txt. Use authentication and access controls instead.",
                    "references": ["CWE-538: Insertion of Sensitive Information into Externally-Accessible File"],
                })
                vuln_counter += 1

        # Check WHOIS
        whois_data = scan_result.get("whois", {})
        if whois_data.get("status") == "completed" and whois_data.get("domain_expiring_soon"):
            vulnerabilities.append({
                "id": f"VULN-{vuln_counter:03d}",
                "title": "Domain Registration Expiring Soon",
                "category": "Configuration",
                "severity": "High",
                "cvss_score": 6.0,
                "description": f"The domain expires in {whois_data.get('days_until_expiry')} days. If not renewed, it could be hijacked.",
                "technical_detail": f"Expiry date: {whois_data.get('expiry_date')}. Registrar: {whois_data.get('registrar')}",
                "affected_component": "Domain Registration",
                "exploitation_scenario": "Expired domains can be registered by attackers for phishing, brand impersonation, or traffic hijacking.",
                "remediation": "Renew the domain immediately. Enable auto-renewal and registrar lock.",
                "references": ["CWE-923: Improper Restriction of Communication Channel to Intended Endpoints"],
            })
            vuln_counter += 1

        # Compute posture scores
        network_score = 100
        app_score = 100
        ssl_score = 100
        header_score = 100
        info_score = 100

        # Network score reductions
        if ports.get("status") == "completed":
            open_count = ports.get("open_count", 0)
            dangerous_count = len(ports.get("dangerous_open", []))
            network_score -= min(50, dangerous_count * 20)
            network_score -= min(30, open_count * 3)

        # SSL score
        if ssl_data.get("status") == "completed":
            ssl_health = ssl_data.get("health_score", 100)
            ssl_score = ssl_health
        elif ssl_data.get("status") == "failed":
            ssl_score = 20

        # Header score
        if headers_data.get("status") == "completed":
            total_headers = 8  # Total headers we check
            missing = headers_data.get("total_missing", 0)
            header_score = max(0, int(100 * (1 - missing / total_headers)))

        # App score
        if content.get("status") == "completed":
            if content.get("sensitive_comments", {}).get("detected"):
                app_score -= 40
            if content.get("external_scripts", {}).get("insecure_scripts"):
                app_score -= 20
            if content.get("inline_scripts", {}).get("count", 0) > 5:
                app_score -= 10

        # Info disclosure score
        if dns_data.get("status") == "completed" and dns_data.get("zone_transfer", {}).get("successful"):
            info_score -= 40
        if robots.get("status") == "completed" and robots.get("robots_txt", {}).get("high_risk_paths"):
            info_score -= 20
        tech = scan_result.get("technologies", {})
        if tech.get("status") == "completed" and tech.get("version_risks"):
            info_score -= 15

        network_score = max(0, network_score)
        app_score = max(0, app_score)
        info_score = max(0, info_score)

        # Build compliance gaps
        owasp_gaps = []
        if missing_critical_headers if headers_data.get("status") == "completed" else False:
            owasp_gaps.append("A05:2021 – Security Misconfiguration")
        if ssl_score < 60:
            owasp_gaps.append("A02:2021 – Cryptographic Failures")
        if content.get("sensitive_comments", {}).get("detected"):
            owasp_gaps.append("A01:2021 – Broken Access Control")
        if dns_data.get("zone_transfer", {}).get("successful"):
            owasp_gaps.append("A01:2021 – Broken Access Control")
        if ports.get("dangerous_open"):
            owasp_gaps.append("A05:2021 – Security Misconfiguration")

        # Deduplicate
        owasp_gaps = list(dict.fromkeys(owasp_gaps))

        # PCI DSS assessment
        if risk_score >= 61:
            pci_dss = "fail - multiple critical security controls missing"
        elif risk_score >= 41:
            pci_dss = "partial - some security controls need improvement"
        else:
            pci_dss = "pass - basic security controls in place"

        # Build attack vectors
        attack_vectors = []
        if ports.get("dangerous_open"):
            attack_vectors.append({
                "vector": "Network Service Exploitation",
                "likelihood": "High",
                "impact": "High",
                "description": f"Dangerous ports are open ({', '.join([str(p['port']) for p in ports['dangerous_open']])}), providing direct attack surface for service exploitation.",
            })
        if ssl_score < 50:
            attack_vectors.append({
                "vector": "Man-in-the-Middle (MITM)",
                "likelihood": "Medium",
                "impact": "High",
                "description": "Weak or missing SSL/TLS configuration allows traffic interception and credential theft.",
            })
        if header_score < 50:
            attack_vectors.append({
                "vector": "Client-Side Attacks (XSS/Clickjacking)",
                "likelihood": "Medium",
                "impact": "Medium",
                "description": "Missing security headers reduce browser-side protections against classes of attacks such as XSS and UI redressing; exploitability is not verified.",
            })
        if content.get("sensitive_comments", {}).get("detected"):
            attack_vectors.append({
                "vector": "Credential Harvesting",
                "likelihood": "High",
                "impact": "Critical",
                "description": "Sensitive information in HTML comments can be trivially extracted for unauthorized access.",
            })

        # Build quick wins
        quick_wins = []
        if headers_data.get("status") == "completed" and headers_data.get("total_missing", 0) > 0:
            quick_wins.append("Add security headers to web server configuration (15 minutes)")
        if ssl_data.get("status") == "completed" and ssl_data.get("protocol", {}).get("risk_level") == "vulnerable":
            quick_wins.append("Disable TLSv1.0/1.1 in server configuration (10 minutes)")
        if content.get("sensitive_comments", {}).get("detected"):
            quick_wins.append("Remove sensitive comments from HTML source (30 minutes)")
        if not scan_result.get("security_txt", {}).get("exists"):
            quick_wins.append("Add security.txt for responsible disclosure (5 minutes)")

        # Build remediation roadmap
        for vuln in vulnerabilities:
            vuln.setdefault("confidence_score", 0.80)
            vuln.setdefault("evidence", vuln.get("technical_detail", "Derived from normalized scan data"))
            vuln.setdefault("detection_method", "Normalized scan result analysis")
            vuln.setdefault("exploit_verified", False)
            vuln.setdefault("passive_only", True)

        # Build remediation roadmap
        roadmap = []
        priority = 1
        for vuln in sorted(vulnerabilities, key=lambda v: self.SEVERITY_WEIGHTS.get(v["severity"], 0), reverse=True):
            effort = "Low" if vuln["cvss_score"] < 5 else "Medium" if vuln["cvss_score"] < 8 else "High"
            roadmap.append({
                "priority": priority,
                "action": vuln["remediation"],
                "effort": effort,
                "impact": vuln["severity"],
            })
            priority += 1

        # Executive summary
        exec_summary = (
            f"Security assessment of {target} reveals a {risk_level.lower()} risk level "
                f"with an externally observable risk score of {risk_score}/100 (Grade: {risk_grade}). "
            f"{len(vulnerabilities)} security issues were identified, "
            f"{'requiring immediate attention' if risk_level in ('Critical', 'High') else 'most of which can be addressed with standard hardening measures'}."
        )

        tech_summary = (
            f"Target scored {risk_score}/100 on the risk index. "
            f"Network exposure: {len(ports.get('open_ports', []))} open ports "
            f"({'including dangerous services' if ports.get('dangerous_open') else 'no critical services exposed'}). "
            f"SSL health: {ssl_score}/100. Header compliance: {header_score}/100."
        )

        return {
            "executive_summary": exec_summary,
            "technical_summary": tech_summary,
            "risk_level": risk_level,
            "attack_surface_score": min(100, risk_score + len(ports.get("open_ports", [])) * 2),
            "vulnerabilities": vulnerabilities,
            "compliance_gaps": {
                "owasp_top_10": owasp_gaps if owasp_gaps else ["None identified"],
                "pci_dss": pci_dss,
                "gdpr_relevant": "yes - if processing EU user data, encryption and access control gaps are relevant" if risk_score > 40 else "no - basic controls appear adequate",
                "iso27001_gaps": [
                    gap for gap in [
                        "A.13 Communications Security" if network_score < 70 else None,
                        "A.10 Cryptography" if ssl_score < 70 else None,
                        "A.14 System Acquisition, Development and Maintenance" if app_score < 70 else None,
                        "A.12 Operations Security" if info_score < 70 else None,
                    ] if gap
                ] or ["None identified"],
            },
            "attack_vectors": attack_vectors if attack_vectors else [{
                "vector": "General Reconnaissance",
                "likelihood": "Low",
                "impact": "Low",
                "description": "Standard internet exposure with no critical attack surfaces identified.",
            }],
            "security_posture_breakdown": {
                "network_security": max(0, network_score),
                "application_security": max(0, app_score),
                "ssl_tls_hygiene": max(0, ssl_score),
                "header_security": max(0, header_score),
                "information_disclosure": max(0, info_score),
            },
            "competitive_benchmark": (
                f"With a grade of {risk_grade}, this target has {'elevated observable exposure' if risk_score > 40 else 'limited externally observable exposure'} "
                f"based on this non-invasive scan. "
                f"{'Significant improvements are recommended.' if risk_score > 60 else 'Targeted hardening is recommended.' if risk_score > 25 else 'Continue periodic validation and monitoring.'}"
            ),
            "quick_wins": quick_wins if quick_wins else ["Continue monitoring and periodic validation"],
            "remediation_roadmap": roadmap if roadmap else [{"priority": 1, "action": "Continue monitoring and regular patching", "effort": "Low", "impact": "Medium"}],
            "monitoring_recommendations": [
                "Set up SSL certificate expiry monitoring",
                "Implement continuous port scanning (weekly)",
                "Monitor security headers after deployments",
                "Track CVEs for detected technology stack",
                "Set up domain expiry alerts",
            ],
            "service_offering_angles": [
                f"{'Emergency remediation needed' if risk_level in ('Critical', 'High') else 'Proactive security hardening opportunity'}",
                f"{len(vulnerabilities)} actionable findings to demonstrate value",
                f"Compliance gaps ({', '.join(owasp_gaps[:2]) if owasp_gaps else 'N/A'}) create urgency",
            ],
            "_metadata": {
                "analysis_engine": "python_fallback",
                "ai_unavailable_reason": error_reason if 'error_reason' in dir() else "Unknown",
                "generated_at": datetime.now(timezone.utc).isoformat(),
            },
        }


# =========================================================================
# NEW INTELLIGENCE LAYER (2026 UPGRADE)
# =========================================================================

from backend.schemas.findings import (
    Finding,
    FindingCategory,
    Severity,
    ObservationType,
    Exploitability,
    FalsePositiveRisk,
    Evidence,
    ComplianceMapping
)


class SecurityIntelligenceAnalyzer:
    """
    Analyzes and enhances security findings with intelligence layer.

    This class applies security engineering reasoning to classify findings
    as actual vulnerabilities, exposures, normal behavior, or inconclusive signals.
    """

    @staticmethod
    def analyze_finding(finding: Finding) -> Finding:
        """
        Apply intelligence analysis to a finding.

        Returns an enhanced finding with intelligence fields populated.
        """
        # Apply classification logic based on finding characteristics
        observation_type = SecurityIntelligenceAnalyzer._classify_observation_type(finding)
        exploitability = SecurityIntelligenceAnalyzer._assess_exploitability(finding)
        real_world_impact = SecurityIntelligenceAnalyzer._determine_real_world_impact(finding)
        attack_surface_context = SecurityIntelligenceAnalyzer._analyze_attack_surface(finding)
        false_positive_risk = SecurityIntelligenceAnalyzer._assess_false_positive_risk(finding)

        # Create enhanced finding with intelligence fields
        enhanced_finding = finding.model_copy(update={
            "observation_type": observation_type,
            "exploitability": exploitability,
            "real_world_impact": real_world_impact,
            "attack_surface_context": attack_surface_context,
            "false_positive_risk": false_positive_risk,
        })

        return enhanced_finding

    @staticmethod
    def _classify_observation_type(finding: Finding) -> ObservationType:
        """Classify the type of security observation."""
        title_lower = finding.title.lower()
        category = finding.category

        # Vulnerability patterns
        if category == FindingCategory.VULNERABILITY:
            return ObservationType.WEAKNESS

        # Configuration issues
        if category in [FindingCategory.CONFIGURATION_GAP, FindingCategory.COMPLIANCE_GAP]:
            return ObservationType.MISCONFIGURATION

        # Exposure observations
        if category == FindingCategory.EXPOSURE_OBSERVATION:
            return ObservationType.EXPOSURE

        # Informational findings
        if category in [FindingCategory.INFORMATIONAL, FindingCategory.HARDENING_RECOMMENDATION]:
            return ObservationType.INFORMATIONAL

        # Security weaknesses
        if category == FindingCategory.SECURITY_WEAKNESS:
            # Distinguish between actual weaknesses and exposures
            if any(word in title_lower for word in ['exposed', 'accessible', 'open', 'reachable']):
                return ObservationType.EXPOSURE
            else:
                return ObservationType.WEAKNESS

        return ObservationType.INFORMATIONAL

    @staticmethod
    def _assess_exploitability(finding: Finding) -> Exploitability:
        """Assess the exploitability potential of a finding."""
        title_lower = finding.title.lower()
        confidence = finding.confidence_score
        severity = finding.severity

        # High confidence confirmed issues
        if confidence >= 0.9 and severity in [Severity.CRITICAL, Severity.HIGH]:
            if finding.category == FindingCategory.VULNERABILITY:
                return Exploitability.POSSIBLE
            elif finding.category == FindingCategory.SECURITY_WEAKNESS:
                return Exploitability.UNLIKELY

        # Passive-only observations
        if finding.passive_only:
            if any(word in title_lower for word in ['reachable', 'accessible', 'exposed']):
                return Exploitability.UNVERIFIED
            else:
                return Exploitability.UNLIKELY

        # Configuration issues
        if finding.category in [FindingCategory.CONFIGURATION_GAP, FindingCategory.COMPLIANCE_GAP]:
            return Exploitability.UNLIKELY

        # Default conservative assessment
        return Exploitability.UNKNOWN

    @staticmethod
    def _determine_real_world_impact(finding: Finding) -> str:
        """Determine the real-world security impact."""
        title_lower = finding.title.lower()
        category = finding.category
        severity = finding.severity

        # Critical findings
        if severity == Severity.CRITICAL:
            if 'cors' in title_lower and 'credentials' in title_lower:
                return "Potential for cross-origin data theft if sensitive endpoints are accessed by authenticated users. Impact depends on whether sensitive data is exposed to CORS-enabled origins."
            elif 'exposed' in title_lower and 'sensitive' in title_lower:
                return "Direct exposure of sensitive system resources. Could lead to information disclosure, unauthorized access, or further compromise depending on exposed content."

        # High severity
        if severity == Severity.HIGH:
            if 'weak' in title_lower and 'cipher' in title_lower:
                return "Reduced encryption strength may allow cryptographic attacks under specific conditions. Impact depends on data sensitivity and attack scenario feasibility."
            elif 'missing' in title_lower and 'security' in title_lower:
                return "Absence of expected security controls. Actual risk depends on service exposure level and whether the control is truly required for the service context."

        # Medium severity
        if severity == Severity.MEDIUM:
            if 'dangerous' in title_lower and 'method' in title_lower:
                return "HTTP methods enabled that could allow unintended operations. Risk depends on application logic and whether authentication properly restricts these methods."
            elif 'information' in title_lower and 'disclosure' in title_lower:
                return "Potential information leakage that could aid reconnaissance. Impact depends on sensitivity of disclosed information and attacker's ability to leverage it."

        # Low severity
        if severity == Severity.LOW:
            return "Minor security observation that may indicate incomplete hardening. Limited direct impact but could contribute to overall security posture assessment."

        # Informational
        if severity == Severity.INFORMATIONAL:
            return "Security-relevant observation for awareness. No immediate risk identified but may be useful for comprehensive security assessment."

        # Default conservative impact
        return "Security observation requiring context-specific risk assessment. Impact depends on service architecture, data sensitivity, and operational environment."

    @staticmethod
    def _analyze_attack_surface(finding: Finding) -> str:
        """Analyze how the finding affects the attack surface."""
        title_lower = finding.title.lower()
        category = finding.category

        # Network exposure
        if 'port' in title_lower or 'service' in title_lower:
            return "Increases network attack surface by exposing additional service endpoints. Attackers can probe these services for vulnerabilities or misconfigurations."

        # Web application exposure
        if 'http' in title_lower or 'web' in title_lower:
            return "Expands web application attack surface. Exposed endpoints may be probed for common web vulnerabilities, injection flaws, or misconfigurations."

        # Information disclosure
        if 'information' in title_lower and 'disclosure' in title_lower:
            return "Provides reconnaissance information that could help attackers map the target environment and identify higher-value attack vectors."

        # Configuration issues
        if category in [FindingCategory.CONFIGURATION_GAP, FindingCategory.COMPLIANCE_GAP]:
            return "Indicates potential gaps in security configuration that could be exploited if the service is otherwise accessible."

        # Authentication/authorization
        if 'auth' in title_lower or 'credential' in title_lower:
            return "Affects authentication boundaries. Could allow unauthorized access if combined with other attack vectors or misconfigurations."

        # Default analysis
        return "Contributes to overall attack surface visibility. May enable reconnaissance or provide context for more targeted attacks."

    @staticmethod
    def _assess_false_positive_risk(finding: Finding) -> FalsePositiveRisk:
        """Assess the likelihood of this being a false positive."""
        confidence = finding.confidence_score
        category = finding.category
        title_lower = finding.title.lower()

        # High confidence findings
        if confidence >= 0.9:
            return FalsePositiveRisk.LOW

        # Moderate confidence
        if confidence >= 0.7:
            if category == FindingCategory.SECURITY_WEAKNESS:
                return FalsePositiveRisk.LOW
            else:
                return FalsePositiveRisk.MEDIUM

        # Lower confidence findings
        if confidence < 0.7:
            if 'missing' in title_lower or 'not found' in title_lower:
                return FalsePositiveRisk.MEDIUM
            elif category == FindingCategory.EXPOSURE_OBSERVATION:
                return FalsePositiveRisk.HIGH
            else:
                return FalsePositiveRisk.MEDIUM

        return FalsePositiveRisk.MEDIUM

    @staticmethod
    def analyze_findings_batch(findings: List[Finding]) -> List[Finding]:
        """Apply intelligence analysis to a batch of findings."""
        return [SecurityIntelligenceAnalyzer.analyze_finding(finding) for finding in findings]


# Convenience functions for easy integration
def enhance_with_intelligence(finding: Finding) -> Finding:
    """Enhance a single finding with security intelligence."""
    return SecurityIntelligenceAnalyzer.analyze_finding(finding)


def enhance_findings_batch(findings: List[Finding]) -> List[Finding]:
    """Enhance a batch of findings with security intelligence."""
    return SecurityIntelligenceAnalyzer.analyze_findings_batch(findings)
