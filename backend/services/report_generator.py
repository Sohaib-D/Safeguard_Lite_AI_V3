# backend/services/report_generator.py
"""
Professional HTML Security Report Generator for Safeguard-AI Lite.

Generates self-contained, print-ready HTML security assessment reports
with embedded CSS styling. No external CDN dependencies at runtime.
"""

import html
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


class ReportGenerator:
    """
    Generates professional cybersecurity audit reports in self-contained HTML format.
    Dark theme with Safeguard-AI brand colors, optimized for both screen and print.
    """

    # Brand Colors
    PRIMARY = "#38bdf8"       # Cyan
    CRITICAL = "#ef4444"      # Red
    HIGH = "#f59e0b"          # Amber
    MEDIUM = "#eab308"        # Yellow
    LOW = "#22c55e"           # Green
    INFO = "#6b7280"          # Gray
    BG_PRIMARY = "#0a0a0f"    # Deep black
    BG_CARD = "#111118"       # Card background
    BG_CARD_ALT = "#1a1a24"  # Alternate card
    BORDER = "#1e293b"        # Border color
    TEXT_PRIMARY = "#e2e8f0"  # Light text
    TEXT_SECONDARY = "#94a3b8" # Muted text
    REQUIRED_DISCLAIMER = (
        "This assessment was performed using non-invasive defensive reconnaissance "
        "techniques and does not verify exploitability or guarantee the absence of "
        "vulnerabilities."
    )

    def generate_html_report(self, target: str, scan_result: dict, analysis: dict) -> str:
        """
        Generate a complete, self-contained HTML security assessment report.

        Args:
            target: The scanned target (domain/IP/URL).
            scan_result: The raw deep scan result dictionary.
            analysis: The AI-generated (or fallback) analysis dictionary.

        Returns:
            Complete HTML string ready for rendering or download.
        """
        risk_score = scan_result.get("overall_risk_score", 0)
        risk_grade = scan_result.get("risk_grade", "N/A")
        scan_timestamp = scan_result.get("scan_timestamp", datetime.now(timezone.utc).isoformat())
        resolved_ip = scan_result.get("resolved_ip", "N/A")

        # Build all sections
        sections = [
            self._build_cover_page(target, risk_grade, risk_score, scan_timestamp),
            self._build_executive_summary(analysis),
            self._build_risk_gauge(risk_score, risk_grade),
            self._build_security_posture(analysis),
            self._build_vulnerability_table(analysis),
            self._build_compliance_section(analysis),
            self._build_attack_vectors(analysis),
            self._build_remediation_roadmap(analysis),
            self._build_quick_wins(analysis),
            self._build_footer(target, scan_timestamp),
        ]

        body_content = "\n".join(sections)

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Assessment Report - {html.escape(target)}</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}

        :root {{
            --primary: {self.PRIMARY};
            --critical: {self.CRITICAL};
            --high: {self.HIGH};
            --medium: {self.MEDIUM};
            --low: {self.LOW};
            --info: {self.INFO};
            --bg-primary: {self.BG_PRIMARY};
            --bg-card: {self.BG_CARD};
            --bg-card-alt: {self.BG_CARD_ALT};
            --border: {self.BORDER};
            --text-primary: {self.TEXT_PRIMARY};
            --text-secondary: {self.TEXT_SECONDARY};
        }}

        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Arial, sans-serif;
            background: var(--bg-primary);
            color: var(--text-primary);
            line-height: 1.6;
            font-size: 14px;
        }}

        .report-container {{
            max-width: 1100px;
            margin: 0 auto;
            padding: 40px 60px;
        }}

        /* Cover Page */
        .cover-page {{
            min-height: 100vh;
            display: flex;
            flex-direction: column;
            justify-content: center;
            align-items: center;
            text-align: center;
            page-break-after: always;
            position: relative;
            border-bottom: 1px solid var(--border);
            padding: 80px 0;
        }}

        .cover-logo {{
            width: 80px;
            height: 80px;
            border: 2px solid var(--primary);
            border-radius: 16px;
            display: flex;
            align-items: center;
            justify-content: center;
            margin-bottom: 40px;
            background: rgba(56, 189, 248, 0.05);
        }}

        .cover-logo svg {{
            width: 48px;
            height: 48px;
        }}

        .cover-title {{
            font-size: 32px;
            font-weight: 700;
            letter-spacing: 3px;
            text-transform: uppercase;
            color: var(--text-primary);
            margin-bottom: 8px;
        }}

        .cover-subtitle {{
            font-size: 14px;
            letter-spacing: 6px;
            text-transform: uppercase;
            color: var(--text-secondary);
            margin-bottom: 60px;
        }}

        .cover-target {{
            font-family: Consolas, 'Courier New', monospace;
            font-size: 22px;
            color: var(--primary);
            background: rgba(56, 189, 248, 0.08);
            padding: 12px 32px;
            border-radius: 8px;
            border: 1px solid rgba(56, 189, 248, 0.2);
            margin-bottom: 40px;
        }}

        .cover-grade {{
            width: 120px;
            height: 120px;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 48px;
            font-weight: 700;
            margin-bottom: 40px;
            border: 4px solid;
        }}

        .grade-aplus, .grade-a {{ border-color: var(--low); color: var(--low); background: rgba(34, 197, 94, 0.08); }}
        .grade-b {{ border-color: var(--primary); color: var(--primary); background: rgba(56, 189, 248, 0.08); }}
        .grade-c {{ border-color: var(--medium); color: var(--medium); background: rgba(234, 179, 8, 0.08); }}
        .grade-d {{ border-color: var(--high); color: var(--high); background: rgba(245, 158, 11, 0.08); }}
        .grade-f {{ border-color: var(--critical); color: var(--critical); background: rgba(239, 68, 68, 0.08); }}

        .cover-meta {{
            display: flex;
            gap: 40px;
            margin-top: 20px;
        }}

        .cover-meta-item {{
            text-align: center;
        }}

        .cover-meta-label {{
            font-size: 10px;
            letter-spacing: 2px;
            text-transform: uppercase;
            color: var(--text-secondary);
            margin-bottom: 4px;
        }}

        .cover-meta-value {{
            font-family: Consolas, 'Courier New', monospace;
            font-size: 13px;
            color: var(--text-primary);
        }}

        .classification {{
            position: absolute;
            top: 40px;
            right: 0;
            background: rgba(239, 68, 68, 0.1);
            border: 1px solid rgba(239, 68, 68, 0.3);
            color: var(--critical);
            padding: 6px 16px;
            font-size: 10px;
            letter-spacing: 3px;
            text-transform: uppercase;
            font-weight: 700;
            border-radius: 4px;
        }}

        /* Section Styles */
        .section {{
            margin: 60px 0;
            page-break-inside: avoid;
        }}

        .section-header {{
            display: flex;
            align-items: center;
            gap: 12px;
            margin-bottom: 24px;
            padding-bottom: 12px;
            border-bottom: 1px solid var(--border);
        }}

        .section-number {{
            font-family: Consolas, 'Courier New', monospace;
            font-size: 12px;
            color: var(--primary);
            background: rgba(56, 189, 248, 0.1);
            padding: 4px 10px;
            border-radius: 4px;
            border: 1px solid rgba(56, 189, 248, 0.2);
        }}

        .section-title {{
            font-size: 20px;
            font-weight: 600;
            color: var(--text-primary);
        }}

        /* Cards */
        .card {{
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 24px;
            margin-bottom: 16px;
        }}

        .card-alt {{
            background: var(--bg-card-alt);
        }}

        /* Executive Summary */
        .exec-summary {{
            font-size: 15px;
            line-height: 1.8;
            color: var(--text-primary);
        }}

        .tech-summary {{
            font-family: Consolas, 'Courier New', monospace;
            font-size: 13px;
            color: var(--text-secondary);
            margin-top: 16px;
            padding: 16px;
            background: var(--bg-card-alt);
            border-radius: 8px;
            border-left: 3px solid var(--primary);
        }}

        /* Risk Gauge */
        .gauge-container {{
            display: flex;
            justify-content: center;
            align-items: center;
            padding: 40px 0;
        }}

        .gauge-wrapper {{
            position: relative;
            width: 280px;
            height: 160px;
            overflow: hidden;
        }}

        .gauge-bg {{
            width: 280px;
            height: 280px;
            border-radius: 50%;
            border: 20px solid var(--bg-card-alt);
            position: absolute;
            top: 0;
            clip-path: polygon(0 0, 100% 0, 100% 50%, 0 50%);
        }}

        .gauge-fill {{
            width: 280px;
            height: 280px;
            border-radius: 50%;
            border: 20px solid transparent;
            position: absolute;
            top: 0;
            clip-path: polygon(0 0, 100% 0, 100% 50%, 0 50%);
        }}

        .gauge-score {{
            position: absolute;
            bottom: 10px;
            left: 50%;
            transform: translateX(-50%);
            text-align: center;
        }}

        .gauge-score-value {{
            font-size: 48px;
            font-weight: 700;
            font-family: Consolas, 'Courier New', monospace;
        }}

        .gauge-score-label {{
            font-size: 11px;
            letter-spacing: 2px;
            text-transform: uppercase;
            color: var(--text-secondary);
        }}

        /* Posture Bars */
        .posture-grid {{
            display: grid;
            gap: 16px;
        }}

        .posture-item {{
            display: grid;
            grid-template-columns: 180px 1fr 50px;
            align-items: center;
            gap: 16px;
        }}

        .posture-label {{
            font-size: 13px;
            color: var(--text-secondary);
            text-align: right;
        }}

        .posture-bar-bg {{
            height: 8px;
            background: var(--bg-card-alt);
            border-radius: 4px;
            overflow: hidden;
        }}

        .posture-bar-fill {{
            height: 100%;
            border-radius: 4px;
            transition: width 0.3s ease;
        }}

        .posture-value {{
            font-family: Consolas, 'Courier New', monospace;
            font-size: 13px;
            font-weight: 700;
        }}

        /* Vulnerability Table */
        .vuln-table {{
            width: 100%;
            border-collapse: collapse;
            font-size: 13px;
        }}

        .vuln-table th {{
            text-align: left;
            padding: 12px 16px;
            background: var(--bg-card-alt);
            color: var(--text-secondary);
            font-size: 10px;
            letter-spacing: 1.5px;
            text-transform: uppercase;
            border-bottom: 1px solid var(--border);
        }}

        .vuln-table td {{
            padding: 14px 16px;
            border-bottom: 1px solid var(--border);
            vertical-align: top;
        }}

        .vuln-table tr:hover {{
            background: rgba(56, 189, 248, 0.02);
        }}

        .severity-badge {{
            display: inline-block;
            padding: 3px 10px;
            border-radius: 4px;
            font-size: 11px;
            font-weight: 600;
            letter-spacing: 0.5px;
            text-transform: uppercase;
        }}

        .severity-critical {{ background: rgba(239, 68, 68, 0.15); color: var(--critical); border: 1px solid rgba(239, 68, 68, 0.3); }}
        .severity-high {{ background: rgba(245, 158, 11, 0.15); color: var(--high); border: 1px solid rgba(245, 158, 11, 0.3); }}
        .severity-medium {{ background: rgba(234, 179, 8, 0.15); color: var(--medium); border: 1px solid rgba(234, 179, 8, 0.3); }}
        .severity-low {{ background: rgba(34, 197, 94, 0.15); color: var(--low); border: 1px solid rgba(34, 197, 94, 0.3); }}
        .severity-informational {{ background: rgba(107, 114, 128, 0.15); color: var(--info); border: 1px solid rgba(107, 114, 128, 0.3); }}

        .cvss-score {{
            font-family: Consolas, 'Courier New', monospace;
            font-weight: 700;
            font-size: 14px;
        }}

        /* Compliance */
        .compliance-grid {{
            display: grid;
            grid-template-columns: repeat(2, 1fr);
            gap: 16px;
        }}

        .compliance-card {{
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 10px;
            padding: 20px;
        }}

        .compliance-card-title {{
            font-size: 12px;
            letter-spacing: 1.5px;
            text-transform: uppercase;
            color: var(--primary);
            margin-bottom: 12px;
            font-weight: 600;
        }}

        .compliance-item {{
            font-size: 13px;
            color: var(--text-secondary);
            padding: 4px 0;
            padding-left: 16px;
            position: relative;
        }}

        .compliance-item::before {{
            content: "›";
            position: absolute;
            left: 0;
            color: var(--primary);
        }}

        /* Attack Vectors */
        .attack-vector-card {{
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 10px;
            padding: 20px;
            margin-bottom: 12px;
            display: grid;
            grid-template-columns: 1fr auto auto;
            gap: 16px;
            align-items: start;
        }}

        .av-name {{
            font-weight: 600;
            font-size: 14px;
            color: var(--text-primary);
            margin-bottom: 6px;
        }}

        .av-desc {{
            font-size: 13px;
            color: var(--text-secondary);
            line-height: 1.5;
        }}

        .av-badge {{
            padding: 4px 10px;
            border-radius: 4px;
            font-size: 11px;
            font-weight: 600;
            text-align: center;
            white-space: nowrap;
        }}

        .likelihood-high {{ background: rgba(239, 68, 68, 0.1); color: var(--critical); }}
        .likelihood-medium {{ background: rgba(245, 158, 11, 0.1); color: var(--high); }}
        .likelihood-low {{ background: rgba(34, 197, 94, 0.1); color: var(--low); }}

        /* Roadmap */
        .roadmap-item {{
            display: grid;
            grid-template-columns: 40px 1fr auto auto;
            gap: 16px;
            align-items: center;
            padding: 16px 0;
            border-bottom: 1px solid var(--border);
        }}

        .roadmap-number {{
            width: 32px;
            height: 32px;
            border-radius: 50%;
            background: rgba(56, 189, 248, 0.1);
            border: 1px solid rgba(56, 189, 248, 0.3);
            display: flex;
            align-items: center;
            justify-content: center;
            font-family: Consolas, 'Courier New', monospace;
            font-size: 13px;
            font-weight: 700;
            color: var(--primary);
        }}

        .roadmap-action {{
            font-size: 13px;
            color: var(--text-primary);
            line-height: 1.5;
        }}

        .effort-badge {{
            padding: 3px 8px;
            border-radius: 4px;
            font-size: 10px;
            font-weight: 600;
            letter-spacing: 0.5px;
            text-transform: uppercase;
        }}

        .effort-low {{ background: rgba(34, 197, 94, 0.1); color: var(--low); }}
        .effort-medium {{ background: rgba(234, 179, 8, 0.1); color: var(--medium); }}
        .effort-high {{ background: rgba(239, 68, 68, 0.1); color: var(--critical); }}

        /* Quick Wins */
        .quick-win-item {{
            display: flex;
            align-items: flex-start;
            gap: 12px;
            padding: 12px 0;
            border-bottom: 1px solid rgba(30, 41, 59, 0.5);
        }}

        .quick-win-check {{
            width: 20px;
            height: 20px;
            border: 2px solid var(--primary);
            border-radius: 4px;
            flex-shrink: 0;
            margin-top: 2px;
        }}

        .quick-win-text {{
            font-size: 13px;
            color: var(--text-primary);
        }}

        /* Footer */
        .report-footer {{
            margin-top: 80px;
            padding-top: 24px;
            border-top: 1px solid var(--border);
            page-break-inside: avoid;
        }}

        .footer-disclaimer {{
            font-size: 11px;
            color: var(--text-secondary);
            line-height: 1.8;
            font-style: italic;
        }}

        .footer-meta {{
            display: flex;
            justify-content: space-between;
            margin-top: 24px;
            font-size: 11px;
            color: var(--text-secondary);
            font-family: Consolas, 'Courier New', monospace;
        }}

        /* Print Styles */
        @media print {{
            body {{
                background: white;
                color: #1a1a2e;
            }}

            .report-container {{
                padding: 20px 40px;
            }}

            .card, .compliance-card, .attack-vector-card {{
                background: #f8f9fa;
                border-color: #dee2e6;
            }}

            .cover-page {{
                min-height: auto;
                padding: 60px 0;
            }}

            .section {{
                page-break-inside: avoid;
            }}

            .vuln-table th {{
                background: #e9ecef;
            }}
        }}

        /* Responsive */
        @media (max-width: 768px) {{
            .report-container {{
                padding: 20px;
            }}

            .compliance-grid {{
                grid-template-columns: 1fr;
            }}

            .posture-item {{
                grid-template-columns: 120px 1fr 40px;
            }}

            .attack-vector-card {{
                grid-template-columns: 1fr;
            }}

            .cover-meta {{
                flex-direction: column;
                gap: 16px;
            }}
        }}
    </style>
</head>
<body>
    <div class="report-container">
        {body_content}
    </div>
</body>
</html>"""

    # =========================================================================
    # SECTION BUILDERS
    # =========================================================================

    def _build_cover_page(self, target: str, risk_grade: str, risk_score: int, timestamp: str) -> str:
        """Build the cover page with logo, title, target, and risk grade."""
        grade_class = self._get_grade_class(risk_grade)
        date_str = self._format_timestamp(timestamp)

        return f"""
        <div class="cover-page">
            <div class="classification">CONFIDENTIAL</div>
            <div class="cover-logo">
                <svg viewBox="0 0 24 24" fill="currentColor">
                    <path d="M12 2L2 7l10 5 10-5-10-5zM2 17l10 5 10-5M2 12l10 5 10-5"/>
                </svg>
            </div>
            <div class="cover-title">Security Assessment</div>
            <div class="cover-subtitle">Comprehensive Vulnerability Report</div>
            <div class="cover-target">{html.escape(target)}</div>
            <div class="cover-grade {grade_class}">{html.escape(risk_grade)}</div>
            <div class="cover-meta">
                <div class="cover-meta-item">
                    <div class="cover-meta-label">Date</div>
                    <div class="cover-meta-value">{date_str}</div>
                </div>
                <div class="cover-meta-item">
                    <div class="cover-meta-label">Risk Score</div>
                    <div class="cover-meta-value">{risk_score}/100</div>
                </div>
                <div class="cover-meta-item">
                    <div class="cover-meta-label">Engine</div>
                    <div class="cover-meta-value">Safeguard-AI Lite v2.0</div>
                </div>
            </div>
        </div>
        """

    def _build_executive_summary(self, analysis: dict) -> str:
        """Build the executive summary section."""
        exec_summary = html.escape(analysis.get("executive_summary", "No executive summary available."))
        tech_summary = html.escape(analysis.get("technical_summary", "No technical summary available."))
        risk_level = analysis.get("risk_level", "Unknown")
        severity_class = f"severity-{risk_level.lower()}" if risk_level.lower() in ("critical", "high", "medium", "low") else "severity-informational"

        return f"""
        <div class="section">
            <div class="section-header">
                <span class="section-number">01</span>
                <span class="section-title">Executive Summary</span>
                <span class="severity-badge {severity_class}">{html.escape(risk_level)}</span>
            </div>
            <div class="card">
                <p class="exec-summary">{exec_summary}</p>
                <div class="tech-summary">{tech_summary}</div>
            </div>
        </div>
        """

    def _build_risk_gauge(self, risk_score: int, risk_grade: str) -> str:
        """Build the risk score gauge visualization using pure CSS/SVG."""
        score_color = self._get_score_color(risk_score)
        # SVG arc for the gauge
        angle = (risk_score / 100) * 180
        # Calculate SVG arc path
        import math
        start_x = 140 - 110 * math.cos(math.radians(180))
        start_y = 140 - 110 * math.sin(math.radians(180))
        end_x = 140 - 110 * math.cos(math.radians(180 - angle))
        end_y = 140 - 110 * math.sin(math.radians(180 - angle))
        large_arc = 1 if angle > 180 else 0

        return f"""
        <div class="section">
            <div class="section-header">
                <span class="section-number">02</span>
                <span class="section-title">Risk Assessment</span>
            </div>
            <div class="card">
                <div class="gauge-container">
                    <div class="gauge-wrapper">
                        <svg viewBox="0 0 280 160" width="280" height="160">
                            <path d="M 30 140 A 110 110 0 0 1 250 140" fill="none" stroke="{self.BG_CARD_ALT}" stroke-width="20" stroke-linecap="round"/>
                            <path d="M {start_x} {start_y} A 110 110 0 {large_arc} 1 {end_x} {end_y}" fill="none" stroke="{score_color}" stroke-width="20" stroke-linecap="round"/>
                        </svg>
                        <div class="gauge-score">
                            <div class="gauge-score-value" style="color:{score_color}">{risk_score}</div>
                            <div class="gauge-score-label">RISK SCORE</div>
                        </div>
                    </div>
                </div>
                <p style="text-align:center;color:{self.TEXT_SECONDARY};font-size:13px;">
                    Grade: {html.escape(risk_grade)} &nbsp;|&nbsp; {self._get_risk_description(risk_score)}
                </p>
            </div>
        </div>
        """

    def _build_security_posture(self, analysis: dict) -> str:
        """Build the security posture breakdown with horizontal bars."""
        posture = analysis.get("security_posture_breakdown", {})

        categories = [
            ("Network Security", posture.get("network_security", 0)),
            ("Application Security", posture.get("application_security", 0)),
            ("SSL/TLS Hygiene", posture.get("ssl_tls_hygiene", 0)),
            ("Header Security", posture.get("header_security", 0)),
            ("Information Disclosure", posture.get("information_disclosure", 0)),
        ]

        bars_html = ""
        for label, score in categories:
            color = self._get_score_color(100 - score)  # Invert for "lower is better" display
            bar_color = self._get_posture_color(score)
            bars_html += f"""
            <div class="posture-item">
                <div class="posture-label">{html.escape(label)}</div>
                <div class="posture-bar-bg">
                    <div class="posture-bar-fill" style="width:{score}%;background:{bar_color}"></div>
                </div>
                <div class="posture-value" style="color:{bar_color}">{score}</div>
            </div>
            """

        return f"""
        <div class="section">
            <div class="section-header">
                <span class="section-number">03</span>
                <span class="section-title">Security Posture Breakdown</span>
            </div>
            <div class="card">
                <div class="posture-grid">
                    {bars_html}
                </div>
                <p style="text-align:center;color:{self.TEXT_SECONDARY};font-size:11px;margin-top:16px;">
                    Scale: 0 (Critical) → 100 (Excellent)
                </p>
            </div>
        </div>
        """

    def _build_vulnerability_table(self, analysis: dict) -> str:
        """Build the vulnerability table sorted by CVSS score descending."""
        vulns = analysis.get("vulnerabilities", [])

        # Sort by CVSS score descending
        vulns_sorted = sorted(vulns, key=lambda v: v.get("cvss_score", 0), reverse=True)

        if not vulns_sorted:
            return f"""
            <div class="section">
                <div class="section-header">
                    <span class="section-number">04</span>
                    <span class="section-title">Technical Findings</span>
                </div>
                <div class="card">
                    <p style="color:{self.LOW}">&#10003; No reportable technical findings identified from this non-invasive assessment</p>
                </div>
            </div>
            """

        rows_html = ""
        for vuln in vulns_sorted:
            severity = vuln.get("severity", "Informational")
            severity_class = f"severity-{severity.lower()}"
            cvss = vuln.get("cvss_score", 0)
            cvss_color = self._get_cvss_color(cvss)

            rows_html += f"""
            <tr>
                <td>{html.escape(str(vuln.get('id', 'N/A')))}</td>
                <td>
                    <strong>{html.escape(str(vuln.get('title', 'Unknown')))}</strong><br/>
                    <span style="color:{self.TEXT_SECONDARY};font-size:12px">{html.escape(str(vuln.get('description', '')[:120]))}</span>
                </td>
                <td><span class="severity-badge {severity_class}">{html.escape(severity)}</span></td>
                <td><span class="cvss-score" style="color:{cvss_color}">{cvss:.1f}</span></td>
                <td>{html.escape(str(vuln.get('category', 'N/A')))}</td>
            </tr>
            """

        return f"""
        <div class="section">
            <div class="section-header">
                <span class="section-number">04</span>
                <span class="section-title">Technical Findings ({len(vulns_sorted)})</span>
            </div>
            <div class="card">
                <table class="vuln-table">
                    <thead>
                        <tr>
                            <th>ID</th>
                            <th>Finding</th>
                            <th>Severity</th>
                            <th>CVSS</th>
                            <th>Category</th>
                        </tr>
                    </thead>
                    <tbody>
                        {rows_html}
                    </tbody>
                </table>
            </div>
            {self._build_vuln_details(vulns_sorted[:5])}
        </div>
        """

    def _build_vuln_details(self, vulns: List[dict]) -> str:
        """Build detailed vulnerability descriptions for top findings."""
        if not vulns:
            return ""

        details_html = ""
        for vuln in vulns:
            severity = vuln.get("severity", "Informational")
            severity_class = f"severity-{severity.lower()}"

            refs = vuln.get("references", [])
            refs_html = ""
            if refs:
                refs_html = f"""
                    References: {', '.join([html.escape(str(r)) for r in refs[:3]])}
                """

            details_html += f"""
            <div class="card card-alt" style="margin-top:12px">
                <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px">
                    <strong>{html.escape(str(vuln.get('id', '')))}: {html.escape(str(vuln.get('title', '')))}</strong>
                    <span class="severity-badge {severity_class}">{html.escape(severity)}</span>
                </div>
                <p style="font-size:13px;color:{self.TEXT_SECONDARY};margin-bottom:8px">
                    <strong>Technical Detail:</strong> {html.escape(str(vuln.get('technical_detail', 'N/A')))}
                </p>
                <p style="font-size:13px;color:{self.TEXT_SECONDARY};margin-bottom:8px">
                    <strong>Exploitation:</strong> {html.escape(str(vuln.get('exploitation_scenario', 'N/A')))}
                </p>
                <p style="font-size:13px;color:{self.TEXT_SECONDARY};margin-bottom:8px">
                    <strong>Remediation:</strong> {html.escape(str(vuln.get('remediation', 'N/A')))}
                </p>
                {refs_html}
            </div>
            """

        return f"""
        <div class="card" style="margin-top:24px">
            <h3 style="font-size:14px;color:{self.PRIMARY};margin-bottom:12px">Detailed Findings (Top {len(vulns)})</h3>
            {details_html}
        </div>
        """

    def _build_compliance_section(self, analysis: dict) -> str:
        """Build the compliance gaps section."""
        compliance = analysis.get("compliance_gaps", {})

        owasp = compliance.get("owasp_top_10", [])
        pci = compliance.get("pci_dss", "Not assessed")
        gdpr = compliance.get("gdpr_relevant", "Not assessed")
        iso = compliance.get("iso27001_gaps", [])

        owasp_items = "\n".join([f'<div class="compliance-item">{html.escape(str(item))}</div>' for item in owasp]) if owasp else '<div class="compliance-item">No gaps identified</div>'
        iso_items = "\n".join([f'<div class="compliance-item">{html.escape(str(item))}</div>' for item in iso]) if iso else '<div class="compliance-item">No gaps identified</div>'

        return f"""
        <div class="section">
            <div class="section-header">
                <span class="section-number">05</span>
                <span class="section-title">Compliance Assessment</span>
            </div>
            <div class="compliance-grid">
                <div class="compliance-card">
                    <div class="compliance-card-title">OWASP Top 10 (2021)</div>
                    {owasp_items}
                </div>
                <div class="compliance-card">
                    <div class="compliance-card-title">ISO 27001 Controls</div>
                    {iso_items}
                </div>
                <div class="compliance-card">
                    <div class="compliance-card-title">PCI DSS</div>
                    <div class="compliance-item">{html.escape(str(pci))}</div>
                </div>
                <div class="compliance-card">
                    <div class="compliance-card-title">GDPR Relevance</div>
                    <div class="compliance-item">{html.escape(str(gdpr))}</div>
                </div>
            </div>
        </div>
        """

    def _build_attack_vectors(self, analysis: dict) -> str:
        """Build the attack vectors section."""
        vectors = analysis.get("attack_vectors", [])

        if not vectors:
            return f"""
            <div class="section">
                <div class="section-header">
                    <span class="section-number">06</span>
                    <span class="section-title">Attack Vector Analysis</span>
                </div>
                <div class="card">
                    <p style="color:{self.LOW}">&#10003; No significant attack vectors identified</p>
                </div>
            </div>
            """

        vectors_html = ""
        for av in vectors:
            likelihood = av.get("likelihood", "Low")
            impact = av.get("impact", "Low")
            likelihood_class = f"likelihood-{likelihood.lower()}"
            impact_class = f"likelihood-{impact.lower()}"

            vectors_html += f"""
            <div class="attack-vector-card">
                <div>
                    <div class="av-name">{html.escape(str(av.get('vector', 'Unknown')))}</div>
                    <div class="av-desc">{html.escape(str(av.get('description', '')))}</div>
                </div>
                <div>
                    <div style="font-size:10px;color:{self.TEXT_SECONDARY};margin-bottom:4px">Likelihood</div>
                    <span class="av-badge {likelihood_class}">{html.escape(likelihood)}</span>
                </div>
                <div>
                    <div style="font-size:10px;color:{self.TEXT_SECONDARY};margin-bottom:4px">Impact</div>
                    <span class="av-badge {impact_class}">{html.escape(impact)}</span>
                </div>
            </div>
            """

        return f"""
        <div class="section">
            <div class="section-header">
                <span class="section-number">06</span>
                <span class="section-title">Attack Vector Analysis</span>
            </div>
            {vectors_html}
        </div>
        """

    def _build_remediation_roadmap(self, analysis: dict) -> str:
        """Build the remediation roadmap with priority ordering."""
        roadmap = analysis.get("remediation_roadmap", [])

        if not roadmap:
            return ""

        items_html = ""
        for item in roadmap[:10]:  # Limit to top 10
            priority = item.get("priority", 0)
            action = item.get("action", "N/A")
            effort = item.get("effort", "Medium")
            impact = item.get("impact", "Medium")
            effort_class = f"effort-{effort.lower()}" if effort.lower() in ("low", "medium", "high") else "effort-medium"
            impact_severity = f"severity-{impact.lower()}" if impact.lower() in ("critical", "high", "medium", "low") else "severity-medium"

            items_html += f"""
            <div class="roadmap-item">
                <div class="roadmap-number">{priority}</div>
                <div class="roadmap-action">{html.escape(str(action)[:200])}</div>
                <span class="effort-badge {effort_class}">{html.escape(effort)}</span>
                <span class="severity-badge severity-{impact.lower() if impact.lower() in ('critical','high','medium','low') else 'medium'}">{html.escape(impact)}</span>
            </div>
            """

        return f"""
        <div class="section">
            <div class="section-header">
                <span class="section-number">07</span>
                <span class="section-title">Remediation Roadmap</span>
            </div>
            <div class="card">
                {items_html}
            </div>
        </div>
        """

    def _build_quick_wins(self, analysis: dict) -> str:
        """Build the quick wins checklist."""
        quick_wins = analysis.get("quick_wins", [])

        if not quick_wins:
            return ""

        items_html = ""
        for win in quick_wins:
            items_html += f"""
            <div class="quick-win-item">
                <div class="quick-win-check"></div>
                <div class="quick-win-text">{html.escape(str(win))}</div>
            </div>
            """

        return f"""
        <div class="section">
            <div class="section-header">
                <span class="section-number">08</span>
                <span class="section-title">Quick Wins (High Impact, Low Effort)</span>
            </div>
            <div class="card">
                {items_html}
            </div>
        </div>
        """

    def _build_footer(self, target: str, timestamp: str) -> str:
        """Build the report footer with disclaimer."""
        date_str = self._format_timestamp(timestamp)

        return f"""
        <div class="report-footer">
            <div class="footer-disclaimer">
                <strong>Disclaimer:</strong> {html.escape(self.REQUIRED_DISCLAIMER)}
                The findings represent a point-in-time snapshot and should be interpreted as defensive
                observations, not proof of compromise or verified exploitability. This report is classified
                as CONFIDENTIAL and should only be shared with authorized personnel.
            </div>
            <div class="footer-meta">
                <span>Generated by Safeguard-AI Lite v2.0</span>
                <span>Target: {html.escape(target)}</span>
                <span>{date_str}</span>
            </div>
        </div>
        """

    # =========================================================================
    # UTILITY METHODS
    # =========================================================================

    def _get_grade_class(self, grade: str) -> str:
        """Return CSS class for risk grade."""
        grade_map = {
            "A+": "grade-aplus",
            "A": "grade-a",
            "B": "grade-b",
            "C": "grade-c",
            "D": "grade-d",
            "F": "grade-f",
        }
        return grade_map.get(grade, "grade-c")

    def _get_score_color(self, score: int) -> str:
        """Return color based on risk score (0=safe/green, 100=dangerous/red)."""
        if score <= 15:
            return self.LOW
        elif score <= 25:
            return self.LOW
        elif score <= 40:
            return self.PRIMARY
        elif score <= 60:
            return self.MEDIUM
        elif score <= 80:
            return self.HIGH
        else:
            return self.CRITICAL

    def _get_posture_color(self, score: int) -> str:
        """Return color for posture score (100=good/green, 0=bad/red)."""
        if score >= 80:
            return self.LOW
        elif score >= 60:
            return self.PRIMARY
        elif score >= 40:
            return self.MEDIUM
        elif score >= 20:
            return self.HIGH
        else:
            return self.CRITICAL

    def _get_cvss_color(self, cvss: float) -> str:
        """Return color for CVSS score."""
        if cvss >= 9.0:
            return self.CRITICAL
        elif cvss >= 7.0:
            return self.HIGH
        elif cvss >= 4.0:
            return self.MEDIUM
        elif cvss >= 0.1:
            return self.LOW
        else:
            return self.INFO

    def _get_risk_description(self, score: int) -> str:
        """Return professional risk description."""
        if score <= 15:
            return "Minimal externally observable risk"
        elif score <= 25:
            return "Low observable exposure with minor hardening opportunities"
        elif score <= 40:
            return "Moderate security concerns identified"
        elif score <= 60:
            return "Elevated attack surface — multiple gaps observed"
        elif score <= 80:
            return "High-risk exposure — significant remediation recommended"
        else:
            return "Critical exposure — immediate remediation required"

    def _format_timestamp(self, timestamp: str) -> str:
        """Format ISO timestamp to readable date."""
        try:
            dt = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
            return dt.strftime("%B %d, %Y at %H:%M UTC")
        except (ValueError, AttributeError):
            return datetime.now(timezone.utc).strftime("%B %d, %Y at %H:%M UTC")
