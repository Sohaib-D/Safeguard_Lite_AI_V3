from __future__ import annotations

import inspect

from backend.network.active_scanner import ActiveScanner
from backend.network.scanner_modules import webapp_scanner
from backend.services.report_generator import ReportGenerator


def test_report_generator_returns_standalone_html_document():
    generator = ReportGenerator()
    html = generator.generate_html_report(
        target="example.com",
        scan_result={
            "overall_risk_score": 12,
            "risk_grade": "A+",
            "scan_timestamp": "2026-05-12T00:00:00+00:00",
            "resolved_ip": "93.184.216.34",
        },
        analysis={
            "executive_summary": "Limited externally observable exposure.",
            "technical_summary": "No high-signal findings in supplied test data.",
            "risk_level": "Minimal",
            "vulnerabilities": [],
            "security_posture_breakdown": {},
            "compliance_gaps": {},
            "attack_vectors": [],
            "remediation_roadmap": [],
            "quick_wins": [],
        },
    )

    assert html.startswith("<!DOCTYPE html>")
    assert "<html" in html
    assert "<head>" in html
    assert "<style>" in html
    assert "</style>" in html
    assert "<body>" in html
    assert "</body>" in html
    assert html.rstrip().endswith("</html>")
    assert "@import url(" not in html
    assert ReportGenerator.REQUIRED_DISCLAIMER in html


def test_webapp_scanner_does_not_attempt_credentials():
    source = inspect.getsource(webapp_scanner.scan_webapp)

    assert '"pwd"' not in source
    assert "Default Credentials Allowed" not in source
    assert ".post(" not in source


def test_active_scanner_security_configs_are_conservative_observations():
    scanner = ActiveScanner()
    findings = scanner._evaluate_security(
        ports=[{"port": 22}, {"port": 8080}],
        headers={"Server": "nginx"},
        dns_info={},
    )

    assert isinstance(findings, list)
    assert findings

    ssh = next(item for item in findings if item["type"] == "SSH Exposure Observation")
    assert ssh["exploit_verified"] is False
    assert ssh["passive_only"] is True
    assert "not evidence of weak passwords" in ssh["description"]

    edge = next(item for item in findings if item["type"] == "No CDN/WAF Fingerprint Observed")
    assert edge["severity"] == "Info"
    assert "does not prove DDoS vulnerability" in edge["description"]
