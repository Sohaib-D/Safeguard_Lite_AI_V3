#!/usr/bin/env python3
"""
Demonstration of the new Security Intelligence Layer for Safeguard-AI Lite.

This script shows how raw scan findings are transformed into actionable
security intelligence with real-world impact analysis.
"""

import asyncio
from backend.schemas.findings import create_finding, FindingCategory, Severity
from backend.services.security_intelligence import enhance_with_intelligence


async def demonstrate_intelligence_layer():
    """Demonstrate the intelligence layer transformation."""

    print("🔍 SAFEGUARD-AI LITE - SECURITY INTELLIGENCE DEMONSTRATION")
    print("=" * 70)

    # Create a raw finding (like the old system would produce)
    raw_finding = create_finding(
        title="SSL/TLS Connection Failed",
        category=FindingCategory.SECURITY_WEAKNESS,
        severity=Severity.HIGH,
        confidence_score=0.85,
        evidence_raw="Connection to https://example.com:443 failed with timeout",
        evidence_source="HTTP scanner timeout on port 443",
        reasoning="Unable to establish HTTPS connection to the target",
        detection_method="HTTP connection attempt",
        affected_asset="https://example.com",
        remediation="Ensure HTTPS service is running and accessible",
        references=["RFC 2818"],
    )

    print("\n📋 RAW FINDING (Old System Output):")
    print("-" * 40)
    legacy_dict = raw_finding.to_legacy_dict()
    for key, value in legacy_dict.items():
        if key != "evidence":  # Skip full evidence for brevity
            print(f"{key}: {value}")
    print(f"evidence: {legacy_dict['evidence'][:60]}...")

    # Apply intelligence layer
    intelligent_finding = enhance_with_intelligence(raw_finding)

    print("\n🧠 ENHANCED WITH SECURITY INTELLIGENCE (New System Output):")
    print("-" * 40)
    enhanced_dict = intelligent_finding.to_legacy_dict()
    for key, value in enhanced_dict.items():
        if key not in ["evidence"]:  # Skip full evidence for brevity
            print(f"{key}: {value}")

    print("\n🎯 INTELLIGENCE ANALYSIS:")
    print("-" * 40)
    print(f"• Observation Type: {intelligent_finding.observation_type.value}")
    print(f"• Exploitability: {intelligent_finding.exploitability.value}")
    print(f"• False Positive Risk: {intelligent_finding.false_positive_risk.value}")
    print(f"• Real World Impact: {intelligent_finding.real_world_impact}")
    print(f"• Attack Surface Context: {intelligent_finding.attack_surface_context}")

    print("\n📊 COMPARISON:")
    print("-" * 40)
    print("OLD SYSTEM: 'SSL/TLS not properly configured → High risk'")
    print("NEW SYSTEM: Provides context about service exposure, confidence levels,")
    print("            and realistic attack scenarios instead of alarmist claims.")

    # Demonstrate another example
    print("\n" + "=" * 70)
    print("🔍 SECOND EXAMPLE - CORS Misconfiguration")

    cors_finding = create_finding(
        title="CORS Allows Any Origin with Credentials",
        category=FindingCategory.SECURITY_WEAKNESS,
        severity=Severity.CRITICAL,
        confidence_score=0.98,
        evidence_raw="ACAO: *, ACAC: true",
        evidence_source="CORS probe response",
        reasoning="CORS policy permits any origin with credentials",
        detection_method="CORS preflight request analysis",
        affected_asset="https://example.com/api",
        remediation="Never use ACAO: * with credentials",
        references=["CWE-942", "OWASP A01:2021"],
    )

    intelligent_cors = enhance_with_intelligence(cors_finding)

    print("\n🧠 INTELLIGENCE ENHANCEMENT:")
    print("-" * 40)
    print(f"• Real World Impact: {intelligent_cors.real_world_impact}")
    print(f"• Attack Surface Context: {intelligent_cors.attack_surface_context}")
    print(f"• Exploitability Assessment: {intelligent_cors.exploitability.value}")
    print(f"• False Positive Risk: {intelligent_cors.false_positive_risk.value}")

    print("\n✅ RESULT: Security engineers now get actionable intelligence")
    print("   instead of raw scan output, enabling better decision-making.")


if __name__ == "__main__":
    asyncio.run(demonstrate_intelligence_layer())