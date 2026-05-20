"""
Central evidence-driven findings model for all scanner modules.
Every finding across the platform must conform to this schema.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field, field_validator


class Severity(str, Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFORMATIONAL = "Informational"


class ConfidenceLevel(str, Enum):
    CONFIRMED = "Confirmed"
    HIGH_CONFIDENCE = "High Confidence"
    MODERATE_CONFIDENCE = "Moderate Confidence"
    HEURISTIC_OBSERVATION = "Heuristic Observation"
    INFORMATIONAL = "Informational"


class ObservationType(str, Enum):
    EXPOSURE = "exposure"
    MISCONFIGURATION = "misconfiguration"
    WEAKNESS = "weakness"
    INFORMATIONAL = "informational"


class Exploitability(str, Enum):
    UNVERIFIED = "unverified"
    UNLIKELY = "unlikely"
    POSSIBLE = "possible"
    UNKNOWN = "unknown"


class FalsePositiveRisk(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class FindingCategory(str, Enum):
    VULNERABILITY = "Vulnerability"
    SECURITY_WEAKNESS = "Security Weakness"
    CONFIGURATION_GAP = "Configuration Gap"
    EXPOSURE_OBSERVATION = "Exposure Observation"
    HARDENING_RECOMMENDATION = "Hardening Recommendation"
    INFORMATIONAL = "Informational"
    COMPLIANCE_GAP = "Compliance Gap"


class Evidence(BaseModel):
    """Structured evidence supporting a finding."""
    raw_data: str = Field(..., description="Raw observed data supporting the finding")
    source: str = Field(..., description="Where the evidence was collected from")
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    context: Optional[str] = Field(None, description="Additional context for interpretation")


class ComplianceMapping(BaseModel):
    """Maps a finding to compliance frameworks."""
    cwe: Optional[str] = Field(None, description="CWE identifier, e.g. CWE-693")
    owasp_top_10: Optional[str] = Field(None, description="OWASP Top 10 category, e.g. A05:2021")
    cve: Optional[str] = Field(None, description="CVE identifier if applicable")
    pci_dss: Optional[str] = Field(None, description="PCI DSS requirement reference")
    iso_27001: Optional[str] = Field(None, description="ISO 27001 control reference")
    nist: Optional[str] = Field(None, description="NIST CSF reference")


class Finding(BaseModel):
    """
    Universal finding schema for all scanner modules.
    Every scanner must produce findings conforming to this model.
    """
    title: str = Field(..., description="Clear, concise finding title")
    category: FindingCategory = Field(..., description="Classification of the finding type")
    severity: Severity = Field(..., description="Risk severity level")
    confidence_score: float = Field(
        ..., ge=0.0, le=1.0,
        description="Confidence in the finding accuracy (0.0-1.0)"
    )
    confidence_level: ConfidenceLevel = Field(
        ..., description="Human-readable confidence classification"
    )
    evidence: Evidence = Field(..., description="Supporting evidence for the finding")
    reasoning: str = Field(
        ...,
        description="Explanation of why this finding matters and how it was determined"
    )
    detection_method: str = Field(
        ..., description="Technical method used to detect this finding"
    )
    affected_asset: str = Field(
        ..., description="The specific asset, component, or endpoint affected"
    )
    exploit_verified: bool = Field(
        False,
        description="Whether exploitability has been verified (always False for passive scans)"
    )
    passive_only: bool = Field(
        True,
        description="Whether detection used only passive/non-invasive techniques"
    )
    remediation: str = Field(
        ...,
        description="Recommended remediation action"
    )
    references: list[str] = Field(
        default_factory=list,
        description="Reference URLs for further information"
    )
    compliance: Optional[ComplianceMapping] = Field(
        None, description="Compliance framework mappings"
    )

    # NEW INTELLIGENCE FIELDS
    observation_type: ObservationType = Field(
        default=ObservationType.INFORMATIONAL, description="Type of security observation made"
    )
    exploitability: Exploitability = Field(
        default=Exploitability.UNKNOWN, description="Assessment of exploitability potential"
    )
    real_world_impact: str = Field(
        default="", description="Real-world security impact and risk implications"
    )
    attack_surface_context: str = Field(
        default="", description="How this finding affects the attack surface"
    )
    false_positive_risk: FalsePositiveRisk = Field(
        default=FalsePositiveRisk.MEDIUM, description="Likelihood this finding is a false positive"
    )

    @field_validator("confidence_level", mode="before")
    @classmethod
    def derive_confidence_level(cls, v, info):
        """If not explicitly set, derive from confidence_score."""
        if v is not None:
            return v
        score = info.data.get("confidence_score", 0.5)
        if score >= 0.95:
            return ConfidenceLevel.CONFIRMED
        elif score >= 0.80:
            return ConfidenceLevel.HIGH_CONFIDENCE
        elif score >= 0.60:
            return ConfidenceLevel.MODERATE_CONFIDENCE
        elif score >= 0.40:
            return ConfidenceLevel.HEURISTIC_OBSERVATION
        return ConfidenceLevel.INFORMATIONAL

    def to_legacy_dict(self) -> dict[str, Any]:
        """Convert to legacy dict format for backward compatibility."""
        result = {
            "title": self.title,
            "category": self.category.value,
            "severity": self.severity.value,
            "confidence_score": self.confidence_score,
            "confidence_level": self.confidence_level.value,
            "evidence": self.evidence.raw_data,
            "reasoning": self.reasoning,
            "detection_method": self.detection_method,
            "affected_asset": self.affected_asset,
            "exploit_verified": self.exploit_verified,
            "passive_only": self.passive_only,
            "remediation": self.remediation,
            "references": self.references,
            # NEW INTELLIGENCE FIELDS
            "observation_type": self.observation_type.value,
            "exploitability": self.exploitability.value,
            "real_world_impact": self.real_world_impact,
            "attack_surface_context": self.attack_surface_context,
            "false_positive_risk": self.false_positive_risk.value,
        }
        if self.compliance:
            result["cwe"] = self.compliance.cwe
            result["owasp"] = self.compliance.owasp_top_10
            result["cve"] = self.compliance.cve
        return result


class ScanMetadata(BaseModel):
    """Metadata for a scan execution."""
    scan_id: str = Field(..., description="Unique scan identifier")
    target: str = Field(..., description="Scan target")
    scanner_module: str = Field(..., description="Name of the scanner module")
    start_time: datetime = Field(default_factory=datetime.utcnow)
    end_time: Optional[datetime] = None
    duration_seconds: Optional[float] = None
    success: bool = True
    error_message: Optional[str] = None
    passive_only: bool = True
    scan_type: str = "reconnaissance"


class ModuleScanResult(BaseModel):
    """Standard result from any scanner module."""
    metadata: ScanMetadata
    findings: list[Finding] = Field(default_factory=list)
    raw_data: dict[str, Any] = Field(
        default_factory=dict,
        description="Module-specific raw data for backward compatibility"
    )


def confidence_from_score(score: float) -> ConfidenceLevel:
    """Utility to derive confidence level from numeric score."""
    if score >= 0.95:
        return ConfidenceLevel.CONFIRMED
    elif score >= 0.80:
        return ConfidenceLevel.HIGH_CONFIDENCE
    elif score >= 0.60:
        return ConfidenceLevel.MODERATE_CONFIDENCE
    elif score >= 0.40:
        return ConfidenceLevel.HEURISTIC_OBSERVATION
    return ConfidenceLevel.INFORMATIONAL


def create_finding(
    title: str,
    category: FindingCategory | str,
    severity: Severity | str,
    confidence_score: float,
    evidence_raw: str,
    evidence_source: str,
    reasoning: str,
    detection_method: str,
    affected_asset: str,
    remediation: str,
    references: list[str] | None = None,
    exploit_verified: bool = False,
    passive_only: bool = True,
    cwe: str | None = None,
    owasp: str | None = None,
    cve: str | None = None,
    pci_dss: str | None = None,
    evidence_context: str | None = None,
) -> Finding:
    """Factory function to create a Finding with proper defaults."""
    if isinstance(category, str):
        category = FindingCategory(category)
    if isinstance(severity, str):
        severity = Severity(severity)

    compliance = None
    if any([cwe, owasp, cve, pci_dss]):
        compliance = ComplianceMapping(
            cwe=cwe, owasp_top_10=owasp, cve=cve, pci_dss=pci_dss
        )

    return Finding(
        title=title,
        category=category,
        severity=severity,
        confidence_score=confidence_score,
        confidence_level=confidence_from_score(confidence_score),
        evidence=Evidence(
            raw_data=evidence_raw,
            source=evidence_source,
            context=evidence_context,
        ),
        reasoning=reasoning,
        detection_method=detection_method,
        affected_asset=affected_asset,
        exploit_verified=exploit_verified,
        passive_only=passive_only,
        remediation=remediation,
        references=references or [],
        compliance=compliance,
    )