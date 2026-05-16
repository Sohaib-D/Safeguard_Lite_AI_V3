"""
Typed schemas for scan results, risk scoring, and report generation.
These provide structure while maintaining backward compatibility with existing dict-based flows.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field


class RiskGrade(str, Enum):
    """Risk posture grades with conservative language."""
    MINIMAL = "A"  # Minimal externally observable risk
    LOW = "B"  # Low exposure with minor gaps
    MODERATE = "C"  # Moderate exposure requiring attention
    ELEVATED = "D"  # Elevated attack surface
    HIGH = "F"  # Significant exposure concerns


class RiskPostureLabel(str, Enum):
    """Human-readable risk posture descriptions."""
    MINIMAL = "Minimal externally observable risk"
    LOW = "Low exposure with minor hardening gaps"
    MODERATE = "Moderate exposure requiring attention"
    ELEVATED = "Elevated attack surface with multiple gaps"
    HIGH = "Significant exposure concerns identified"
    STRONG_EDGE = "Strong edge-layer security posture observed"


class PortInfo(BaseModel):
    port: int
    service: str
    banner: Optional[str] = None
    state: str = "open"
    protocol: str = "tcp"


class PortScanResult(BaseModel):
    open_ports: list[PortInfo] = Field(default_factory=list)
    open_count: int = 0
    total_scanned: int = 0
    scan_duration_seconds: float = 0.0
    banners: dict[str, str] = Field(default_factory=dict)


class TLSInfo(BaseModel):
    is_valid: bool = False
    days_until_expiry: Optional[int] = None
    protocol_version: Optional[str] = None
    cipher_suite: Optional[str] = None
    is_self_signed: bool = False
    domain_match: bool = True
    hsts_enabled: bool = False
    ocsp_stapling: bool = False
    certificate_chain_valid: bool = False
    has_error: bool = False
    error_message: Optional[str] = None


class TLSScanResult(BaseModel):
    certificate: TLSInfo = Field(default_factory=TLSInfo)
    protocol: dict[str, Any] = Field(default_factory=dict)
    cipher: dict[str, Any] = Field(default_factory=dict)


class HTTPHeadersResult(BaseModel):
    headers: dict[str, str] = Field(default_factory=dict)
    missing_security_headers: list[str] = Field(default_factory=list)
    cors_issues: list[dict[str, Any]] = Field(default_factory=list)
    cookie_issues: list[dict[str, Any]] = Field(default_factory=list)
    sensitive_files: list[str] = Field(default_factory=list)
    redirect_chain: list[str] = Field(default_factory=list)
    security_txt: Optional[str] = None
    robots_txt: Optional[str] = None


class TechnologyResult(BaseModel):
    web_server: Optional[str] = None
    backend_framework: Optional[str] = None
    cms: Optional[str] = None
    cdn: Optional[str] = None
    waf_detected: bool = False
    javascript_libraries: list[str] = Field(default_factory=list)
    cloud_provider: Optional[str] = None
    additional: dict[str, Any] = Field(default_factory=dict)


class DNSResult(BaseModel):
    spf_status: str = "Unknown"
    dkim_found: bool = False
    dmarc_policy: str = "Unknown"
    zone_transfer_possible: bool = False
    dnssec_enabled: bool = False
    caa_records: list[str] = Field(default_factory=list)
    ns_records: list[str] = Field(default_factory=list)
    mx_records: list[str] = Field(default_factory=list)
    a_records: list[str] = Field(default_factory=list)
    txt_records: list[str] = Field(default_factory=list)


class WHOISResult(BaseModel):
    registrar: Optional[str] = None
    creation_date: Optional[str] = None
    expiry_date: Optional[str] = None
    name_servers: list[str] = Field(default_factory=list)
    status: list[str] = Field(default_factory=list)
    dnssec: Optional[str] = None


class CVEMatch(BaseModel):
    software: str
    version: str
    cve: str
    cvss: float
    description: str
    severity: str
    confidence: float = 0.7
    exploit_maturity: str = "Unknown"
    disclosure_date: Optional[str] = None
    references: list[str] = Field(default_factory=list)


class CVEScanResult(BaseModel):
    matched_cves: list[CVEMatch] = Field(default_factory=list)
    eol_software: list[str] = Field(default_factory=list)
    total_critical_cves: int = 0
    total_high_cves: int = 0


class SeverityCounts(BaseModel):
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    informational: int = 0


class SecurityPostureBreakdown(BaseModel):
    network_security: int = Field(0, ge=0, le=100)
    application_security: int = Field(0, ge=0, le=100)
    ssl_tls_hygiene: int = Field(0, ge=0, le=100)
    header_security: int = Field(0, ge=0, le=100)
    information_disclosure: int = Field(0, ge=0, le=100)
    dns_security: int = Field(0, ge=0, le=100)
    compliance_posture: int = Field(0, ge=0, le=100)


class DeepScanResult(BaseModel):
    """
    Full deep scan result schema.
    Maintains backward compatibility with existing frontend expectations.
    """
    target: str
    clean_target: str
    resolved_ip: Optional[str] = None
    quick_scan: bool = True
    scan_timestamp: str = Field(default_factory=lambda: datetime.utcnow().isoformat())
    scan_id: Optional[str] = None

    # Risk assessment
    overall_risk_score: int = Field(0, ge=0, le=100)
    risk_grade: str = "B"
    risk_posture_label: str = RiskPostureLabel.LOW.value
    severity_counts: dict[str, int] = Field(
        default_factory=lambda: {"critical": 0, "high": 0, "medium": 0, "low": 0, "informational": 0}
    )
    critical_findings: list[str] = Field(default_factory=list)
    total_findings: int = 0

    # Module results (backward-compatible dict format)
    ports: dict[str, Any] = Field(default_factory=dict)
    ssl: dict[str, Any] = Field(default_factory=dict)
    http_headers: dict[str, Any] = Field(default_factory=dict)
    dns: dict[str, Any] = Field(default_factory=dict)
    technologies: dict[str, Any] = Field(default_factory=dict)
    whois: dict[str, Any] = Field(default_factory=dict)
    cve_scan: dict[str, Any] = Field(default_factory=dict)

    # Normalized findings (new field, additive)
    findings_normalized: list[dict[str, Any]] = Field(default_factory=list)

    # Raw module data for debugging/analysis
    raw_modules: dict[str, Any] = Field(default_factory=dict)

    # Scan limitations and methodology
    scan_limitations: list[str] = Field(default_factory=list)
    methodology_notes: list[str] = Field(default_factory=list)

    def to_legacy_dict(self) -> dict[str, Any]:
        """Convert to legacy dict format for backward compatibility."""
        return self.model_dump()


class AnalysisResult(BaseModel):
    """Schema for AI/fallback analysis results."""
    executive_summary: str = ""
    technical_summary: str = ""
    risk_level: str = ""
    attack_surface_score: int = 0
    vulnerabilities: list[dict[str, Any]] = Field(default_factory=list)
    compliance_gaps: dict[str, Any] = Field(default_factory=dict)
    attack_vectors: list[dict[str, Any]] = Field(default_factory=list)
    security_posture_breakdown: dict[str, int] = Field(default_factory=dict)
    quick_wins: list[str] = Field(default_factory=list)
    remediation_roadmap: list[dict[str, Any]] = Field(default_factory=list)
    methodology: str = ""
    scope: str = ""
    confidence_summary: str = ""
    scan_limitations: list[str] = Field(default_factory=list)
    disclaimer: str = (
        "This assessment was performed using non-invasive defensive reconnaissance "
        "techniques and does not verify exploitability or guarantee the absence of vulnerabilities."
    )