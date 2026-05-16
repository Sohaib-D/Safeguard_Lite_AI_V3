import re
from typing import Dict, Any, List

CVE_DB = {
  "Apache": {
    "2.4.49": [{"cve": "CVE-2021-41773", "cvss": 9.8, "desc": "Path traversal and RCE"}],
    "2.4.50": [{"cve": "CVE-2021-42013", "cvss": 9.8, "desc": "Path traversal bypass"}],
    "2.4.0-2.4.46": [{"cve": "CVE-2021-40438", "cvss": 9.0, "desc": "SSRF mod_proxy"}]
  },
  "OpenSSH": {
    "< 8.8": [{"cve": "CVE-2021-28041", "cvss": 7.1, "desc": "Double free memory vulnerability"}],
    "7.4": [{"cve": "CVE-2016-10708", "cvss": 7.5, "desc": "Denial of service"}]
  },
  "PHP": {
    "< 7.4": [{"cve": "CVE-2019-11043", "cvss": 9.8, "desc": "RCE in FPM/FastCGI"}],
    "8.0.0-8.0.2": [{"cve": "CVE-2021-21705", "cvss": 5.3, "desc": "SSRF vulnerability"}]
  },
  "WordPress": {
    "< 5.8": [{"cve": "CVE-2021-29447", "cvss": 7.1, "desc": "XXE via media upload"}],
    "< 5.9": [{"cve": "CVE-2022-21661", "cvss": 7.5, "desc": "SQL injection"}]
  },
  "jQuery": {
    "< 3.5.0": [{"cve": "CVE-2020-11022", "cvss": 6.9, "desc": "XSS via HTML passing"}],
    "1.x": [{"cve": "CVE-2019-11358", "cvss": 6.1, "desc": "Prototype pollution"}]
  },
  "Drupal": {
    "< 9.3.3": [{"cve": "CVE-2022-25271", "cvss": 8.1, "desc": "Remote code execution"}]
  },
  "nginx": {
    "< 1.21.0": [{"cve": "CVE-2021-23017", "cvss": 7.7, "desc": "DNS resolver buffer overflow"}]
  },
  "OpenSSL": {
    "< 1.1.1l": [{"cve": "CVE-2021-3711", "cvss": 9.8, "desc": "SM2 buffer overflow"}],
    "3.0.0-3.0.6": [{"cve": "CVE-2022-3786", "cvss": 7.5, "desc": "X.509 email address buffer overflow"}]
  },
  "IIS": {
    "< 10.0": [{"cve": "CVE-2017-7269", "cvss": 9.8, "desc": "Buffer overflow WebDAV"}]
  },
  "Tomcat": {
    "< 9.0.45": [{"cve": "CVE-2021-25122", "cvss": 7.5, "desc": "Information disclosure h2c"}]
  }
}

def parse_version_tuple(v: str) -> tuple:
    v = v.lower().lstrip('v')
    parts = []
    for part in v.split('.'):
        num = ""
        for char in part:
            if char.isdigit():
                num += char
            else:
                break
        if num:
            parts.append(int(num))
        else:
            parts.append(0)
    return tuple(parts)

def version_matches(detected: str, rule: str) -> bool:
    if rule == "1.x" and detected.startswith("1."):
        return True
    
    detected_tuple = parse_version_tuple(detected)
    
    if rule.startswith("< "):
        target = rule[2:]
        return detected_tuple < parse_version_tuple(target)
    elif "-" in rule:
        parts = rule.split("-")
        if len(parts) == 2:
            low = parse_version_tuple(parts[0])
            high = parse_version_tuple(parts[1])
            return low <= detected_tuple <= high
    else:
        return detected_tuple == parse_version_tuple(rule)
        
    return False

def check_eol(software: str, version: str) -> bool:
    v = parse_version_tuple(version)
    if software.lower() == "php" and v < (7, 4): return True
    if software.lower() == "python" and v < (3, 8): return True
    if software.lower() == "jquery" and v < (2, 0): return True
    if software.lower() == "openssl" and v < (1, 1, 1): return True
    if software.lower() == "apache" and v < (2, 4, 0): return True
    if software.lower() == "ubuntu" and version in ["16.04", "18.04"]: return True
    return False

def extract_software_info(texts: List[str]) -> Dict[str, str]:
    known = ["Apache", "OpenSSH", "PHP", "WordPress", "jQuery", "Drupal", "nginx", "OpenSSL", "IIS", "Tomcat", "Python", "Ubuntu"]
    detected = {}
    
    for text in texts:
        for sw in known:
            pattern = re.compile(rf'{sw}[/ \-]?v?([0-9]+\.[0-9]+(?:\.[0-9]+)*[a-z]?)', re.IGNORECASE)
            match = pattern.search(text)
            if match:
                detected[sw] = match.group(1)
            else:
                if sw == "Ubuntu":
                    match = re.search(r'Ubuntu[/ \-]?([0-9]+\.[0-9]+)', text, re.IGNORECASE)
                    if match:
                        detected[sw] = match.group(1)
    return detected

def get_severity_from_cvss(score: float) -> str:
    if score >= 9.0: return "Critical"
    if score >= 7.0: return "High"
    if score >= 4.0: return "Medium"
    return "Low"

def scan_cve(banners: dict, software_detected: list) -> dict:
    texts_to_scan = list(banners.values()) + software_detected
    detected_sw = extract_software_info(texts_to_scan)

    matched_cves = []
    eol_software = []
    total_critical = 0
    total_high = 0
    findings = []

    for sw, version in detected_sw.items():
        # Banner-based detection has moderate confidence
        banner_confidence = 0.70

        if check_eol(sw, version):
            eol_software.append(f"{sw} {version}")
            findings.append({
                "title": f"End-of-Life Software Detected: {sw} {version}",
                "category": "Security Weakness",
                "severity": "High",
                "cvss_score": 0.0,
                "cve_id": "N/A",
                "confidence_score": banner_confidence,
                "description": f"{sw} {version} has reached End of Life and no longer receives security patches. This increases exposure to known and future vulnerabilities.",
                "reasoning": "EOL software lacks vendor security support, increasing risk over time.",
                "evidence": f"Banner/header fingerprint matched: {sw} {version}",
                "detection_method": "Banner version fingerprinting",
                "exploit_verified": False,
                "passive_only": True,
                "remediation": f"Upgrade {sw} to a currently supported version.",
                "references": ["CWE-1104"],
            })

        if sw in CVE_DB:
            for rule, cves in CVE_DB[sw].items():
                if version_matches(version, rule):
                    for cve_info in cves:
                        matched_cves.append({
                            "software": sw,
                            "version": version,
                            **cve_info
                        })

                        severity = get_severity_from_cvss(cve_info["cvss"])
                        if severity == "Critical":
                            total_critical += 1
                        elif severity == "High":
                            total_high += 1

                        findings.append({
                            "title": f"Potentially Affected: {sw} {version} — {cve_info['cve']}",
                            "category": "Heuristic Risk",
                            "severity": severity,
                            "cvss_score": cve_info["cvss"],
                            "cve_id": cve_info["cve"],
                            "confidence_score": banner_confidence,
                            "description": f"{sw} {version} may be affected by {cve_info['cve']}: {cve_info['desc']}. Exploitability is NOT verified — version was inferred from banner fingerprinting.",
                            "reasoning": f"Version {version} matches known affected range for {cve_info['cve']}. Banner-based detection has inherent uncertainty.",
                            "evidence": f"Banner fingerprint matched: {sw}/{version}",
                            "detection_method": "Banner version correlation against CVE database",
                            "exploit_verified": False,
                            "passive_only": True,
                            "remediation": f"Verify the exact installed version of {sw} and apply patches if affected.",
                            "references": [cve_info["cve"], f"CVSS: {cve_info['cvss']}"],
                        })

    return {
        "matched_cves": matched_cves,
        "eol_software": eol_software,
        "total_critical_cves": total_critical,
        "total_high_cves": total_high,
        "findings": findings
    }

