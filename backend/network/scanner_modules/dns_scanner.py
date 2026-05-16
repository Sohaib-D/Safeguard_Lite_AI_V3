import asyncio
import dns.asyncresolver
import dns.resolver
import dns.zone
import dns.query
import dns.exception
import urllib.parse
from typing import Dict, Any

def _finding(title: str, severity: str, description: str, evidence: str, confidence: float, references: list = None) -> dict:
    return {
        "title": title,
        "severity": severity,
        "description": description,
        "category": "DNS Intelligence",
        "confidence_score": confidence,
        "evidence": evidence,
        "detection_method": "DNS record lookup",
        "exploit_verified": False,
        "passive_only": True,
        "references": references or [],
    }

def extract_domain(target: str) -> str:
    target = target.strip()
    if not target.startswith("http://") and not target.startswith("https://"):
        target = "http://" + target
    parsed = urllib.parse.urlparse(target)
    domain = parsed.netloc
    if ":" in domain:
        domain = domain.split(":")[0]
    return domain

async def _check_zone_transfer(domain: str, nameservers: list) -> bool:
    def sync_check():
        for ns in nameservers:
            try:
                ns_ips = dns.resolver.resolve(ns, 'A')
                for ns_ip in ns_ips:
                    z = dns.zone.from_xfr(dns.query.xfr(ns_ip.to_text(), domain, timeout=3.0))
                    if z:
                        return True
            except Exception:
                continue
        return False
    return await asyncio.to_thread(sync_check)

async def _check_subdomain_takeover(domain: str, sub: str, resolver: dns.asyncresolver.Resolver) -> tuple:
    subdomain = f"{sub}.{domain}"
    try:
        answers = await resolver.resolve(subdomain, 'CNAME')
        for rdata in answers:
            target = rdata.target.to_text()
            vulnerable_providers = ['github.io', 'herokuapp.com', 'netlify.app', 'azurewebsites.net', 'cloudapp.net', 'amazonaws.com']
            for provider in vulnerable_providers:
                if provider in target:
                    try:
                        await resolver.resolve(target, 'A')
                    except dns.resolver.NXDOMAIN:
                        return (subdomain, True, True, target)
                    except Exception:
                        pass
            return (subdomain, True, False, target)
        return (subdomain, False, False, "")
    except Exception:
        return (subdomain, False, False, "")

async def scan_dns(target: str) -> Dict[str, Any]:
    domain = extract_domain(target)
    
    result = {
        "spf_status": "Missing",
        "dkim_found": False,
        "dmarc_policy": "Missing",
        "zone_transfer_possible": False,
        "subdomains_found": [],
        "takeover_risks": [],
        "dnssec_enabled": False,
        "findings": [],
        "ns_records": [],
        "mx_records": [],
    }

    try:
        resolver = dns.asyncresolver.Resolver()
        resolver.timeout = 5.0
        resolver.lifetime = 10.0

        nameservers = []
        try:
            ns_answers = await resolver.resolve(domain, 'NS')
            nameservers = [rdata.target.to_text() for rdata in ns_answers]
            result["ns_records"] = nameservers
        except Exception:
            result["ns_records"] = []

        if nameservers:
            try:
                zt = await _check_zone_transfer(domain, nameservers)
                result["zone_transfer_possible"] = zt
                if zt:
                    result["findings"].append(_finding(
                        "Zone Transfer Allowed",
                        "Critical",
                        "DNS server allowed AXFR zone transfer, exposing DNS zone data to this scanner.",
                        "AXFR query succeeded against at least one authoritative nameserver",
                        0.98,
                        ["CWE-200"],
                    ))
            except Exception:
                pass

        try:
            txt_answers = await resolver.resolve(domain, 'TXT')
            for rdata in txt_answers:
                txt = b"".join(rdata.strings).decode()
                if txt.startswith("v=spf1"):
                    if "+all" in txt:
                        result["spf_status"] = "vulnerable"
                        result["findings"].append({
                            "title": "Insecure SPF Record (+all)",
                            "severity": "Critical",
                            "description": "SPF record ends with +all, which authorizes any sender and weakens anti-spoofing controls.",
                            "category": "DNS Intelligence",
                            "confidence_score": 0.98,
                            "evidence": txt,
                            "detection_method": "DNS TXT SPF lookup",
                            "exploit_verified": False,
                            "passive_only": True,
                            "references": ["CWE-290"],
                        })
                    elif "~all" in txt:
                        result["spf_status"] = "softfail"
                        result["findings"].append({
                            "title": "Weak SPF Record (~all)",
                            "severity": "Medium",
                            "description": "SPF record uses soft fail (~all), which is a weaker anti-spoofing policy than -all.",
                            "category": "DNS Intelligence",
                            "confidence_score": 0.95,
                            "evidence": txt,
                            "detection_method": "DNS TXT SPF lookup",
                            "exploit_verified": False,
                            "passive_only": True,
                        })
                    elif "-all" in txt:
                        result["spf_status"] = "secure"
                    else:
                        result["spf_status"] = "neutral"
                    break
        except Exception:
            pass

        if result["spf_status"] == "Missing":
            result["findings"].append(_finding(
                "Missing SPF Record",
                "Medium",
                "No SPF record was found. This is an email authentication control gap, not proof of active spoofing.",
                "No TXT record starting with v=spf1 was returned",
                0.90,
                ["CWE-290"],
            ))

        selectors = ["google", "default", "mail", "k1", "selector1", "selector2"]
        dkim_found = False
        for selector in selectors:
            try:
                dkim_answers = await resolver.resolve(f"{selector}._domainkey.{domain}", 'TXT')
                if dkim_answers:
                    dkim_found = True
                    break
            except Exception:
                pass
                
        result["dkim_found"] = dkim_found
        if not dkim_found:
            result["findings"].append(_finding(
                "DKIM Not Found Using Common Selectors",
                "Low",
                "DKIM records were not found for common selectors. This is a heuristic observation because custom selectors may exist.",
                "Selectors checked: google, default, mail, k1, selector1, selector2",
                0.65,
            ))

        try:
            dmarc_answers = await resolver.resolve(f"_dmarc.{domain}", 'TXT')
            dmarc_txt = b"".join(dmarc_answers[0].strings).decode()
            if "p=none" in dmarc_txt:
                result["dmarc_policy"] = "p=none"
                result["findings"].append({
                    "title": "Weak DMARC Policy (p=none)",
                    "severity": "Medium",
                    "description": "DMARC policy is set to monitoring-only. This provides visibility but does not request quarantine or rejection.",
                    "category": "DNS Intelligence",
                    "confidence_score": 0.95,
                    "evidence": dmarc_txt,
                    "detection_method": "DMARC TXT lookup",
                    "exploit_verified": False,
                    "passive_only": True,
                })
            elif "p=quarantine" in dmarc_txt:
                result["dmarc_policy"] = "p=quarantine"
            elif "p=reject" in dmarc_txt:
                result["dmarc_policy"] = "p=reject"
            else:
                result["dmarc_policy"] = "other"
        except Exception:
            result["findings"].append(_finding(
                "Missing DMARC Record",
                "Medium",
                "No DMARC record was found. This is an email authentication policy gap, not proof of active spoofing.",
                "No TXT record was returned for _dmarc domain",
                0.90,
                ["CWE-290"],
            ))

        try:
            ds_answers = await resolver.resolve(domain, 'DS')
            if ds_answers:
                result["dnssec_enabled"] = True
        except Exception:
            result["dnssec_enabled"] = False
            result["findings"].append(_finding(
                "DNSSEC Not Enabled",
                "Low",
                "No DS records were observed. DNSSEC is an integrity hardening control and may not be deployed for all domains.",
                "No DS record returned for domain",
                0.85,
            ))

        try:
            await resolver.resolve(domain, 'CAA')
        except Exception:
            result["findings"].append(_finding(
                "Missing CAA Record",
                "Low",
                "No CAA record was observed. CAA can restrict which certificate authorities may issue certificates for the domain.",
                "No CAA record returned for domain",
                0.85,
            ))

        try:
            mx_answers = await resolver.resolve(domain, 'MX')
            result["mx_records"] = [f"{rdata.preference} {rdata.exchange.to_text()}" for rdata in mx_answers]
        except Exception:
            result["mx_records"] = []

        subdomains = [
            "www", "mail", "ftp", "api", "admin", "dev", "staging", 
            "test", "vpn", "cdn", "assets", "beta", "app", "portal", "dashboard"
        ]
        tasks = [_check_subdomain_takeover(domain, sub, resolver) for sub in subdomains]
        subdomain_results = await asyncio.gather(*tasks)
        
        for sub_full, has_cname, is_vulnerable, target_url in subdomain_results:
            if has_cname:
                result["subdomains_found"].append({"subdomain": sub_full, "target": target_url})
                if is_vulnerable:
                    result["takeover_risks"].append(sub_full)
                    result["findings"].append({
                        "title": f"Subdomain Takeover Risk: {sub_full}",
                        "severity": "High",
                        "description": f"Subdomain {sub_full} has a CNAME pointing to {target_url} that did not resolve during this check. Manual verification is required before treating this as exploitable.",
                        "category": "DNS Intelligence",
                        "confidence_score": 0.75,
                        "evidence": f"CNAME {target_url} returned NXDOMAIN",
                        "detection_method": "DNS CNAME resolution heuristic",
                        "exploit_verified": False,
                        "passive_only": True,
                        "references": ["CWE-404"],
                    })

    except Exception as e:
        # Return whatever partial results we collected
        if not result.get("findings"):
            result["findings"].append({
                "title": "DNS Scan Partially Failed",
                "severity": "Low",
                "description": f"Some DNS checks could not complete: {str(e)[:200]}",
                "category": "DNS Intelligence",
                "confidence_score": 1.0,
                "evidence": str(e)[:200],
                "detection_method": "DNS scanner",
                "exploit_verified": False,
                "passive_only": True,
            })

    return result
