import asyncio
import httpx
import re
from typing import Dict, Any

from backend.schemas.findings import create_finding, FindingCategory, Severity
from backend.services.security_intelligence import enhance_with_intelligence


async def _check_sensitive_file(client: httpx.AsyncClient, base_url: str, path: str, sem: asyncio.Semaphore) -> tuple[str, int, str]:
    async with sem:
        url = f"{base_url.rstrip('/')}{path}"
        try:
            resp = await client.get(url, timeout=5.0, follow_redirects=False)
            return (path, resp.status_code, resp.text[:1000])
        except httpx.RequestError:
            return (path, 0, "")


async def scan_http(target: str) -> Dict[str, Any]:
    if not target.startswith("http://") and not target.startswith("https://"):
        base_url = f"https://{target}"
    else:
        base_url = target

    result = {
        "headers_found": {},
        "missing_security_headers": [],
        "cors_issues": [],
        "dangerous_methods": [],
        "sensitive_files_found": [],
        "cookie_issues": [],
        "redirect_chain": [],
        "security_txt": None,
        "robots_txt": None,
        "findings": []
    }

    try:
        async with httpx.AsyncClient(verify=False, timeout=10.0) as client:
            # 1. Headers & Security Analysis
            try:
                resp = await client.get(base_url, follow_redirects=True)
                headers = {k.lower(): v for k, v in resp.headers.items()}
                result["headers_found"] = dict(resp.headers)

                # Track redirect chain
                result["redirect_chain"] = [str(r.url) for r in resp.history] + [str(resp.url)]

                # ── Content-Security-Policy ──
                csp = headers.get("content-security-policy")
                if not csp:
                    result["missing_security_headers"].append("Content-Security-Policy")
                    result["findings"].append(
                        create_finding(
                            title="Missing Content-Security-Policy",
                            category=FindingCategory.SECURITY_WEAKNESS,
                            severity=Severity.MEDIUM,
                            confidence_score=0.96,
                            evidence_raw="HTTP response headers inspected; CSP header not present",
                            evidence_source=f"HTTP headers from {base_url}",
                            reasoning="Absence of CSP does not confirm XSS exists, but removes an important defense layer.",
                            detection_method="HTTP header inspection",
                            affected_asset=base_url,
                            remediation="Implement a Content-Security-Policy header restricting script and resource origins.",
                            references=["CWE-693", "A05:2021 – Security Misconfiguration"],
                        ).to_legacy_dict()
                    )
                elif "unsafe-inline" in csp.lower():
                    result["findings"].append(
                        create_finding(
                            title="Weak CSP Policy (unsafe-inline)",
                            category=FindingCategory.SECURITY_WEAKNESS,
                            severity=Severity.MEDIUM,
                            confidence_score=0.92,
                            evidence_raw=f"CSP: {csp[:200]}",
                            evidence_source=f"HTTP headers from {base_url}",
                            reasoning="unsafe-inline permits inline scripts, reducing CSP effectiveness.",
                            detection_method="HTTP header inspection",
                            affected_asset=base_url,
                            remediation="Remove 'unsafe-inline' and use nonces or hashes for inline scripts.",
                            references=["CWE-693"],
                        ).to_legacy_dict()
                    )

                # ── X-Frame-Options ──
                xfo = headers.get("x-frame-options")
                if not xfo:
                    result["missing_security_headers"].append("X-Frame-Options")
                    result["findings"].append(
                        create_finding(
                            title="Missing X-Frame-Options",
                            category=FindingCategory.SECURITY_WEAKNESS,
                            severity=Severity.MEDIUM,
                            confidence_score=0.94,
                            evidence_raw="Header not found in HTTP response",
                            evidence_source=f"HTTP headers from {base_url}",
                            reasoning="Without framing controls, the page could be embedded in malicious iframes.",
                            detection_method="HTTP header inspection",
                            affected_asset=base_url,
                            remediation="Set X-Frame-Options to DENY or SAMEORIGIN.",
                            references=["CWE-1021", "A05:2021 – Security Misconfiguration"],
                        ).to_legacy_dict()
                    )

                # ── X-Content-Type-Options ──
                xcto = headers.get("x-content-type-options")
                if not xcto or xcto.lower() != "nosniff":
                    result["missing_security_headers"].append("X-Content-Type-Options")
                    result["findings"].append(
                        create_finding(
                            title="Missing or Incorrect X-Content-Type-Options",
                            category=FindingCategory.SECURITY_WEAKNESS,
                            severity=Severity.LOW,
                            confidence_score=0.95,
                            evidence_raw=f"Value: {xcto}" if xcto else "Header not found",
                            evidence_source=f"HTTP headers from {base_url}",
                            reasoning="Browsers may MIME-sniff responses without this header.",
                            detection_method="HTTP header inspection",
                            affected_asset=base_url,
                            remediation="Set X-Content-Type-Options: nosniff",
                            references=["CWE-16"],
                        ).to_legacy_dict()
                    )

                # ── Strict-Transport-Security ──
                hsts = headers.get("strict-transport-security")
                if not hsts and base_url.startswith("https"):
                    result["missing_security_headers"].append("Strict-Transport-Security")
                    result["findings"].append(
                        create_finding(
                            title="Missing Strict-Transport-Security (HSTS)",
                            category=FindingCategory.SECURITY_WEAKNESS,
                            severity=Severity.MEDIUM,
                            confidence_score=0.95,
                            evidence_raw="Header not found in HTTPS response",
                            evidence_source=f"HTTP headers from {base_url}",
                            reasoning="HSTS header is absent on an HTTPS site. Users may be vulnerable to protocol downgrade attacks.",
                            detection_method="HTTP header inspection",
                            affected_asset=base_url,
                            remediation="Set Strict-Transport-Security with max-age of at least 31536000.",
                            references=["CWE-319", "A02:2021 – Cryptographic Failures"],
                        ).to_legacy_dict()
                    )

                # ── Referrer-Policy ──
                if "referrer-policy" not in headers:
                    result["missing_security_headers"].append("Referrer-Policy")
                    result["findings"].append(
                        create_finding(
                            title="Missing Referrer-Policy",
                            category=FindingCategory.INFORMATIONAL,
                            severity=Severity.LOW,
                            confidence_score=0.90,
                            evidence_raw="Header not found in response",
                            evidence_source=f"HTTP headers from {base_url}",
                            reasoning="Referrer information may leak to third parties without explicit policy.",
                            detection_method="HTTP header inspection",
                            affected_asset=base_url,
                            remediation="Set Referrer-Policy to strict-origin-when-cross-origin or no-referrer.",
                        ).to_legacy_dict()
                    )

                # ── Permissions-Policy ──
                if "permissions-policy" not in headers:
                    result["missing_security_headers"].append("Permissions-Policy")
                    result["findings"].append(
                        create_finding(
                            title="Missing Permissions-Policy",
                            category=FindingCategory.INFORMATIONAL,
                            severity=Severity.LOW,
                            confidence_score=0.88,
                            evidence_raw="Header not found in response",
                            evidence_source=f"HTTP headers from {base_url}",
                            reasoning="Browser features like camera/mic are unrestricted without explicit policy.",
                            detection_method="HTTP header inspection",
                            affected_asset=base_url,
                            remediation="Configure Permissions-Policy to restrict unnecessary browser APIs.",
                        ).to_legacy_dict()
                    )

                # ── Information Disclosure ──
                server = headers.get("server")
                if server and re.search(r"\d", server):
                    result["findings"].append(
                        create_finding(
                            title="Server Version Disclosure",
                            category=FindingCategory.INFORMATIONAL,
                            severity=Severity.LOW,
                            confidence_score=0.97,
                            evidence_raw=f"Server: {server}",
                            evidence_source=f"HTTP headers from {base_url}",
                            reasoning="Server header exposes version information, aiding attacker reconnaissance.",
                            detection_method="HTTP header inspection",
                            affected_asset=base_url,
                            remediation="Configure the web server to suppress version information in the Server header.",
                        ).to_legacy_dict()
                    )

                x_powered_by = headers.get("x-powered-by")
                if x_powered_by:
                    result["findings"].append(
                        create_finding(
                            title="Technology Disclosure (X-Powered-By)",
                            category=FindingCategory.INFORMATIONAL,
                            severity=Severity.LOW,
                            confidence_score=0.97,
                            evidence_raw=f"X-Powered-By: {x_powered_by}",
                            evidence_source=f"HTTP headers from {base_url}",
                            reasoning="X-Powered-By header exposes backend technology stack.",
                            detection_method="HTTP header inspection",
                            affected_asset=base_url,
                            remediation="Remove the X-Powered-By header from server responses.",
                        ).to_legacy_dict()
                    )

                x_aspnet = headers.get("x-aspnet-version")
                if x_aspnet:
                    result["findings"].append(
                        create_finding(
                            title="Technology Disclosure (X-AspNet-Version)",
                            category=FindingCategory.INFORMATIONAL,
                            severity=Severity.LOW,
                            confidence_score=0.97,
                            evidence_raw=f"X-AspNet-Version: {x_aspnet}",
                            evidence_source=f"HTTP headers from {base_url}",
                            reasoning="X-AspNet-Version header exposes ASP.NET framework version.",
                            detection_method="HTTP header inspection",
                            affected_asset=base_url,
                            remediation="Disable the X-AspNet-Version header in web.config.",
                        ).to_legacy_dict()
                    )

                # ── Cookie Security ──
                for name, value in resp.headers.multi_items():
                    if name.lower() == "set-cookie":
                        c_val = value.lower()
                        c_name = value.split("=")[0] if "=" in value else value
                        if "secure" not in c_val:
                            result["cookie_issues"].append({"cookie": c_name, "issue": "Missing Secure flag"})
                            result["findings"].append(
                                create_finding(
                                    title=f"Cookie Missing Secure Flag: {c_name}",
                                    category=FindingCategory.SECURITY_WEAKNESS,
                                    severity=Severity.MEDIUM,
                                    confidence_score=0.95,
                                    evidence_raw=f"Set-Cookie: {value[:200]}",
                                    evidence_source=f"HTTP cookies from {base_url}",
                                    reasoning="Cookie is not flagged Secure. It may be transmitted over unencrypted connections.",
                                    detection_method="HTTP cookie inspection",
                                    affected_asset=base_url,
                                    remediation="Add the Secure flag to all sensitive cookies.",
                                    references=["CWE-614"],
                                ).to_legacy_dict()
                            )
                        if "httponly" not in c_val:
                            result["cookie_issues"].append({"cookie": c_name, "issue": "Missing HttpOnly flag"})
                            result["findings"].append(
                                create_finding(
                                    title=f"Cookie Missing HttpOnly Flag: {c_name}",
                                    category=FindingCategory.SECURITY_WEAKNESS,
                                    severity=Severity.MEDIUM,
                                    confidence_score=0.95,
                                    evidence_raw=f"Set-Cookie: {value[:200]}",
                                    evidence_source=f"HTTP cookies from {base_url}",
                                    reasoning="Cookie is not flagged HttpOnly. It may be accessible via client-side scripts.",
                                    detection_method="HTTP cookie inspection",
                                    affected_asset=base_url,
                                    remediation="Add the HttpOnly flag to prevent JavaScript access.",
                                    references=["CWE-1004"],
                                ).to_legacy_dict()
                            )
                        if "samesite" not in c_val:
                            result["cookie_issues"].append({"cookie": c_name, "issue": "Missing SameSite attribute"})
                            result["findings"].append(
                                create_finding(
                                    title=f"Cookie Missing SameSite Attribute: {c_name}",
                                    category=FindingCategory.SECURITY_WEAKNESS,
                                    severity=Severity.LOW,
                                    confidence_score=0.90,
                                    evidence_raw=f"Set-Cookie: {value[:200]}",
                                    evidence_source=f"HTTP cookies from {base_url}",
                                    reasoning="Cookie lacks SameSite attribute. May be sent in cross-site requests.",
                                    detection_method="HTTP cookie inspection",
                                    affected_asset=base_url,
                                    remediation="Set SameSite=Strict or SameSite=Lax on all cookies.",
                                    references=["CWE-1275"],
                                ).to_legacy_dict()
                            )
            except Exception as e:
                result["findings"].append({
                    "title": "HTTP Request Error",
                    "category": "Informational",
                    "severity": "Info",
                    "confidence_score": 1.0,
                    "description": f"Could not complete HTTP analysis: {str(e)[:200]}",
                    "evidence": str(e)[:200],
                    "detection_method": "HTTP request",
                    "exploit_verified": False,
                    "passive_only": True,
                })

            # 2. CORS Analysis
            try:
                cors_resp = await client.get(base_url, headers={"Origin": "https://evil.com"}, follow_redirects=True)
                cors_headers = {k.lower(): v for k, v in cors_resp.headers.items()}
                acao = cors_headers.get("access-control-allow-origin")
                acac = cors_headers.get("access-control-allow-credentials")

                if acao == "*":
                    if acac and acac.lower() == "true":
                        result["cors_issues"].append("Wildcard Origin with Credentials")
                        result["findings"].append(
                            enhance_with_intelligence(
                                create_finding(
                                    title="Critical CORS Misconfiguration",
                                    category=FindingCategory.SECURITY_WEAKNESS,
                                    severity=Severity.CRITICAL,
                                    confidence_score=0.98,
                                    evidence_raw=f"ACAO: {acao}, ACAC: {acac}",
                                    evidence_source=f"CORS probe response from {base_url}",
                                    reasoning="CORS allows any origin with credentials. Sensitive data may be exfiltrated cross-origin.",
                                    detection_method="CORS probe with test origin",
                                    affected_asset=base_url,
                                    remediation="Never combine Access-Control-Allow-Origin: * with Allow-Credentials: true.",
                                    references=["CWE-942", "A01:2021 – Broken Access Control"],
                                )
                            ).to_legacy_dict()
                        )
                elif acao == "https://evil.com":
                    result["cors_issues"].append("Reflected Origin")
                    result["findings"].append(
                        enhance_with_intelligence(
                            create_finding(
                                title="CORS Reflects Arbitrary Origin",
                                category=FindingCategory.SECURITY_WEAKNESS,
                                severity=Severity.HIGH,
                                confidence_score=0.95,
                                evidence_raw=f"ACAO: {acao}",
                                evidence_source=f"CORS probe response from {base_url}",
                                reasoning="Server reflects arbitrary Origin in ACAO header. Cross-origin data theft may be possible.",
                                detection_method="CORS probe with test origin",
                                affected_asset=base_url,
                                remediation="Validate Origin against an explicit whitelist. Do not reflect untrusted origins.",
                                references=["CWE-942"],
                            )
                        ).to_legacy_dict()
                    )
            except Exception:
                pass

            # 3. HTTP Methods
            try:
                options_resp = await client.options(base_url, follow_redirects=True)
                allow_header = options_resp.headers.get("allow", "")
                if allow_header:
                    allowed_methods = [m.strip().upper() for m in allow_header.split(",")]
                    dangerous = [m for m in allowed_methods if m in ["PUT", "DELETE", "TRACE", "CONNECT"]]
                    if dangerous:
                        result["dangerous_methods"].extend(dangerous)
                        result["findings"].append(
                            enhance_with_intelligence(
                                create_finding(
                                    title="Potentially Dangerous HTTP Methods Allowed",
                                    category=FindingCategory.SECURITY_WEAKNESS,
                                    severity=Severity.MEDIUM,
                                    confidence_score=0.85,
                                    evidence_raw=f"Allow header: {allow_header}",
                                    evidence_source=f"HTTP OPTIONS response from {base_url}",
                                    reasoning="Server advertises support for methods that may allow unintended data modification.",
                                    detection_method="HTTP OPTIONS request",
                                    affected_asset=base_url,
                                    remediation="Disable unnecessary HTTP methods (PUT, DELETE, TRACE) if not required.",
                                    references=["CWE-749"],
                                )
                            ).to_legacy_dict()
                        )
            except Exception:
                pass

            # 4. Sensitive Files & Resources
            sensitive_paths = [
                "/.env", "/.git/HEAD", "/backup.zip", "/.htaccess",
                "/phpinfo.php", "/wp-config.php", "/config.php",
                "/admin", "/phpmyadmin", "/wp-admin",
                "/robots.txt", "/sitemap.xml", "/.well-known/security.txt", "/security.txt",
            ]
            sem = asyncio.Semaphore(10)
            tasks = [_check_sensitive_file(client, base_url, path, sem) for path in sensitive_paths]
            files_results = await asyncio.gather(*tasks)

            for path, status, content in files_results:
                if status == 200:
                    # Parse robots.txt
                    if path == "/robots.txt":
                        result["robots_txt"] = content[:2000]
                        disallowed = [line for line in content.split("\n") if line.strip().lower().startswith("disallow")]
                        if disallowed:
                            result["findings"].append({
                                "title": "robots.txt Exposes Internal Paths",
                                "category": "Informational",
                                "severity": "Info",
                                "confidence_score": 0.85,
                                "description": f"robots.txt contains {len(disallowed)} Disallow entries which may reveal internal structure.",
                                "evidence": f"Sample: {'; '.join(d.strip() for d in disallowed[:5])}",
                                "detection_method": "robots.txt analysis",
                                "exploit_verified": False,
                                "passive_only": True,
                            })
                        continue

                    # Parse security.txt
                    if "security.txt" in path:
                        result["security_txt"] = content[:2000]
                        result["findings"].append(
                            enhance_with_intelligence(
                                create_finding(
                                    title="security.txt Found",
                                    category=FindingCategory.INFORMATIONAL,
                                    severity=Severity.INFORMATIONAL,
                                    confidence_score=1.0,
                                    evidence_raw=f"Content preview: {content[:200]}",
                                    evidence_source=f"HTTP resource at {base_url}{path}",
                                    reasoning="A security.txt file was found, indicating a vulnerability disclosure policy.",
                                    detection_method="HTTP resource check",
                                    affected_asset=f"{base_url}{path}",
                                )
                            ).to_legacy_dict()
                        )
                        continue

                    if path == "/sitemap.xml":
                        continue  # Informational only, no finding needed

                    # Skip soft 404s for sensitive config files
                    if "html" in content[:100].lower() and path in ["/.env", "/.git/HEAD", "/backup.zip", "/.htaccess", "/wp-config.php", "/config.php"]:
                        continue

                    result["sensitive_files_found"].append(path)
                    severity = Severity.HIGH if path in ["/.env", "/.git/HEAD", "/backup.zip", "/wp-config.php", "/config.php"] else Severity.MEDIUM

                    result["findings"].append(
                        enhance_with_intelligence(
                            create_finding(
                                title=f"Exposed Sensitive Resource: {path}",
                                category=FindingCategory.SECURITY_WEAKNESS,
                                severity=severity,
                                confidence_score=0.90,
                                evidence_raw=f"HTTP 200 OK. Content preview: {content[:100]}...",
                                evidence_source=f"HTTP resource at {base_url}{path}",
                                reasoning=f"Resource at {path} returned HTTP 200 and appears to contain non-trivial content.",
                                detection_method="HTTP resource enumeration",
                                affected_asset=f"{base_url}{path}",
                                remediation=f"Restrict access to {path} or remove it from the web root.",
                                references=["CWE-538", "A01:2021 – Broken Access Control"],
                            )
                        ).to_legacy_dict()
                    )

    except Exception as e:
        result["findings"].append(
            enhance_with_intelligence(
                create_finding(
                    title="HTTP Scanner Error",
                    category=FindingCategory.INFORMATIONAL,
                    severity=Severity.INFORMATIONAL,
                    confidence_score=1.0,
                    evidence_raw=f"Failed to complete HTTP analysis: {str(e)[:200]}",
                    evidence_source="HTTP scanner exception",
                    reasoning="HTTP scanner encountered an error during analysis.",
                    detection_method="HTTP scanner",
                    affected_asset=base_url,
                )
            ).to_legacy_dict()
        )

    return result
