import asyncio
import socket
import ssl
import time
import urllib.parse
from datetime import datetime
from typing import Any, Dict, List, Optional

import httpx
import re
import whois
import dns.resolver


class ActiveScanner:
    """Safe reconnaissance scanner for local and external targets."""

    COMMON_PORTS = {
        21: ("FTP", "File Transfer Protocol (transmits data in plain text)"),
        22: ("SSH", "Secure Shell (remote login)"),
        23: ("Telnet", "Unencrypted remote login (highly insecure)"),
        25: ("SMTP", "Simple Mail Transfer Protocol"),
        53: ("DNS", "Domain Name System"),
        80: ("HTTP", "Unencrypted web traffic"),
        110: ("POP3", "Post Office Protocol"),
        135: ("RPC", "Windows RPC"),
        139: ("NetBIOS", "Windows NetBIOS"),
        143: ("IMAP", "Internet Message Access Protocol"),
        443: ("HTTPS", "Secure web traffic"),
        445: ("SMB", "Windows File Sharing"),
        3306: ("MySQL", "Database"),
        3389: ("RDP", "Remote Desktop Protocol"),
        5432: ("PostgreSQL", "Database"),
        8000: ("HTTP-ALT", "Alternative web port"),
        8080: ("HTTP-ALT", "Alternative web service port"),
    }

    async def scan_target(self, target: str) -> Dict[str, Any]:
        """Perform a full safe reconnaissance scan on a target."""
        original_target = target
        target = self._clean_target(target)
        results: Dict[str, Any] = {
            "target": target,
            "input_target": original_target,
            "timestamp": datetime.utcnow().isoformat(),
            "dns": {},
            "ports": [],
            "ssl": None,
            "http_headers": {},
            "whois": None,
            "latency_ms": None,
            "error": None,
        }

        try:
            # 1. DNS Resolution & Latency
            results["dns"], results["latency_ms"] = await self._resolve_and_ping(target)
            ip_address = results["dns"].get("ip_address")

            if not ip_address:
                results["error"] = "Could not resolve target IP address."
                return results

            # 2. Port Scanning
            results["ports"] = await self._scan_ports(ip_address)

            # 3. SSL Check (if port 443 is open)
            # Pass the original domain (not IP) so SNI works with CDN edge servers
            domain_for_sni = None if self._is_ip(target) else target
            if any(p["port"] == 443 for p in results["ports"]):
                results["ssl"] = await self._check_ssl(ip_address, domain=domain_for_sni)

            # 4. HTTP Headers (if port 80 or 443 is open)
            if any(p["port"] in (80, 443, 8000, 8080) for p in results["ports"]):
                port_to_check = 443 if any(p["port"] == 443 for p in results["ports"]) else 80
                host_for_http = None if self._is_ip(target) else target
                raw_headers = await self._get_http_headers(ip_address, port_to_check, host_for_http)
                # Filter out noisy non-security headers for the "Security Headers" UI section
                _exclude = {"date", "accept-ranges", "content-encoding", "content-length", "keep-alive", "connection", "vary"}
                filtered = {k: v for k, v in raw_headers.items() if k.lower() not in _exclude}
                # Keep both raw and filtered forms for transparency; UI should prefer filtered
                results["http_headers_raw"] = raw_headers
                results["http_headers"] = filtered
                results["http_headers_filtered"] = filtered

            # 5. WHOIS (only if it's a domain)
            if not self._is_ip(target):
                results["whois"] = await self._get_whois(target)

            # 6. Advanced Vulnerability Configuration Checks
            results["security_configs"] = self._evaluate_security(
                results["ports"], 
                results.get("http_headers", {}), 
                results["dns"]
            )

        except Exception as e:
            results["error"] = str(e)

        return results

    def _clean_target(self, target: str) -> str:
        target = target.strip()
        if target.startswith("http://") or target.startswith("https://"):
            parsed = urllib.parse.urlparse(target)
            target = parsed.netloc
        if "@" in target:
            target = target.rsplit("@", 1)[-1]
        if ":" in target:
            target = target.split(":", 1)[0]
        return target.strip("/")

    def _is_ip(self, target: str) -> bool:
        try:
            socket.inet_aton(target)
            return True
        except socket.error:
            return False

    async def _resolve_and_ping(self, target: str) -> tuple[Dict[str, Any], Optional[float]]:
        loop = asyncio.get_event_loop()
        dns_info = {}
        latency = None
        ip_address = None

        start_time = time.time()
        try:
            # Basic resolution
            if self._is_ip(target):
                ip_address = target
                try:
                    hostnames = await loop.run_in_executor(None, socket.gethostbyaddr, target)
                    dns_info["hostname"] = hostnames[0]
                except socket.herror:
                    dns_info["hostname"] = None
            else:
                ip_address = await loop.run_in_executor(None, socket.gethostbyname, target)
                dns_info["hostname"] = target

            dns_info["ip_address"] = ip_address
            latency = round((time.time() - start_time) * 1000, 2)

            # Additional DNS records if it's a domain
            if not self._is_ip(target):
                for record_type in ['MX', 'TXT', 'NS']:
                    try:
                        answers = await loop.run_in_executor(None, dns.resolver.resolve, target, record_type)
                        dns_info[f"{record_type}_records"] = [str(rdata) for rdata in answers]
                    except Exception:
                        pass
        except Exception:
            pass

        return dns_info, latency

    async def _scan_ports(self, ip: str) -> List[Dict[str, Any]]:
        open_ports = []
        loop = asyncio.get_event_loop()

        async def check_port(port: int):
            try:
                conn = asyncio.open_connection(ip, port)
                reader, writer = await asyncio.wait_for(conn, timeout=1.0)
                
                banner = None
                if port not in (80, 443, 8000, 8080):  # HTTP doesn't send banner first
                    try:
                        data = await asyncio.wait_for(reader.read(1024), timeout=1.5)
                        if data:
                            banner = data.decode('utf-8', errors='ignore').strip()
                            # Truncate long banners
                            if len(banner) > 200:
                                banner = banner[:197] + "..."
                    except Exception:
                        pass

                writer.close()
                await writer.wait_closed()
                
                service_name, description = self.COMMON_PORTS.get(port, ("Unknown", "Unidentified service"))
                open_ports.append({
                    "port": port,
                    "service": service_name,
                    "description": description,
                    "banner": banner,
                    "vulnerability_context": self._get_port_context(port)
                })
            except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
                pass

        # Scan top common ports
        tasks = [check_port(port) for port in self.COMMON_PORTS.keys()]
        await asyncio.gather(*tasks)
        return sorted(open_ports, key=lambda x: x["port"])

    def _get_port_context(self, port: int) -> str:
        contexts = {
            21: "FTP commonly transmits credentials in cleartext. Confirm this service is intentionally exposed.",
            22: "SSH is externally reachable. This is not a vulnerability by itself; enforce keys, MFA, and rate limiting.",
            23: "Telnet is an unencrypted remote administration protocol and should generally be avoided.",
            80: "HTTP is reachable. Confirm HTTPS redirection and avoid serving sensitive workflows over cleartext.",
            445: "SMB is frequently targeted. Avoid exposing it directly to untrusted networks.",
            3389: "RDP is frequently targeted. Prefer VPN or access controls before public exposure."
        }
        return contexts.get(port, "Ensure this service is intentionally exposed and properly secured.")

    async def _check_ssl(self, ip: str, domain: str = None) -> Optional[Dict[str, Any]]:
        """
        Fetch and parse the SSL/TLS certificate for the target.

        Uses the original domain for SNI so that CDN edge servers (Cloudflare,
        Akamai, Fastly, etc.) return the correct certificate rather than
        failing the handshake silently.
        """
        loop = asyncio.get_event_loop()
        sni_host = domain if domain else ip  # SNI must be the domain, not the IP

        def get_cert() -> Dict[str, Any]:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            try:
                with socket.create_connection((ip, 443), timeout=5) as sock:
                    with ctx.wrap_socket(sock, server_hostname=sni_host) as ssock:
                        cert_bin = ssock.getpeercert(binary_form=True)
                        cipher = ssock.cipher()          # (name, version, bits)
                        tls_version = ssock.version()    # e.g. 'TLSv1.3'

                        import cryptography.x509
                        from cryptography.hazmat.backends import default_backend
                        x509 = cryptography.x509.load_der_x509_certificate(
                            cert_bin, default_backend()
                        )

                        # Safe date access for older cryptography versions
                        try:
                            not_after = x509.not_valid_after_utc.isoformat()
                        except AttributeError:
                            not_after = x509.not_valid_after.isoformat()

                        try:
                            not_before = x509.not_valid_before_utc.isoformat()
                        except AttributeError:
                            not_before = x509.not_valid_before.isoformat()

                        # Check for CDN issuer signatures
                        issuer_str = x509.issuer.rfc4514_string()
                        cdn_issuers = [
                            "Cloudflare", "Amazon", "DigiCert", "GlobalSign",
                            "Let's Encrypt", "Akamai", "Fastly", "Google Trust",
                        ]
                        cdn_note = None
                        if any(cdn in issuer_str for cdn in cdn_issuers):
                            cdn_note = (
                                "Certificate issued by a CDN/cloud provider. "
                                "Origin server is likely shielded — direct infrastructure "
                                "inspection is not available."
                            )

                        return {
                            "status": "ok",
                            "issuer": issuer_str,
                            "subject": x509.subject.rfc4514_string(),
                            "expires": not_after,
                            "valid_from": not_before,
                            "tls_version": tls_version,
                            "cipher": cipher[0] if cipher else "Unknown",
                            "cdn_protected": cdn_note is not None,
                            "cdn_note": cdn_note,
                        }

            except socket.timeout:
                return {
                    "status": "timeout",
                    "error": "Connection timed out — target may be behind a CDN or firewall that blocks direct SSL inspection.",
                    "cdn_protected": True,
                    "cdn_note": "Protected by CDN — direct SSL inspection not available.",
                }
            except ConnectionRefusedError:
                return {
                    "status": "refused",
                    "error": "Port 443 refused the connection.",
                    "cdn_protected": False,
                    "cdn_note": None,
                }
            except ssl.SSLError as e:
                # SNI mismatch or handshake failure — common with strict CDNs
                err_str = str(e).lower()
                is_cdn_block = any(k in err_str for k in (
                    "handshake", "certificate_unknown", "unrecognized_name",
                    "wrong_version", "alert",
                ))
                return {
                    "status": "ssl_error",
                    "error": f"TLS handshake failed: {str(e)[:120]}",
                    "cdn_protected": is_cdn_block,
                    "cdn_note": (
                        "Protected by CDN — direct SSL inspection not available."
                        if is_cdn_block else None
                    ),
                }
            except Exception as e:
                err_str = str(e).lower()
                likely_cdn = any(k in err_str for k in (
                    "timed out", "blocked", "reset", "eof", "ssl", "certificate",
                ))
                return {
                    "status": "error",
                    "error": str(e)[:200],
                    "cdn_protected": likely_cdn,
                    "cdn_note": (
                        "Protected by CDN — direct SSL inspection not available."
                        if likely_cdn else None
                    ),
                }

        return await loop.run_in_executor(None, get_cert)


    async def _get_http_headers(self, ip: str, port: int, host: str = None) -> Dict[str, str]:
        protocol = "https" if port == 443 else "http"
        target_host = host or ip
        url = f"{protocol}://{target_host}:{port}/"
        try:
            async with httpx.AsyncClient(verify=False, timeout=3.0) as client:
                response = await client.head(url, follow_redirects=True)
                return dict(response.headers)
        except Exception:
            return {}

    async def _get_whois(self, domain: str) -> Optional[Dict[str, Any]]:
        loop = asyncio.get_event_loop()

        def _root_domain(d: str) -> str:
            """Strip subdomains — WHOIS records exist only for root domains."""
            parts = d.rstrip(".").split(".")
            # Keep the last two labels (e.g. nmap.org from scanme.nmap.org)
            # For country-code SLDs like co.uk keep the last three
            two_label_ccSLDs = {"co", "com", "net", "org", "gov", "edu", "ac"}
            if len(parts) >= 3 and parts[-2] in two_label_ccSLDs:
                return ".".join(parts[-3:])
            return ".".join(parts[-2:]) if len(parts) >= 2 else d

        def query_whois():
            root = _root_domain(domain)
            try:
                w = whois.whois(root)
                # creation_date / expiration_date can be list or single value or None
                def _fmt_date(val):
                    if val is None:
                        return "N/A"
                    if isinstance(val, list):
                        val = val[0]
                    return str(val)

                return {
                    "registrar": w.registrar or "N/A",
                    "creation_date": _fmt_date(w.creation_date),
                    "expiration_date": _fmt_date(w.expiration_date),
                    "name_servers": w.name_servers or [],
                    "root_domain_queried": root,
                }
            except Exception:
                return None

        return await loop.run_in_executor(None, query_whois)

    def _evaluate_security(self, ports: List[Dict[str, Any]], headers: Dict[str, str], dns_info: Dict[str, Any]) -> List[Dict[str, str]]:
        vulns = []

        def observation(
            finding_type: str,
            severity: str,
            description: str,
            evidence: str,
            confidence: float,
            method: str,
        ) -> Dict[str, Any]:
            return {
                "type": finding_type,
                "severity": severity,
                "description": description,
                "confidence_score": confidence,
                "evidence": evidence,
                "detection_method": method,
                "exploit_verified": False,
                "passive_only": True,
            }
        
        # 1. Bruteforce Vulnerability Checks
        open_port_nums = [p["port"] for p in ports]
        if 22 in open_port_nums:
            vulns.append(observation(
                "SSH Exposure Observation",
                "Medium",
                "SSH (port 22) is externally reachable. This is an exposure observation, not evidence of weak passwords or successful brute force.",
                "TCP connection to port 22 succeeded",
                0.95,
                "TCP connect scan",
            ))
        if 3389 in open_port_nums:
            vulns.append(observation(
                "RDP Exposure Observation",
                "High",
                "RDP (port 3389) is externally reachable. Prefer VPN, allowlists, MFA, and lockout policies if remote access is required.",
                "TCP connection to port 3389 succeeded",
                0.95,
                "TCP connect scan",
            ))
        if 21 in open_port_nums or 23 in open_port_nums:
            exposed = [str(p) for p in (21, 23) if p in open_port_nums]
            vulns.append(observation(
                "Cleartext Service Exposure",
                "High",
                "FTP or Telnet is reachable. These protocols may transmit sensitive data without encryption depending on configuration.",
                f"TCP connection succeeded on port(s): {', '.join(exposed)}",
                0.95,
                "TCP connect scan",
            ))

        # 2. Edge protection observation
        if headers:
            headers_lower = {k.lower(): v.lower() for k, v in headers.items()}
            is_protected = False
            waf_signatures = ['cloudflare', 'cloudfront', 'akamai', 'sucuri', 'incapsula', 'fastly']
            
            # Check Server header or custom headers
            server_header = headers_lower.get('server', '')
            if any(waf in server_header for waf in waf_signatures):
                is_protected = True
            if 'x-sucuri-id' in headers_lower or 'x-amz-cf-id' in headers_lower or 'cf-ray' in headers_lower:
                is_protected = True
                
            if not is_protected:
                vulns.append(observation(
                    "No CDN/WAF Fingerprint Observed",
                    "Info",
                    "No common CDN/WAF fingerprint was observed in HTTP headers. This does not prove DDoS vulnerability or absence of edge protection.",
                    "Common CDN/WAF response headers were not present",
                    0.65,
                    "HTTP header fingerprinting",
                ))

        # 3. Web Security Headers (XSS, Clickjacking, MitM)
        if headers:
            headers_lower = {k.lower(): v.lower() for k, v in headers.items()}

            # If Server header contains a version string, flag it as disclosed
            server_val = headers.get('Server') or headers.get('server') or headers_lower.get('server')
            if server_val and isinstance(server_val, str) and re.search(r"\d", server_val):
                vulns.append(observation(
                    "Web Server Version Disclosed",
                    "Medium",
                    f"Web server discloses a version string: {server_val}. This information can aid targeted attacks.",
                    f"server: {server_val}",
                    0.85,
                    "HTTP header inspection",
                ))

            # HSTS: required on HTTPS with High severity if missing
            if 'strict-transport-security' not in headers_lower and 443 in open_port_nums:
                vulns.append(observation(
                    "Missing HSTS",
                    "High",
                    "Strict-Transport-Security header was not observed on HTTPS. HSTS is a hardening control against downgrade scenarios; exploitability is not verified.",
                    "HSTS header absent from inspected HTTP response",
                    0.95,
                    "HTTP header inspection",
                ))

            # Content-Security-Policy: High severity if missing
            if 'content-security-policy' not in headers_lower:
                vulns.append(observation(
                    "Missing CSP",
                    "High",
                    "Content-Security-Policy header was not observed. Missing CSP reduces browser-side mitigation but does not prove exploitable XSS.",
                    "CSP header absent from inspected HTTP response",
                    0.96,
                    "HTTP header inspection",
                ))

            # X-Content-Type-Options: Medium
            if 'x-content-type-options' not in headers_lower:
                vulns.append(observation(
                    "Missing X-Content-Type-Options",
                    "Medium",
                    "X-Content-Type-Options header was not observed. This header prevents MIME sniffing attacks.",
                    "X-Content-Type-Options header absent from inspected HTTP response",
                    0.92,
                    "HTTP header inspection",
                ))

            # Referrer-Policy: Low
            if 'referrer-policy' not in headers_lower:
                vulns.append(observation(
                    "Missing Referrer-Policy",
                    "Low",
                    "Referrer-Policy header was not observed. URL data may leak to third parties through Referer headers.",
                    "Referrer-Policy header absent from inspected HTTP response",
                    0.8,
                    "HTTP header inspection",
                ))

            # Permissions-Policy: Low
            if 'permissions-policy' not in headers_lower:
                vulns.append(observation(
                    "Missing Permissions-Policy",
                    "Low",
                    "Permissions-Policy header was not observed. Browser feature access by third-party scripts is not explicitly constrained.",
                    "Permissions-Policy header absent from inspected HTTP response",
                    0.8,
                    "HTTP header inspection",
                ))

            # X-Frame-Options remains a Low-severity check
            if 'x-frame-options' not in headers_lower:
                vulns.append(observation(
                    "Missing X-Frame-Options",
                    "Low",
                    "X-Frame-Options header was not observed. Review frame-ancestor protections such as CSP frame-ancestors.",
                    "X-Frame-Options header absent from inspected HTTP response",
                    0.94,
                    "HTTP header inspection",
                ))

        # Return a clean list of findings. If empty, the target has a good basic posture.
        return vulns
