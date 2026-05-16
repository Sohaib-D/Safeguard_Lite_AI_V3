import asyncio
import ssl
import socket
from datetime import datetime, timezone
import ipaddress
from cryptography import x509
from cryptography.x509.oid import ExtensionOID, NameOID

def _finding(title: str, severity: str, description: str, evidence: str, confidence: float, references: list = None) -> dict:
    return {
        "title": title,
        "severity": severity,
        "description": description,
        "category": "TLS/SSL",
        "confidence_score": confidence,
        "evidence": evidence,
        "detection_method": "TLS handshake and certificate inspection",
        "exploit_verified": False,
        "passive_only": True,
        "references": references or [],
    }

def check_weak_cipher(cipher_name: str) -> bool:
    name = cipher_name.upper()
    for weak in ["RC4", "DES", "3DES", "NULL", "EXPORT", "MD5"]:
        if weak in name:
            return True
    return False

def check_deprecated_protocol(protocol: str) -> bool:
    proto = protocol.upper()
    for dep in ["SSLV2", "SSLV3", "TLSV1.0", "TLSV1.1", "TLSV1"]:
        if proto == dep:
            return True
    return False

async def get_hsts_header(target: str, port: int) -> bool:
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(target, port, ssl=context),
            timeout=5.0
        )
        request = f"GET / HTTP/1.1\r\nHost: {target}\r\nConnection: close\r\n\r\n"
        writer.write(request.encode())
        await writer.drain()
        
        headers_data = b""
        while True:
            try:
                line = await asyncio.wait_for(reader.readline(), timeout=2.0)
                if not line or line == b"\r\n":
                    break
                headers_data += line
            except asyncio.TimeoutError:
                break
            
        writer.close()
        await writer.wait_closed()
        
        headers_str = headers_data.decode("utf-8", errors="ignore").lower()
        for line in headers_str.split("\r\n"):
            if line.startswith("strict-transport-security:"):
                parts = line.split(";")
                for part in parts:
                    part = part.strip()
                    if part.startswith("max-age="):
                        try:
                            age = int(part.split("=")[1])
                            if age >= 31536000:
                                return True
                        except ValueError:
                            pass
        return False
    except Exception:
        return False

async def scan_tls(target: str, port: int = 443) -> dict:
    result = {
        "is_valid": False,
        "days_until_expiry": 0,
        "protocol_version": "Unknown",
        "cipher_suite": "Unknown",
        "is_self_signed": False,
        "domain_match": False,
        "hsts_enabled": False,
        "findings": [],
        "has_error": False,
        "error_message": ""
    }

    try:
        result["hsts_enabled"] = await get_hsts_header(target, port)
        
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(target, port, ssl=context, server_hostname=target),
            timeout=15.0
        )
        
        ssl_obj = writer.get_extra_info('ssl_object')
        cert_bin = ssl_obj.getpeercert(binary_form=True)
        cipher = ssl_obj.cipher()
        protocol_ver = ssl_obj.version()
        
        writer.close()
        await writer.wait_closed()

        if not cert_bin:
            raise ValueError("No certificate provided by server.")

        cert = x509.load_der_x509_certificate(cert_bin)
        
        result["protocol_version"] = protocol_ver
        if cipher:
            result["cipher_suite"] = cipher[0]
            
        if check_deprecated_protocol(protocol_ver):
            result["findings"].append(_finding(
                "Deprecated Protocol",
                "High",
                f"Server negotiated deprecated protocol {protocol_ver}. Disable legacy TLS/SSL protocols if still enabled.",
                f"Negotiated protocol: {protocol_ver}",
                0.95,
                ["CWE-327"],
            ))
            
        if cipher and check_weak_cipher(cipher[0]):
            result["findings"].append(_finding(
                "Weak Cipher Suite",
                "High",
                f"Server negotiated a weak cipher suite: {cipher[0]}.",
                f"Negotiated cipher: {cipher[0]}",
                0.95,
                ["CWE-327"],
            ))

        try:
            not_after = cert.not_valid_after_utc
            now = datetime.now(timezone.utc)
        except AttributeError:
            not_after = cert.not_valid_after
            now = datetime.utcnow()
            
        days_left = (not_after - now).days
        result["days_until_expiry"] = days_left
        
        if days_left < 14:
            result["findings"].append(_finding(
                "Certificate Expiring Soon",
                "Critical",
                f"Certificate expires in {days_left} days. Renew before expiry to avoid service trust errors.",
                f"days_until_expiry={days_left}",
                0.98,
                ["CWE-324"],
            ))
        elif days_left < 30:
            result["findings"].append(_finding(
                "Certificate Expiring Soon",
                "High",
                f"Certificate expires in {days_left} days. Plan renewal before expiry.",
                f"days_until_expiry={days_left}",
                0.98,
                ["CWE-324"],
            ))

        is_self_signed = cert.issuer == cert.subject
        result["is_self_signed"] = is_self_signed
        if is_self_signed:
            result["findings"].append(_finding(
                "Self-Signed Certificate",
                "High",
                "The certificate is self-signed. Public clients may not trust the connection unless this is an internal/private deployment.",
                "Certificate issuer equals subject",
                0.98,
                ["CWE-295"],
            ))

        domain_match = False
        try:
            for attr in cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME):
                cn = attr.value
                if cn.startswith("*."):
                    base = cn[2:]
                    if target == base or target.endswith("." + base):
                        domain_match = True
                elif cn == target:
                    domain_match = True
                    
            try:
                san_ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
                san_names = san_ext.value.get_values_for_type(x509.DNSName)
                for name in san_names:
                    if name.startswith("*."):
                        base = name[2:]
                        if target == base or target.endswith("." + base):
                            domain_match = True
                    elif name == target:
                        domain_match = True
                
                try:
                    target_ip = ipaddress.ip_address(target)
                    ip_names = san_ext.value.get_values_for_type(x509.IPAddress)
                    for ip in ip_names:
                        if ip == target_ip:
                            domain_match = True
                except ValueError:
                    pass
            except x509.ExtensionNotFound:
                pass
        except Exception:
            pass

        result["domain_match"] = domain_match
        if not domain_match:
            result["findings"].append(_finding(
                "Certificate Domain Mismatch",
                "High",
                f"Certificate subject/SAN did not match target domain {target}.",
                f"Target checked: {target}",
                0.90,
                ["CWE-297"],
            ))

        try:
            cert.extensions.get_extension_for_oid(ExtensionOID.PRECERT_SIGNED_CERTIFICATE_TIMESTAMPS)
        except x509.ExtensionNotFound:
            result["findings"].append(_finding(
                "Missing Certificate Transparency SCT Extension",
                "Low",
                "Certificate did not contain embedded SCT extensions. This may be normal if SCTs are delivered another way.",
                "SCT extension not present in certificate",
                0.75,
            ))

        try:
            verify_ctx = ssl.create_default_context()
            verify_ctx.check_hostname = True
            
            v_reader, v_writer = await asyncio.wait_for(
                asyncio.open_connection(target, port, ssl=verify_ctx),
                timeout=10.0
            )
            v_writer.close()
            await v_writer.wait_closed()
            result["is_valid"] = True
        except ssl.SSLCertVerificationError as e:
            result["is_valid"] = False
            err_str = str(e)
            if "unable to get local issuer certificate" in err_str:
                result["findings"].append({
                    "title": "Incomplete Certificate Chain",
                    "severity": "Medium",
                    "description": "The server failed to provide intermediate certificates.",
                    "category": "TLS/SSL",
                    "confidence_score": 0.90,
                    "evidence": err_str,
                    "detection_method": "Verified TLS connection",
                    "exploit_verified": False,
                    "passive_only": True,
                })
            else:
                result["findings"].append({
                    "title": "Certificate Verification Failed",
                    "severity": "High",
                    "description": err_str,
                    "category": "TLS/SSL",
                    "confidence_score": 0.90,
                    "evidence": err_str,
                    "detection_method": "Verified TLS connection",
                    "exploit_verified": False,
                    "passive_only": True,
                })
        except Exception:
            result["is_valid"] = False

    except Exception as e:
        result["has_error"] = True
        result["error_message"] = str(e)
        
    return result
