import logging
import dns.resolver
import socket
from typing import Dict, Any

logger = logging.getLogger("safeguard.network.recon")

class SafeRecon:
    """Safe, non-offensive reconnaissance toolset."""
    
    @staticmethod
    def dns_lookup(domain: str) -> Dict[str, Any]:
        """Performs basic DNS record enumeration."""
        results = {}
        record_types = ["A", "MX", "NS", "TXT"]
        
        for rtype in record_types:
            try:
                answers = dns.resolver.resolve(domain, rtype)
                results[rtype] = [str(rdata) for rdata in answers]
            except Exception:
                results[rtype] = []
        return results

    @staticmethod
    def banner_grab(ip: str, port: int) -> str:
        """Attempts to grab service banners safely."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(2.0)
                s.connect((ip, port))
                s.send(b"GET / HTTP/1.1\r\nHost: test\r\n\r\n")
                banner = s.recv(1024).decode("utf-8", errors="ignore")
                return banner.strip()
        except Exception as e:
            return f"Banner grab failed: {str(e)}"
