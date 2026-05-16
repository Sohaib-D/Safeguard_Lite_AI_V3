import asyncio
import socket
import time

COMMON_PORTS = {
    20: "FTP-DATA", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 
    53: "DNS", 67: "DHCP", 68: "DHCP", 69: "TFTP", 80: "HTTP", 
    110: "POP3", 111: "RPCBind", 119: "NNTP", 123: "NTP", 135: "MSRPC", 
    137: "NetBIOS-NS", 138: "NetBIOS-DGM", 139: "NetBIOS-SSN", 143: "IMAP", 
    161: "SNMP", 162: "SNMP-TRAP", 179: "BGP", 389: "LDAP", 443: "HTTPS", 
    445: "SMB", 465: "SMTPS", 500: "ISAKMP", 514: "Syslog", 515: "LPD", 
    587: "SMTP-Submission", 636: "LDAPS", 873: "Rsync", 993: "IMAPS", 
    995: "POP3S", 1080: "SOCKS", 1194: "OpenVPN", 1433: "MSSQL", 
    1434: "MSSQL-Monitor", 1521: "Oracle-SQLNet", 1723: "PPTP", 2049: "NFS", 
    2082: "cPanel", 2083: "cPanel-SSL", 2181: "ZooKeeper", 3306: "MySQL", 
    3389: "RDP", 4848: "GlassFish", 5000: "UPnP", 5432: "PostgreSQL", 
    5672: "AMQP", 5900: "VNC", 6379: "Redis", 8000: "HTTP-Alt", 
    8080: "HTTP-Proxy", 8443: "HTTPS-Alt", 9000: "SonarQube", 
    9200: "Elasticsearch", 11211: "Memcached", 27017: "MongoDB"
}

CRITICAL_PORTS = {23, 21, 3389, 6379, 27017, 9200}
HIGH_RISK_PORTS = {22, 3306, 5432, 1433}

TOP_1000_PORTS = list(set(list(range(1, 1025)) + [
    1433, 1434, 1521, 1723, 2049, 2082, 2083, 2181, 3306, 3389, 
    4848, 5000, 5432, 5672, 5900, 6379, 8000, 8080, 8443, 9000, 
    9200, 11211, 27017
]))

async def _scan_single_port(target: str, port: int, sem: asyncio.Semaphore) -> tuple[int, bool, str]:
    async with sem:
        for attempt in range(2):  # One retry for transient failures
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(target, port), timeout=5.0
                )
                banner = ""
                try:
                    data = await asyncio.wait_for(reader.read(512), timeout=3.0)
                    banner = data.decode("utf-8", errors="replace").strip()
                except (asyncio.TimeoutError, Exception):
                    pass
                finally:
                    writer.close()
                    try:
                        await writer.wait_closed()
                    except Exception:
                        pass
                return (port, True, banner)
            except ConnectionRefusedError:
                return (port, False, "")  # Definitively closed, no retry
            except (asyncio.TimeoutError, OSError):
                if attempt == 0:
                    await asyncio.sleep(0.1)  # Brief pause before retry
                    continue
                return (port, False, "")

async def scan_ports(target: str, quick: bool = True) -> dict:
    start_time = time.time()
    sem = asyncio.Semaphore(100)  # Conservative for Windows socket stability
    
    if quick:
        ports_to_scan = TOP_1000_PORTS
    else:
        ports_to_scan = range(1, 65536)
    total_scanned = len(ports_to_scan) if hasattr(ports_to_scan, "__len__") else 65535
        
    results = []
    ports_list = list(ports_to_scan)
    # Build tasks in bounded batches so full scans do not allocate tens of
    # thousands of pending sockets/tasks at once, which is especially fragile
    # on Windows.
    batch_size = 1000
    for start in range(0, len(ports_list), batch_size):
        batch = ports_list[start:start + batch_size]
        tasks = [_scan_single_port(target, port, sem) for port in batch]
        results.extend(await asyncio.gather(*tasks))
    
    open_ports = []
    critical_ports = []
    high_risk_ports = []
    banners = {}
    findings = []
    
    for port, is_open, banner in results:
        if is_open:
            port_info = {
                "port": port,
                "service": COMMON_PORTS.get(port, "Unknown")
            }
            open_ports.append(port_info)
            if banner:
                banners[port] = banner
                
            if port in CRITICAL_PORTS:
                critical_ports.append(port_info)
                findings.append({
                    "title": f"Externally Accessible Service: {port_info['service']} (port {port})",
                    "severity": "High",
                    "description": f"Port {port} ({port_info['service']}) is externally reachable. This is an exposure observation for a frequently targeted service, not proof of compromise.",
                    "category": "Heuristic Observation",
                    "confidence_score": 0.95,
                    "evidence": f"TCP connection to port {port} succeeded",
                    "detection_method": "TCP connect scan",
                    "reasoning": "The service is reachable from the scanner and should be reviewed for business need, access controls, and hardening.",
                    "exploit_verified": False,
                    "passive_only": True,
                    "remediation": f"Restrict access to TCP/{port} if it is not intentionally public. Prefer VPN, firewall allowlists, and strong authentication for administrative services.",
                })
            elif port in HIGH_RISK_PORTS:
                high_risk_ports.append(port_info)
                findings.append({
                    "title": f"Sensitive Service Accessible: {port_info['service']} (port {port})",
                    "severity": "Medium",
                    "description": f"Port {port} ({port_info['service']}) is accessible. This is not a vulnerability by itself; verify that exposure is intended and hardened.",
                    "category": "Heuristic Observation",
                    "confidence_score": 0.90,
                    "evidence": f"TCP connection to port {port} succeeded",
                    "detection_method": "TCP connect scan",
                    "reasoning": "Publicly reachable administrative or data services increase attack surface when not restricted.",
                    "exploit_verified": False,
                    "passive_only": True,
                    "remediation": f"Confirm TCP/{port} is required externally. Apply firewall restrictions and strong authentication.",
                })
                
    duration = time.time() - start_time
    
    return {
        "open_ports": open_ports,
        "critical_ports": critical_ports,
        "high_risk_ports": high_risk_ports,
        "banners": banners,
        "total_open": len(open_ports),
        "total_scanned": total_scanned,
        "scan_duration_seconds": round(duration, 2),
        "findings": findings,
    }
