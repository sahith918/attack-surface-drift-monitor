"""
scanner.py

Wraps Nmap (via python-nmap) to produce a structured snapshot of a host's
open ports/services, ready to hand to state_store.save_snapshot().

Requires the `nmap` binary on PATH and the `python-nmap` pip package.
"""

import nmap


class ScanError(Exception):
    pass


def scan_host(host: str, arguments: str = "-sV --open") -> list[dict]:
    """
    Run an Nmap scan against a single host and return findings as:
        [{port, protocol, state, service, product, version, banner}, ...]
    """
    scanner = nmap.PortScanner()

    try:
        scanner.scan(hosts=host, arguments=arguments)
    except nmap.PortScannerError as e:
        raise ScanError(f"Nmap failed to scan {host}: {e}") from e

    if host not in scanner.all_hosts():
        return []

    findings = []
    host_data = scanner[host]

    for protocol in host_data.all_protocols():
        ports = host_data[protocol].keys()
        for port in sorted(ports):
            port_info = host_data[protocol][port]
            findings.append({
                "port": port,
                "protocol": protocol,
                "state": port_info.get("state", "unknown"),
                "service": port_info.get("name") or None,
                "product": port_info.get("product") or None,
                "version": port_info.get("version") or None,
                "banner": _build_banner(port_info),
            })

    return findings


def _build_banner(port_info: dict) -> str | None:
    parts = [port_info.get("product", ""), port_info.get("version", ""),
              port_info.get("extrainfo", "")]
    banner = " ".join(p for p in parts if p).strip()
    return banner or None


if __name__ == "__main__":
    import sys
    import json

    target = sys.argv[1] if len(sys.argv) > 1 else "192.168.56.103"
    print(f"Scanning {target} ...")
    try:
        results = scan_host(target)
    except ScanError as e:
        print(f"Error: {e}")
        sys.exit(1)
    
    print(json.dumps(results, indent=2))
    print(f"\n{len(results)} finding(s)")
        
