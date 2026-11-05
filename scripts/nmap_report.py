#!/usr/bin/env python3
"""Parse an Nmap XML scan and generate a Markdown report flagging risky or outdated services."""
import re
import sys
import xml.etree.ElementTree as ET
from datetime import datetime

# Ports that are risky when exposed: port -> (name, why, severity)
RISKY_PORTS = {
    21:   ("FTP", "Unencrypted file transfer; credentials sent in plain text", "High"),
    23:   ("Telnet", "Unencrypted remote shell; credentials sent in plain text", "Critical"),
    69:   ("TFTP", "No authentication", "High"),
    80:   ("HTTP", "Unencrypted web traffic", "Medium"),
    139:  ("NetBIOS", "Legacy file sharing, common attack target", "High"),
    445:  ("SMB", "File sharing, frequent exploit target", "High"),
    3389: ("RDP", "Remote desktop, frequent brute-force target", "High"),
    5900: ("VNC", "Remote desktop, often weakly protected", "High"),
}

# Minimum version considered reasonably current (update these as you research)
MIN_VERSIONS = {
    "dnsmasq": "2.90",
    "openssh": "9.0",
    "nginx": "1.24",
    "apache httpd": "2.4.58",
}


def to_tuple(version):
    return tuple(int(n) for n in re.findall(r"\d+", version)[:3])


def is_outdated(product, version):
    minimum = MIN_VERSIONS.get(product.lower())
    if not minimum or not version:
        return None
    try:
        return to_tuple(version) < to_tuple(minimum), minimum
    except ValueError:
        return None


def parse(xml_file):
    root = ET.parse(xml_file).getroot()
    results = []
    for host in root.findall("host"):
        addr = host.find("address").get("addr")
        name_el = host.find("hostnames/hostname")
        name = name_el.get("name") if name_el is not None else "unknown"
        ports = []
        for p in host.findall("ports/port"):
            if p.find("state").get("state") != "open":
                continue
            svc = p.find("service")
            ports.append({
                "port": int(p.get("portid")),
                "proto": p.get("protocol"),
                "service": svc.get("name", "unknown") if svc is not None else "unknown",
                "product": svc.get("product", "") if svc is not None else "",
                "version": svc.get("version", "") if svc is not None else "",
            })
        results.append({"addr": addr, "name": name, "ports": ports})
    return results


def build_report(hosts, source):
    lines = [
        "# Nmap Scan Report",
        f"\nSource file: `{source}`  ",
        f"Generated: {datetime.now():%Y-%m-%d %H:%M}\n",
    ]
    findings = 0
    for h in hosts:
        lines.append(f"## Host: {h['addr']} ({h['name']})\n")
        if not h["ports"]:
            lines.append("No open ports found in scanned range.\n")
            continue
        lines.append("| Port | Service | Product | Version | Flags |")
        lines.append("|------|---------|---------|---------|-------|")
        for p in h["ports"]:
            flags = []
            if p["port"] in RISKY_PORTS:
                n, why, sev = RISKY_PORTS[p["port"]]
                flags.append(f"{sev}: {n} - {why}")
            old = is_outdated(p["product"], p["version"])
            if old and old[0]:
                flags.append(f"Outdated (current baseline {old[1]}+)")
            findings += len(flags)
            lines.append(
                f"| {p['port']}/{p['proto']} | {p['service']} | {p['product'] or '-'} "
                f"| {p['version'] or '-'} | {'; '.join(flags) or 'None'} |"
            )
        lines.append("")
    lines.append(f"**Total flagged findings: {findings}**")
    lines.append("\n_Note: version-based flags are potential issues, not confirmed vulnerabilities._")
    return "\n".join(lines)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit("Usage: nmap_report.py <scan.xml> [output.md]")
    out = sys.argv[2] if len(sys.argv) > 2 else "report/scan_report.md"
    report = build_report(parse(sys.argv[1]), sys.argv[1])
    with open(out, "w") as f:
        f.write(report)
    print(report)
    print(f"\nSaved to {out}")
