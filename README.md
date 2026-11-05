# Network Security Assessment: Recon, Traffic Analysis and Scan Detection

A hands-on security assessment of my own network (a personal phone hotspot with one laptop connected), built on a low-spec 4 GB Ubuntu 24.04 machine. The project covers three parts: reconnaissance, traffic analysis, and detection engineering. I wrote two Python tools along the way.

> **Scope and ethics:** Every scan in this repo targets devices I own, on a network I control. Real MAC addresses, hostnames and usernames have been removed from all published files.

## Summary of findings

| # | Finding | Evidence | Severity (my rating) |
|---|---------|----------|----------|
| 1 | Hotspot gateway runs **dnsmasq 2.51** (released ~2010) on port 53 | `scans_public/02_phone.txt` | Medium (see caveats) |
| 2 | Version matches known CVEs, including CVE-2017-14491 (heap overflow, CVSS 9.8) and CVE-2019-14513 (out-of-bounds read, CVSS 7.5) | `scans_public/04_phone_vuln.txt` | Potential, not confirmed |
| 3 | DNS queries travel unencrypted over UDP/53 to the outdated resolver, so any host on the network can see which sites I look up | `screenshots/02_dns.png` | Low |
| 4 | Some applications send data over plain HTTP, such as Chrome usage stats and the Ubuntu connectivity check | `screenshots/03_http_packets.png` | Low |
| 5 | The laptop exposes **no listening TCP ports** (top 1000) | `scans_public/03_laptop.txt` | Good result |

## What I did

### 1. Reconnaissance (Nmap)
- Host discovery (`nmap -sn`): 256 addresses scanned, 2 hosts up (phone gateway and laptop). No unknown devices.
- Service and version scan (`nmap -sV -O`): the phone exposes one port, 53/tcp (dnsmasq 2.51). All other scanned ports closed.
- Vulnerability scan (`--script vuln`, which uses the vulners database): about 60 matches for dnsmasq 2.51.

### 2. Traffic analysis (Wireshark / tshark)
- **DNS** (`screenshots/02_dns.png`): queries and answers are readable by anyone on the network. The phone's dnsmasq is the resolver, which ties the Nmap finding to real traffic.
- **HTTP vs HTTPS** (`screenshots/04_http_stream.png`, `screenshots/06_tls_stream.png`): with plain HTTP, the full request, server software and page content are readable. The same request over TLS shows no readable content. The server name (SNI) is still visible in the TLS handshake.

### 3. Detection engineering
I ran a SYN scan (`nmap -sS -p 1-1000`) against my own phone while capturing traffic, then studied its signature:

| Filter | Result | Meaning |
|--------|--------|---------|
| `tcp.flags.syn==1 && tcp.flags.ack==0` | 1000 packets | One probe per port, all within milliseconds |
| `tcp.flags.syn==1 && tcp.flags.ack==1` | 1 packet | Only port 53 answered (open) |
| `tcp.flags.reset==1` | 1000 packets | Closed ports resetting, plus Nmap's own reset on the open port |

Screenshots: `screenshots/05_scan_syn.png`, `05_scan_synack.png`, `05_scan_rst.png`.

**Detection rule:** flag any source IP that sends SYNs to 20 or more distinct ports on one target within 5 seconds.

| Test capture | SYN packets | Result |
|--------------|-------------|--------|
| Port scan (`05_portscan`) | 1000 | **Alert raised** (true positive) |
| Normal browsing (`04_capture`) | 2 | No alert (true negative) |

## Tools I wrote

| Script | Purpose |
|--------|---------|
| `scripts/nmap_report.py` | Parses Nmap XML (`-oX`) and builds a Markdown report that flags risky ports and outdated service versions |
| `scripts/detect_scan.py` | Uses tshark to extract SYN packets from a pcap and applies a sliding-window rule to detect port scans |

```bash
nmap -sV -oX scans/05_phone.xml <target>
python3 scripts/nmap_report.py scans/05_phone.xml report/phone_report.md
python3 scripts/detect_scan.py captures/<capture>.pcapng
```

## Limitations (what I would improve)

- **Version matching is not exploit verification.** The vulners script reports every CVE ever filed against a version number. Many need features a phone hotspot does not use, vendors sometimes backport fixes without changing the version, and an attacker must already be on the hotspot. I treat these as *potential* issues.
- The "current version" baseline in `nmap_report.py` is a value I set myself. [Update after checking the vendor's release page.]
- The hotspot network is tiny, so there was little to harden. A before/after comparison on a real router with several devices is a planned next step.
- The detection rule only handles TCP SYN scans, and thresholds were tuned on two captures. It would miss slow scans, and it has not been tested against UDP or FIN scans.
- Raw `.pcapng` captures and unredacted scan files are not published, to protect device identifiers.

## Skills demonstrated

Network reconnaissance, service enumeration, CVE research and severity interpretation, packet analysis, protocol behavior (TCP handshake, DNS, HTTP vs TLS), Python tooling and automation, detection logic with true/false-positive testing, responsible disclosure and data sanitization.

## Environment

Ubuntu 24.04 LTS, Nmap 7.94, Wireshark/tshark, Python 3. Runs comfortably on 4 GB RAM.
