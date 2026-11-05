#!/usr/bin/env python3
"""Detect TCP SYN port scans in a pcap file.
Rule: one source IP sends SYNs to >= THRESHOLD distinct ports within WINDOW seconds.
"""
import subprocess
import sys
from collections import defaultdict

THRESHOLD = 20   # distinct destination ports
WINDOW = 5.0     # seconds


def read_syns(pcap):
    """Use tshark to extract (time, src, dst, dport) for every SYN without ACK."""
    cmd = [
        "tshark", "-r", pcap,
        "-Y", "tcp.flags.syn == 1 && tcp.flags.ack == 0",
        "-T", "fields",
        "-e", "frame.time_relative", "-e", "ip.src", "-e", "ip.dst", "-e", "tcp.dstport",
    ]
    out = subprocess.run(cmd, capture_output=True, text=True, check=True).stdout
    events = []
    for line in out.splitlines():
        parts = line.split("\t")
        if len(parts) == 4 and all(parts):
            events.append((float(parts[0]), parts[1], parts[2], int(parts[3])))
    return events


def detect(events):
    by_pair = defaultdict(list)
    for t, src, dst, port in events:
        by_pair[(src, dst)].append((t, port))

    alerts = []
    for (src, dst), probes in by_pair.items():
        probes.sort()
        start = 0
        for end in range(len(probes)):
            while probes[end][0] - probes[start][0] > WINDOW:
                start += 1
            ports = {p for _, p in probes[start:end + 1]}
            if len(ports) >= THRESHOLD:
                alerts.append({
                    "src": src, "dst": dst, "ports": len(ports),
                    "first": probes[start][0], "last": probes[end][0],
                })
                break  # one alert per source/target pair
    return alerts


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit("Usage: detect_scan.py <capture.pcapng>")
    events = read_syns(sys.argv[1])
    print(f"Analyzed {len(events)} SYN packets from {sys.argv[1]}")
    alerts = detect(events)
    if not alerts:
        print("No port scans detected.")
    for a in alerts:
        print(f"[ALERT] Possible port scan: {a['src']} -> {a['dst']} "
              f"probed {a['ports']}+ distinct ports "
              f"between t={a['first']:.3f}s and t={a['last']:.3f}s")
