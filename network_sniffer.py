#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Basic Network Sniffer - Internship Task 1
Uses scapy to capture and analyze network packets.

Windows: Run CMD as Administrator, then: python network_sniffer.py
Linux  : sudo python3 network_sniffer.py
"""

import os
import sys

# Fix Windows CMD encoding (must be before any print)
if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw, DNS, DNSQR, DNSRR
from datetime import datetime

# -----------------------------------------
# CONFIG
# -----------------------------------------
PACKET_COUNT = 100        # How many packets to capture (0 = infinite)
SAVE_LOG     = True       # Save output to a .txt log file
LOG_FILE     = "capture_log.txt"
FILTER       = ""         # BPF filter e.g. "tcp port 80" or "" for all traffic

# Stats counters
stats = {"TCP": 0, "UDP": 0, "ICMP": 0, "OTHER": 0, "TOTAL": 0}

# Log file handle
log_handle = None


# -----------------------------------------
# HELPERS
# -----------------------------------------
def log(msg):
    """Print to console and optionally write to log file."""
    try:
        print(msg)
    except UnicodeEncodeError:
        print(msg.encode("ascii", errors="replace").decode())
    if SAVE_LOG and log_handle:
        log_handle.write(msg + "\n")
        log_handle.flush()


def get_proto_name(packet):
    if TCP in packet:  return "TCP"
    if UDP in packet:  return "UDP"
    if ICMP in packet: return "ICMP"
    return "OTHER"


def get_service(port):
    """Map common ports to service names."""
    services = {
        20: "FTP-DATA", 21: "FTP", 22: "SSH", 23: "TELNET",
        25: "SMTP", 53: "DNS", 67: "DHCP", 68: "DHCP",
        80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS",
        3306: "MySQL", 3389: "RDP", 8080: "HTTP-ALT",
    }
    return services.get(port, str(port))


# -----------------------------------------
# DNS PARSER
# -----------------------------------------
def parse_dns(packet):
    if DNS not in packet:
        return None

    dns = packet[DNS]

    # DNS Query
    if dns.qr == 0 and dns.qdcount > 0 and DNSQR in packet:
        qname = packet[DNSQR].qname.decode(errors="replace").rstrip(".")
        return f"  [DNS QUERY]  -> Asking for: {qname}"

    # DNS Response
    if dns.qr == 1 and dns.ancount > 0 and DNSRR in packet:
        rr = packet[DNSRR]
        try:
            rdata = rr.rdata
            if isinstance(rdata, bytes):
                rdata = rdata.decode(errors="replace")
            name = rr.rrname.decode(errors="replace").rstrip(".")
            return f"  [DNS REPLY]  -> {name} = {rdata}"
        except Exception:
            return "  [DNS REPLY]  -> (could not parse)"

    return None


# -----------------------------------------
# PAYLOAD PARSER
# -----------------------------------------
def parse_payload(packet):
    if Raw not in packet:
        return None

    raw     = packet[Raw].load
    preview = raw[:80]

    try:
        text = preview.decode("utf-8", errors="strict")
        text = text.replace("\r\n", " | ").replace("\n", " | ").strip()
        return f"  [PAYLOAD]    -> {text[:120]}"
    except UnicodeDecodeError:
        hex_str = preview.hex()
        return f"  [PAYLOAD-HEX]-> {hex_str[:80]}"


# -----------------------------------------
# MAIN PACKET HANDLER
# -----------------------------------------
def packet_callback(packet):
    stats["TOTAL"] += 1

    if IP not in packet:
        return

    ip    = packet[IP]
    proto = get_proto_name(packet)
    stats[proto] += 1

    timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]
    divider   = "-" * 65

    log(divider)
    log(f"  [{timestamp}]  Packet #{stats['TOTAL']}  |  Protocol: {proto}")
    log(f"  [IP]         SRC: {ip.src:<18}  ->  DST: {ip.dst}")
    log(f"               TTL: {ip.ttl}  |  Length: {ip.len} bytes")

    # TCP
    if TCP in packet:
        tcp   = packet[TCP]
        sport = get_service(tcp.sport)
        dport = get_service(tcp.dport)
        flags = tcp.sprintf("%TCP.flags%")
        log(f"  [TCP]        SRC Port: {sport:<10}  DST Port: {dport}")
        log(f"               Flags: {flags}  |  Seq: {tcp.seq}  Ack: {tcp.ack}")

    # UDP
    elif UDP in packet:
        udp   = packet[UDP]
        sport = get_service(udp.sport)
        dport = get_service(udp.dport)
        log(f"  [UDP]        SRC Port: {sport:<10}  DST Port: {dport}")

    # ICMP
    elif ICMP in packet:
        icmp = packet[ICMP]
        icmp_types = {
            0: "Echo Reply", 8: "Echo Request",
            3: "Dest Unreachable", 11: "TTL Exceeded"
        }
        icmp_name = icmp_types.get(icmp.type, f"Type {icmp.type}")
        log(f"  [ICMP]       Type: {icmp_name}  |  Code: {icmp.code}")

    # DNS
    dns_info = parse_dns(packet)
    if dns_info:
        log(dns_info)

    # Payload
    payload_info = parse_payload(packet)
    if payload_info:
        log(payload_info)


# -----------------------------------------
# SUMMARY
# -----------------------------------------
def print_summary():
    log("\n" + "=" * 65)
    log("  CAPTURE SUMMARY")
    log("=" * 65)
    log(f"  Total Packets : {stats['TOTAL']}")
    log(f"  TCP           : {stats['TCP']}")
    log(f"  UDP           : {stats['UDP']}")
    log(f"  ICMP          : {stats['ICMP']}")
    log(f"  Other         : {stats['OTHER']}")
    log("=" * 65)
    if SAVE_LOG:
        log(f"  Log saved to  : {LOG_FILE}")
    log("")


# -----------------------------------------
# ENTRY POINT
# -----------------------------------------
def main():
    global log_handle

    # Linux/Mac: check for root
    if os.name != "nt" and os.geteuid() != 0:
        print("\n[!] ERROR: Run this script with sudo:")
        print("    sudo python3 network_sniffer.py\n")
        sys.exit(1)

    # Open log file with UTF-8 encoding
    if SAVE_LOG:
        log_handle = open(LOG_FILE, "w", encoding="utf-8")

    print("\n" + "=" * 65)
    print("  NETWORK SNIFFER  |  Internship Task 1")
    print("=" * 65)
    print(f"  Capturing : {PACKET_COUNT if PACKET_COUNT > 0 else 'infinite'} packets")
    print(f"  Filter    : '{FILTER}' (empty = all traffic)")
    print(f"  Logging   : {'Yes -> ' + LOG_FILE if SAVE_LOG else 'No'}")
    print("  Press Ctrl+C to stop early")
    print("=" * 65 + "\n")

    try:
        sniff(
            prn=packet_callback,
            store=False,
            count=PACKET_COUNT,
            filter=FILTER if FILTER else None,
        )
    except KeyboardInterrupt:
        print("\n[!] Capture stopped by user.")
    finally:
        print_summary()
        if log_handle:
            log_handle.close()


if __name__ == "__main__":
    main()
