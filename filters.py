from __future__ import annotations

from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import ARP

from utils import normalize_ip


def normalize_protocol(protocol: str | None) -> str:
    if not protocol:
        return "ALL"
    return protocol.strip().upper()


def packet_protocol(packet) -> str:
    if packet.haslayer(ARP):
        return "ARP"
    if packet.haslayer(TCP):
        return "TCP"
    if packet.haslayer(UDP):
        return "UDP"
    if packet.haslayer(ICMP):
        return "ICMP"
    return "OTHER"


def packet_matches_protocol(packet, protocol: str) -> bool:
    protocol = normalize_protocol(protocol)
    if protocol == "ALL":
        return True
    return packet_protocol(packet) == protocol


def packet_matches_ip(packet, ip_address: str | None) -> bool:
    normalized = normalize_ip(ip_address)
    if not normalized:
        return True

    candidates = []
    if packet.haslayer(IP):
        candidates.extend([packet[IP].src, packet[IP].dst])
    if packet.haslayer(ARP):
        candidates.extend([packet[ARP].psrc, packet[ARP].pdst])

    return normalized in {normalize_ip(candidate) for candidate in candidates if candidate}


def packet_matches(packet, protocol: str = "ALL", ip_address: str | None = None) -> bool:
    return packet_matches_protocol(packet, protocol) and packet_matches_ip(packet, ip_address)

