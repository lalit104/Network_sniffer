from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Optional

from scapy.all import ARP, Ether, IP, IPv6, TCP, UDP, ICMP, Raw, DNS, DNSQR

from filters import packet_protocol
from utils import common_port_name, decode_payload, format_timestamp, normalize_ip, safe_join, truncate_text


@dataclass(slots=True)
class PacketRecord:
    packet_number: int
    timestamp: str
    source_ip: str
    destination_ip: str
    source_mac: str
    destination_mac: str
    protocol: str
    source_port: str
    destination_port: str
    packet_length: int
    tcp_flags: str
    ttl: str
    payload: str
    decoded_payload: str
    notes: str

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


class PacketAnalyzer:
    def analyze(self, packet, packet_number: int, timestamp: float | None = None) -> PacketRecord:
        protocol = packet_protocol(packet)
        source_ip, destination_ip = self._extract_ips(packet)
        source_mac, destination_mac = self._extract_macs(packet)
        source_port, destination_port, tcp_flags = self._extract_ports_and_flags(packet)
        ttl = self._extract_ttl(packet)
        payload_bytes = bytes(packet[Raw].load) if packet.haslayer(Raw) else b""
        payload, decoded_payload = decode_payload(payload_bytes, limit=100)
        packet_length = len(bytes(packet))
        notes = self._build_notes(packet, protocol, source_port, destination_port, payload_bytes)

        return PacketRecord(
            packet_number=packet_number,
            timestamp=format_timestamp(timestamp),
            source_ip=source_ip,
            destination_ip=destination_ip,
            source_mac=source_mac,
            destination_mac=destination_mac,
            protocol=protocol,
            source_port=source_port,
            destination_port=destination_port,
            packet_length=packet_length,
            tcp_flags=tcp_flags,
            ttl=ttl,
            payload=payload,
            decoded_payload=decoded_payload,
            notes=notes,
        )

    def _extract_ips(self, packet) -> tuple[str, str]:
        if packet.haslayer(IP):
            return normalize_ip(packet[IP].src) or "-", normalize_ip(packet[IP].dst) or "-"
        if packet.haslayer(IPv6):
            return packet[IPv6].src, packet[IPv6].dst
        if packet.haslayer(ARP):
            return packet[ARP].psrc or "-", packet[ARP].pdst or "-"
        return "-", "-"

    def _extract_macs(self, packet) -> tuple[str, str]:
        if packet.haslayer(Ether):
            return packet[Ether].src, packet[Ether].dst
        return "-", "-"

    def _extract_ports_and_flags(self, packet) -> tuple[str, str, str]:
        if packet.haslayer(TCP):
            return str(packet[TCP].sport), str(packet[TCP].dport), str(packet[TCP].flags)
        if packet.haslayer(UDP):
            return str(packet[UDP].sport), str(packet[UDP].dport), "-"
        return "-", "-", "-"

    def _extract_ttl(self, packet) -> str:
        if packet.haslayer(IP):
            return str(packet[IP].ttl)
        if packet.haslayer(IPv6):
            return str(packet[IPv6].hlim)
        return "-"

    def _build_notes(self, packet, protocol: str, source_port: str, destination_port: str, payload_bytes: bytes) -> str:
        notes = []
        if protocol == "TCP":
            if source_port.isdigit():
                notes.append(common_port_name(int(source_port)))
            if destination_port.isdigit():
                notes.append(common_port_name(int(destination_port)))
        if protocol == "UDP":
            if source_port == "53" or destination_port == "53":
                notes.append("DNS")
        if packet.haslayer(DNS) or packet.haslayer(DNSQR):
            notes.append("DNS Packet")
        if self._looks_like_http(payload_bytes, source_port, destination_port):
            notes.append("HTTP")
        return safe_join(dict.fromkeys(notes).keys()) or "-"

    def _looks_like_http(self, payload_bytes: bytes, source_port: str, destination_port: str) -> bool:
        if source_port == "80" or destination_port == "80" or source_port == "443" or destination_port == "443":
            return True
        preview = payload_bytes[:12].upper()
        return preview.startswith((b"GET ", b"POST ", b"PUT ", b"DELETE ", b"HEAD ", b"OPTIONS ", b"HTTP/"))

