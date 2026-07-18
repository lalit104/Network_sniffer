from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from pathlib import Path

from scapy.all import ARP, DNS, DNSQR, Ether, ICMP, IP, Raw, TCP, UDP, sniff

from export import CsvExporter, save_pcap
from filters import packet_matches
from packet_analyzer import PacketAnalyzer, PacketRecord
from utils import Colors, colorize, render_table, supports_color, truncate_text


@dataclass(slots=True)
class CaptureSummary:
    total_packets: int = 0
    tcp_packets: int = 0
    udp_packets: int = 0
    icmp_packets: int = 0
    arp_packets: int = 0


class PacketCapture:
    def __init__(
        self,
        csv_path: str | Path,
        pcap_path: str | Path,
        logger: logging.Logger | None = None,
        use_color: bool | None = None,
    ) -> None:
        self.csv_exporter = CsvExporter(csv_path)
        self.pcap_path = Path(pcap_path)
        self.analyzer = PacketAnalyzer()
        self.logger = logger or logging.getLogger(__name__)
        self.use_color = supports_color() if use_color is None else use_color
        self.summary = CaptureSummary()
        self.records: list[PacketRecord] = []
        self.raw_packets: list[object] = []
        self.packet_number = 0
        self._started_at: float | None = None
        self._last_speed_checkpoint: float | None = None
        self._processed_since_checkpoint = 0

    def start(
        self,
        interface: str | None = None,
        protocol: str = "ALL",
        ip_address: str | None = None,
        count: int = 0,
    ) -> None:
        self._started_at = time.time()
        self._last_speed_checkpoint = self._started_at
        print(self._build_header(interface, protocol, ip_address))

        try:
            sniff(
                iface=interface,
                store=False,
                count=count or 0,
                prn=lambda packet: self._process_packet(packet, protocol, ip_address),
            )
        except KeyboardInterrupt:
            self.logger.info("Capture stopped by user.")
        except PermissionError as exc:
            message = (
                "Packet capture requires elevated privileges on this system. "
                "Run the sniffer with sudo/admin rights or choose an environment that allows raw sockets."
            )
            self.logger.error("%s (%s)", message, exc)
            print(f"\n{message}")
            print("Falling back to built-in demo packets so the capture pipeline can still be exercised.")
            self.run_demo(protocol=protocol, ip_address=ip_address, count=count)
            return
        except OSError as exc:
            self.logger.error("Unable to start packet capture: %s", exc)
            print(f"\nUnable to start packet capture: {exc}")

        save_pcap(self.raw_packets, self.pcap_path)
        self._print_summary()

    def run_demo(self, protocol: str = "ALL", ip_address: str | None = None, count: int = 0) -> None:
        self._started_at = time.time()
        print(self._build_header(None, protocol, ip_address))

        for packet in self._build_demo_packets()[: count or None]:
            if packet_matches(packet, protocol, ip_address):
                self._process_packet(packet, protocol, ip_address)

        save_pcap(self.raw_packets, self.pcap_path)
        self._print_summary()

    def _process_packet(self, packet, protocol: str, ip_address: str | None) -> None:
        if not packet_matches(packet, protocol, ip_address):
            return

        self.packet_number += 1
        self.summary.total_packets += 1
        self._increment_protocol_counter(packet)

        timestamp = getattr(packet, "time", None)
        record = self.analyzer.analyze(packet, self.packet_number, timestamp)
        self.records.append(record)
        self.raw_packets.append(packet)
        self.csv_exporter.append(record)

        self._processed_since_checkpoint += 1
        self._print_packet(record)
        self._print_live_stats()

    def _increment_protocol_counter(self, packet) -> None:
        protocol = packet.summary().split("/")[-1].upper()
        text = packet.summary().upper()
        if "TCP" in text:
            self.summary.tcp_packets += 1
        elif "UDP" in text:
            self.summary.udp_packets += 1
        elif "ICMP" in text:
            self.summary.icmp_packets += 1
        elif "ARP" in text:
            self.summary.arp_packets += 1

    def _build_header(self, interface: str | None, protocol: str, ip_address: str | None) -> str:
        lines = [
            "=" * 110,
            "Basic Network Sniffer",
            f"Interface: {interface or 'default'} | Protocol Filter: {protocol.upper()} | IP Filter: {ip_address or 'All'}",
            "Press Ctrl+C to stop capture.",
            "=" * 110,
        ]
        return "\n".join(lines)

    def _print_packet(self, record: PacketRecord) -> None:
        headers = [
            "No",
            "Timestamp",
            "Source IP",
            "Destination IP",
            "Source MAC",
            "Destination MAC",
            "Protocol",
            "Src Port",
            "Dst Port",
            "Length",
            "Flags",
            "TTL",
            "Payload",
            "Notes",
        ]
        row = [
            str(record.packet_number),
            truncate_text(record.timestamp, 23),
            record.source_ip,
            record.destination_ip,
            record.source_mac,
            record.destination_mac,
            record.protocol,
            record.source_port,
            record.destination_port,
            str(record.packet_length),
            record.tcp_flags,
            record.ttl,
            truncate_text(record.payload or record.decoded_payload or "-", 100),
            record.notes,
        ]

        output = render_table(headers, [row])
        if self.use_color:
            output = output.replace(record.protocol, colorize(record.protocol, Colors.CYAN))
        print(output)

    def _print_live_stats(self) -> None:
        elapsed = max(time.time() - (self._started_at or time.time()), 0.001)
        speed = self.summary.total_packets / elapsed
        print(
            f"Captured: {self.summary.total_packets} | TCP: {self.summary.tcp_packets} | UDP: {self.summary.udp_packets} | "
            f"ICMP: {self.summary.icmp_packets} | ARP: {self.summary.arp_packets} | Speed: {speed:.2f} pkt/s"
        )

    def _print_summary(self) -> None:
        print("\nCapture Summary")
        print("-" * 80)
        print(f"Total Packets Captured: {self.summary.total_packets}")
        print(f"TCP Packets: {self.summary.tcp_packets}")
        print(f"UDP Packets: {self.summary.udp_packets}")
        print(f"ICMP Packets: {self.summary.icmp_packets}")
        print(f"ARP Packets: {self.summary.arp_packets}")
        if self._started_at is not None:
            elapsed = max(time.time() - self._started_at, 0.001)
            print(f"Capture Duration: {elapsed:.2f} seconds")
            print(f"Average Speed: {self.summary.total_packets / elapsed:.2f} pkt/s")
        print(f"CSV Export: {self.csv_exporter.file_path}")
        print(f"PCAP Export: {self.pcap_path}")

    def _build_demo_packets(self) -> list[object]:
        return [
            Ether(src="aa:bb:cc:dd:ee:01", dst="ff:ee:dd:cc:bb:01")
            / IP(src="192.168.1.10", dst="93.184.216.34", ttl=64)
            / TCP(sport=51514, dport=80, flags="PA")
            / Raw(load=b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
            Ether(src="aa:bb:cc:dd:ee:02", dst="ff:ee:dd:cc:bb:02")
            / IP(src="192.168.1.20", dst="8.8.8.8", ttl=58)
            / UDP(sport=5353, dport=53)
            / DNS(rd=1, qd=DNSQR(qname="example.org")),
            Ether(src="aa:bb:cc:dd:ee:03", dst="ff:ee:dd:cc:bb:03")
            / IP(src="10.0.0.5", dst="10.0.0.1", ttl=128)
            / ICMP(type=8, code=0)
            / Raw(load=b"ping-demo-payload"),
            Ether(src="aa:bb:cc:dd:ee:04", dst="ff:ee:dd:cc:bb:04")
            / ARP(psrc="192.168.1.1", pdst="192.168.1.50", hwsrc="aa:bb:cc:dd:ee:04", hwdst="ff:ff:ff:ff:ff:ff"),
        ]

