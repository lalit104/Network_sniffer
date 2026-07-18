from __future__ import annotations

import argparse
import logging
from pathlib import Path

from packet_capture import PacketCapture


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Basic Network Sniffer using Scapy",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("-i", "--interface", help="Network interface to sniff on")
    parser.add_argument(
        "-p",
        "--protocol",
        choices=["all", "tcp", "udp", "icmp", "arp"],
        default="all",
        help="Filter packets by protocol",
    )
    parser.add_argument("--ip", help="Filter packets by source or destination IP address")
    parser.add_argument("--csv", default="output/packets.csv", help="CSV export file")
    parser.add_argument("--pcap", default="output/capture.pcap", help="PCAP export file")
    parser.add_argument("--log-file", default="output/sniffer.log", help="Log file path")
    parser.add_argument("--count", type=int, default=0, help="Stop after capturing this many matching packets; 0 means unlimited")
    parser.add_argument("--no-color", action="store_true", help="Disable colored terminal output")
    parser.add_argument("--demo", action="store_true", help="Run with built-in demo packets instead of live capture")
    return parser


def configure_logging(log_file: str) -> logging.Logger:
    log_path = Path(log_file)
    log_path.parent.mkdir(parents=True, exist_ok=True)

    logger = logging.getLogger("basic_network_sniffer")
    logger.setLevel(logging.INFO)
    logger.handlers.clear()

    formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")

    file_handler = logging.FileHandler(log_path, encoding="utf-8")
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)

    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(formatter)
    logger.addHandler(stream_handler)

    return logger


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    logger = configure_logging(args.log_file)
    logger.info("Starting Basic Network Sniffer")

    capture = PacketCapture(
        csv_path=args.csv,
        pcap_path=args.pcap,
        logger=logger,
        use_color=not args.no_color,
    )
    if args.demo:
        capture.run_demo(protocol=args.protocol, ip_address=args.ip, count=args.count)
    else:
        capture.start(interface=args.interface, protocol=args.protocol, ip_address=args.ip, count=args.count)


if __name__ == "__main__":
    main()

