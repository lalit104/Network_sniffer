# Basic Network Sniffer

Basic Network Sniffer is a Python 3.11+ project built with Scapy to capture live network packets, analyze them in real time, and export results to CSV and PCAP files. It is designed as a clean cybersecurity lab project with a modular codebase and terminal-friendly output.

## Project Description

This project sniffs packets from a selected network interface, applies protocol and IP filters, and displays packet metadata in a formatted table. It also saves captured packets for later inspection and produces a summary report when the capture stops.

## Objectives

- Capture live network traffic.
- Display packet details in a readable table.
- Support common protocol filtering.
- Export captured data for reporting and analysis.
- Provide useful statistics for quick monitoring.

## Features

- Live packet capture with Scapy.
- Packet number, timestamp, IP/MAC addresses, ports, protocol, length, TTL, flags, and payload preview.
- Payload decoding when possible.
- Protocol filtering for TCP, UDP, ICMP, ARP, or all packets.
- IP address filtering.
- PCAP export.
- CSV export.
- Error handling and logging.
- Summary report on Ctrl+C.
- Colored terminal output.
- Live packet counter and packet processing speed.
- Network interface selection.
- DNS packet detection.
- HTTP request detection.
- Common port detection for 21, 22, 25, 53, 80, and 443.
- Cross-platform support for Windows, Linux, and Kali Linux.

## Installation Steps

1. Make sure Python 3.11 or newer is installed.
2. Create and activate a virtual environment if desired.
3. Install the dependency:

```bash
pip install -r requirements.txt
```

4. On Linux or Kali Linux, run the tool with elevated privileges if packet capture requires it.

## Usage Instructions

Run the sniffer from the project directory:

```bash
python sniffer.py
```

If you do not have packet-capture privileges, the sniffer now falls back to demo packets automatically so you can still exercise the full pipeline without live sniffing. You can also invoke demo mode directly:

```bash
python sniffer.py --demo
```

Examples:

```bash
python sniffer.py --interface eth0 --protocol tcp
python sniffer.py --protocol udp --ip 192.168.1.10
python sniffer.py --interface wlan0 --csv output/packets.csv --pcap output/capture.pcap
python sniffer.py --no-color
```

Stop capturing with Ctrl+C to print the summary report.

## Screenshots

Add screenshots of the live terminal output here after running the project in your lab environment.

Suggested screenshot list:

- Live packet table view.
- Filtered capture example.
- Final summary report.
- CSV and PCAP export files.

## Folder Structure

```text
Basic_Network_Sniffer/
│── sniffer.py
│── packet_capture.py
│── packet_analyzer.py
│── filters.py
│── export.py
│── utils.py
│── requirements.txt
│── README.md
│── output/
│    ├── packets.csv
│    └── capture.pcap
```

## Technologies Used

- Python 3.11+
- Scapy
- csv
- datetime
- os / pathlib
- argparse
- logging

## Future Enhancements

- GUI dashboard for packet monitoring.
- GeoIP enrichment for external addresses.
- Export to JSON and Excel formats.
- Stateful session tracking.
- Packet payload signature matching.
- Real-time alerting for suspicious traffic.

## License

This project is provided for educational use. Add your preferred license before distribution.
