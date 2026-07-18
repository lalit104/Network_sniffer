from __future__ import annotations

import csv
from pathlib import Path
from typing import Iterable

from scapy.all import wrpcap

from packet_analyzer import PacketRecord


class CsvExporter:
    def __init__(self, file_path: str | Path) -> None:
        self.file_path = Path(file_path)
        self.file_path.parent.mkdir(parents=True, exist_ok=True)
        self._header_written = self.file_path.exists() and self.file_path.stat().st_size > 0

    def append(self, record: PacketRecord) -> None:
        mode = "a" if self.file_path.exists() else "w"
        with self.file_path.open(mode, newline="", encoding="utf-8") as csv_file:
            writer = csv.DictWriter(csv_file, fieldnames=list(record.to_dict().keys()))
            if not self._header_written:
                writer.writeheader()
                self._header_written = True
            writer.writerow(record.to_dict())


def save_pcap(packets: Iterable[object], file_path: str | Path) -> None:
    packet_list = list(packets)
    if not packet_list:
        return
    output_path = Path(file_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    wrpcap(str(output_path), packet_list)

