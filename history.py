import json
import time
from dataclasses import dataclass, asdict
from typing import List, Optional
from threading import RLock

from config import HISTORY_FILE


@dataclass
class TransferRecord:
    timestamp: float
    direction: str  # "sent" sau "received"
    peer_name: str
    peer_host: str
    num_files: int
    total_size: int
    duration: float
    status: str
    error_msg: Optional[str] = None
    sha256_ok: Optional[bool] = None

    @property
    def speed_mbps(self) -> float:
        if self.duration > 0 and self.status == "completed":
            return (self.total_size / (1024 * 1024)) / self.duration
        return 0.0

    @property
    def timestamp_str(self) -> str:
        return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(self.timestamp))


class TransferHistory:
    def __init__(self):
        self._lock = RLock()
        self.records: List[TransferRecord] = []
        self.load()

    def load(self):
        try:
            with self._lock:
                with open(HISTORY_FILE, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    self.records = [TransferRecord(**record) for record in data]
        except (FileNotFoundError, json.JSONDecodeError):
            self.records = []

    def save(self):
        try:
            with self._lock:
                with open(HISTORY_FILE, "w", encoding="utf-8") as f:
                    data = [asdict(record) for record in self.records]
                    json.dump(data, f, indent=2, ensure_ascii=False)
        except Exception:
            pass

    def add_record(self, record: TransferRecord):
        with self._lock:
            self.records.insert(0, record)
            if len(self.records) > 1000:
                self.records = self.records[:1000]
            self.save()

    def delete_record(self, index: int):
        with self._lock:
            if 0 <= index < len(self.records):
                self.records.pop(index)
                self.save()

    def clear_all(self):
        with self._lock:
            self.records = []
            self.save()

    def get_all(self) -> List[TransferRecord]:
        with self._lock:
            return list(self.records)
