from dataclasses import dataclass, field
from enum import Enum
from threading import RLock
import time
from typing import Dict, List


class AppStatus(str, Enum):
    AVAILABLE = "available"
    BUSY = "busy"


class TransferStatus(str, Enum):
    COMPLETED = "completed"
    ERROR = "error"
    CANCELED = "canceled"
    RUNNING = "running"


@dataclass
class Device:
    device_id: str
    name: str
    host: str
    port: int
    status: AppStatus
    last_seen: float = field(default_factory=time.time)


@dataclass
class MonitorStats:
    total_bytes_sent: int = 0
    total_bytes_received: int = 0
    last_speed_mb_s: float = 0.0
    last_update: float = field(default_factory=time.time)
    active_transfers: int = 0
    errors: int = 0


class AppState:
    def __init__(self, cfg):
        self._lock = RLock()
        self.cfg = cfg
        self.status: AppStatus = AppStatus.AVAILABLE if cfg.allow_incoming else AppStatus.BUSY
        self.devices: Dict[str, Device] = {}
        self.selected_device_ids: List[str] = []
        self.selected_files: List[str] = []

        self.progress: Dict[str, float] = {}
        self.transfer_speeds: Dict[str, float] = {}
        self.transfer_start_times: Dict[str, float] = {}
        self.transfer_bytes: Dict[str, int] = {}
        self.transfer_status: Dict[str, TransferStatus] = {}

        self.monitor: Dict[str, MonitorStats] = {}  # per device_id

    def set_status(self, status: AppStatus):
        with self._lock:
            self.status = status

    def upsert_device(self, dev: Device):
        with self._lock:
            dev.last_seen = time.time()
            self.devices[dev.device_id] = dev
            if dev.device_id not in self.monitor:
                self.monitor[dev.device_id] = MonitorStats()

    def update_progress(self, device_id: str, ratio: float, bytes_transferred: int = 0, direction: str = "sent"):
        with self._lock:
            self.progress[device_id] = max(0.0, min(1.0, float(ratio)))
            if bytes_transferred >= 0:
                self.transfer_bytes[device_id] = bytes_transferred
                if device_id in self.transfer_start_times:
                    elapsed = time.time() - self.transfer_start_times[device_id]
                    if elapsed > 0:
                        speed = (bytes_transferred / (1024 * 1024)) / elapsed
                        self.transfer_speeds[device_id] = speed
                        stats = self.monitor.setdefault(device_id, MonitorStats())
                        stats.last_speed_mb_s = speed
                        stats.last_update = time.time()
                        if direction == "sent":
                            stats.total_bytes_sent = max(stats.total_bytes_sent, bytes_transferred)
                        else:
                            stats.total_bytes_received = max(stats.total_bytes_received, bytes_transferred)

    def get_progress(self, device_id: str) -> float:
        with self._lock:
            return float(self.progress.get(device_id, 0.0))

    def get_speed(self, device_id: str) -> float:
        with self._lock:
            return self.transfer_speeds.get(device_id, 0.0)

    def start_transfer(self, device_id: str):
        with self._lock:
            self.transfer_start_times[device_id] = time.time()
            self.transfer_bytes[device_id] = 0
            self.transfer_speeds[device_id] = 0.0
            self.transfer_status[device_id] = TransferStatus.RUNNING
            stats = self.monitor.setdefault(device_id, MonitorStats())
            stats.active_transfers += 1

    def finish_transfer(self, device_id: str, status: TransferStatus):
        with self._lock:
            self.transfer_status[device_id] = status
            stats = self.monitor.setdefault(device_id, MonitorStats())
            stats.active_transfers = max(0, stats.active_transfers - 1)
            if status == TransferStatus.ERROR:
                stats.errors += 1

    def get_transfer_status(self, device_id: str) -> TransferStatus:
        with self._lock:
            return self.transfer_status.get(device_id, TransferStatus.COMPLETED)

    def clear_progress(self, device_id: str):
        with self._lock:
            self.progress.pop(device_id, None)
            self.transfer_speeds.pop(device_id, None)
            self.transfer_start_times.pop(device_id, None)
            self.transfer_bytes.pop(device_id, None)
            self.transfer_status.pop(device_id, None)

    def prune_devices(self, ttl_seconds: float = 6.0):
        with self._lock:
            now = time.time()
            self.devices = {k: v for k, v in self.devices.items() if now - v.last_seen < ttl_seconds}
            self.progress = {k: v for k, v in self.progress.items() if k in self.devices}
            self.selected_device_ids = [d for d in self.selected_device_ids if d in self.devices]
            self.monitor = {k: v for k, v in self.monitor.items() if k in self.devices}
