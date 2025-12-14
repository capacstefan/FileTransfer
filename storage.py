"""
Storage module - Config and History persistence
Handles all file-based storage operations
"""
from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path
from threading import RLock
from typing import List, Optional, Dict, Any

# Paths
APP_DIR = Path(__file__).parent
DATA_DIR = APP_DIR / "Data"
CONFIG_FILE = DATA_DIR / "config.json"
HISTORY_FILE = DATA_DIR / "history.json"
KEYS_DIR = DATA_DIR / "keys"

# Ensure directories exist
DATA_DIR.mkdir(exist_ok=True)
KEYS_DIR.mkdir(exist_ok=True)


# ============================================================
# Configuration
# ============================================================

DEFAULT_CONFIG = {
    "profile": {
        "username": os.environ.get("COMPUTERNAME", os.environ.get("HOSTNAME", "FIshare"))[:32],
        "availability": "available",  # "available" or "busy"
        "download_dir": str(Path.home() / "Downloads" / "FIshare"),
    },
    "network": {
        "tcp_port": 49222,
        "chunk_size": 1048576,  # 1MB chunks
        "max_concurrent_transfers": 8,
        "max_streams_per_transfer": 4,
    },
    "discovery": {
        "udp_port": 49221,
        "multicast_group": "239.255.255.250",
        "announce_interval_sec": 1.5,
        "peer_timeout_sec": 6.0,
        "method": "multicast",  # "multicast" or "broadcast"
    },
}


class Config:
    """Thread-safe configuration manager"""
    
    def __init__(self):
        self._lock = RLock()
        self._data: Dict[str, Any] = {}
        self.load()
    
    def load(self) -> None:
        with self._lock:
            if CONFIG_FILE.exists():
                try:
                    with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                        loaded = json.load(f)
                    # Deep merge with defaults
                    self._data = self._deep_merge(DEFAULT_CONFIG, loaded)
                except Exception:
                    self._data = DEFAULT_CONFIG.copy()
            else:
                self._data = DEFAULT_CONFIG.copy()
            
            # Ensure download dir exists
            try:
                Path(self._data["profile"]["download_dir"]).mkdir(parents=True, exist_ok=True)
            except Exception:
                pass
    
    def save(self) -> None:
        with self._lock:
            try:
                with open(CONFIG_FILE, "w", encoding="utf-8") as f:
                    json.dump(self._data, f, indent=2, ensure_ascii=False)
            except Exception:
                pass
    
    def _deep_merge(self, base: dict, override: dict) -> dict:
        result = base.copy()
        for k, v in override.items():
            if k in result and isinstance(result[k], dict) and isinstance(v, dict):
                result[k] = self._deep_merge(result[k], v)
            else:
                result[k] = v
        return result
    
    def __getitem__(self, key: str) -> Any:
        with self._lock:
            return self._data[key]
    
    def __setitem__(self, key: str, value: Any) -> None:
        with self._lock:
            self._data[key] = value
            self.save()
    
    def get(self, *keys: str, default: Any = None) -> Any:
        """Get nested config value: config.get("profile", "username")"""
        with self._lock:
            current = self._data
            for key in keys:
                if isinstance(current, dict) and key in current:
                    current = current[key]
                else:
                    return default
            return current
    
    def set(self, *keys_and_value) -> None:
        """Set nested config value: config.set("profile", "username", "NewName")"""
        if len(keys_and_value) < 2:
            return
        keys = keys_and_value[:-1]
        value = keys_and_value[-1]
        
        with self._lock:
            current = self._data
            for key in keys[:-1]:
                if key not in current:
                    current[key] = {}
                current = current[key]
            current[keys[-1]] = value
            self.save()


# ============================================================
# Transfer History
# ============================================================

@dataclass
class TransferRecord:
    """Single transfer record"""
    transfer_id: str
    timestamp: float
    direction: str  # "send" or "receive"
    peer_name: str
    peer_host: str
    num_files: int
    total_bytes: int
    duration_sec: float
    status: str  # "completed", "error", "canceled"
    error_msg: Optional[str] = None
    avg_speed_mbps: float = 0.0
    sha256_verified: Optional[bool] = None
    
    @property
    def timestamp_str(self) -> str:
        return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(self.timestamp))
    
    def to_dict(self) -> dict:
        return asdict(self)
    
    @classmethod
    def from_dict(cls, d: dict) -> TransferRecord:
        return cls(**d)


class TransferHistory:
    """Thread-safe transfer history manager"""
    
    MAX_RECORDS = 1000
    
    def __init__(self):
        self._lock = RLock()
        self._records: List[TransferRecord] = []
        self.load()
    
    def load(self) -> None:
        with self._lock:
            if HISTORY_FILE.exists():
                try:
                    with open(HISTORY_FILE, "r", encoding="utf-8") as f:
                        data = json.load(f)
                    self._records = [TransferRecord.from_dict(r) for r in data]
                except Exception:
                    self._records = []
            else:
                self._records = []
    
    def save(self) -> None:
        with self._lock:
            try:
                with open(HISTORY_FILE, "w", encoding="utf-8") as f:
                    json.dump([r.to_dict() for r in self._records], f, indent=2, ensure_ascii=False)
            except Exception:
                pass
    
    def add(self, record: TransferRecord) -> None:
        with self._lock:
            self._records.insert(0, record)
            # Trim to max size
            if len(self._records) > self.MAX_RECORDS:
                self._records = self._records[:self.MAX_RECORDS]
            self.save()
    
    def get_all(self) -> List[TransferRecord]:
        with self._lock:
            return list(self._records)
    
    def delete(self, index: int) -> bool:
        with self._lock:
            if 0 <= index < len(self._records):
                self._records.pop(index)
                self.save()
                return True
            return False
    
    def clear(self) -> None:
        with self._lock:
            self._records = []
            self.save()


# Singleton instances
_config: Optional[Config] = None
_history: Optional[TransferHistory] = None


def get_config() -> Config:
    global _config
    if _config is None:
        _config = Config()
    return _config


def get_history() -> TransferHistory:
    global _history
    if _history is None:
        _history = TransferHistory()
    return _history
