from __future__ import annotations

import json
import platform
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Dict

from ..backend.constants import (
    DEFAULT_BROADCAST_INTERVAL,
    DEFAULT_MAX_FILE_SIZE_BYTES,
    DEFAULT_MAX_STREAMS,
    DEFAULT_TCP_PORT,
    DEFAULT_UDP_PORT,
)
from .paths import CONFIG_PATH, STATE_DIR, ensure_state_dirs


@dataclass(slots=True)
class AppConfig:
    username: str
    status: str
    download_dir: Path
    udp_port: int = DEFAULT_UDP_PORT
    tcp_port: int = DEFAULT_TCP_PORT
    broadcast_interval: float = DEFAULT_BROADCAST_INTERVAL
    max_concurrent_streams: int = DEFAULT_MAX_STREAMS
    max_file_size_bytes: int = DEFAULT_MAX_FILE_SIZE_BYTES

    def to_json(self) -> Dict[str, Any]:
        data = asdict(self)
        data["download_dir"] = str(self.download_dir)
        return data

    @classmethod
    def from_json(cls, data: Dict[str, Any]) -> "AppConfig":
        return cls(
            username=data.get("username", platform.node()),
            status=data.get("status", "available"),
            download_dir=Path(data.get("download_dir", STATE_DIR / "downloads")),
            udp_port=int(data.get("udp_port", DEFAULT_UDP_PORT)),
            tcp_port=int(data.get("tcp_port", DEFAULT_TCP_PORT)),
            broadcast_interval=float(data.get("broadcast_interval", DEFAULT_BROADCAST_INTERVAL)),
            max_concurrent_streams=int(data.get("max_concurrent_streams", DEFAULT_MAX_STREAMS)),
            max_file_size_bytes=int(data.get("max_file_size_bytes", DEFAULT_MAX_FILE_SIZE_BYTES)),
        )


class ConfigStore:
    """Loads and saves config.json inside state/."""

    def __init__(self, path: Path = CONFIG_PATH) -> None:
        self.path = path

    def load(self) -> AppConfig:
        ensure_state_dirs()
        if not self.path.exists():
            cfg = self._default_config()
            self.save(cfg)
            return cfg
        try:
            data = json.loads(self.path.read_text())
            return AppConfig.from_json(data)
        except (json.JSONDecodeError, OSError):
            cfg = self._default_config()
            self.save(cfg)
            return cfg

    def save(self, config: AppConfig) -> None:
        ensure_state_dirs()
        self.path.write_text(json.dumps(config.to_json(), indent=2))

    def _default_config(self) -> AppConfig:
        ensure_state_dirs()
        download_dir = STATE_DIR / "downloads"
        download_dir.mkdir(parents=True, exist_ok=True)
        return AppConfig(
            username=platform.node(),
            status="available",
            download_dir=download_dir,
        )
