from __future__ import annotations

import json
import os
import socket
import tempfile
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


# ----------------------------
# Paths / App data management
# ----------------------------

def _project_root() -> Path:
    # root = folder where main.py lives (same level as this file if you keep it in root)
    return Path(__file__).resolve().parent


def data_dir() -> Path:
    """
    Phase 1: keep data alongside the project (./data).
    Later, you can migrate this to %APPDATA%\\LanFileTransfer without changing other modules.
    """
    d = _project_root() / "data"
    d.mkdir(parents=True, exist_ok=True)
    return d


def keys_dir() -> Path:
    d = data_dir() / "keys"
    d.mkdir(parents=True, exist_ok=True)
    return d


def config_path() -> Path:
    return data_dir() / "config.json"


def history_path() -> Path:
    return data_dir() / "history.json"


# ----------------------------
# Defaults
# ----------------------------

def _default_username() -> str:
    # Windows-friendly device name fallback
    try:
        return os.environ.get("COMPUTERNAME") or socket.gethostname()
    except Exception:
        return "UnknownDevice"


def _default_download_dir() -> str:
    # Try Downloads folder, fallback to current user's home
    home = Path.home()
    downloads = home / "Downloads"
    return str(downloads if downloads.exists() else home)


def default_config() -> Dict[str, Any]:
    return {
        "profile": {
            "username": "",  # empty means "use device name"
            "availability": "available",  # "available" | "busy"
            "download_dir": ""  # empty means "use Downloads"
        },
        "limits": {
            "max_parallel_transfers": 4,
            "max_receivers_per_transfer": 8,
            "max_streams_per_transfer": 2,
            "chunk_size_kb": 512
        },
        "discovery": {
            "method": "multicast",  # multicast (primary), later we can add "broadcast" fallback
            "udp_port": 38455,
            "multicast_group": "239.255.50.10",
            "announce_interval_sec": 2.0,
            "peer_timeout_sec": 6.0
        },
        "network": {
            "tcp_port": 38456,
            "connect_timeout_sec": 4.0
        },
        "security": {
            "enabled": True,
            "handshake": "x25519+aesgcm",
            "trust_mode": "prompt"  # prompt | allow_all | deny_unknown (we’ll implement prompt first)
        }
    }


def _merge_defaults(user_cfg: Dict[str, Any], defaults: Dict[str, Any]) -> Dict[str, Any]:
    """
    Merge defaults into user config without deleting user keys.
    Keeps config forward-compatible when we add fields later.
    """
    out = dict(defaults)

    for k, v in user_cfg.items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _merge_defaults(v, out[k])  # type: ignore[arg-type]
        else:
            out[k] = v
    return out


def _sanitize_config(cfg: Dict[str, Any]) -> Dict[str, Any]:
    # Normalize profile
    prof = cfg.setdefault("profile", {})
    if not isinstance(prof, dict):
        cfg["profile"] = prof = {}

    username = str(prof.get("username", "")).strip()
    availability = str(prof.get("availability", "available")).strip().lower()
    download_dir = str(prof.get("download_dir", "")).strip()

    if availability not in ("available", "busy"):
        availability = "available"

    if not username:
        username = _default_username()
    if not download_dir:
        download_dir = _default_download_dir()

    prof["username"] = username
    prof["availability"] = availability
    prof["download_dir"] = download_dir

    # Normalize limits
    limits = cfg.setdefault("limits", {})
    if not isinstance(limits, dict):
        cfg["limits"] = limits = {}

    def _clamp_int(name: str, val: Any, lo: int, hi: int, default: int) -> int:
        try:
            n = int(val)
        except Exception:
            n = default
        return max(lo, min(hi, n))

    limits["max_parallel_transfers"] = _clamp_int(
        "max_parallel_transfers", limits.get("max_parallel_transfers", 4), 1, 32, 4
    )
    limits["max_receivers_per_transfer"] = _clamp_int(
        "max_receivers_per_transfer", limits.get("max_receivers_per_transfer", 8), 1, 128, 8
    )
    limits["max_streams_per_transfer"] = _clamp_int(
        "max_streams_per_transfer", limits.get("max_streams_per_transfer", 2), 1, 16, 2
    )
    limits["chunk_size_kb"] = _clamp_int(
        "chunk_size_kb", limits.get("chunk_size_kb", 512), 16, 4096, 512
    )

    # Normalize discovery/network/security sections minimally (types + basic ranges)
    disc = cfg.setdefault("discovery", {})
    if not isinstance(disc, dict):
        cfg["discovery"] = disc = {}
    disc["method"] = str(disc.get("method", "multicast")).strip().lower()
    if disc["method"] not in ("multicast", "broadcast"):
        disc["method"] = "multicast"
    disc["udp_port"] = _clamp_int("udp_port", disc.get("udp_port", 38455), 1024, 65535, 38455)
    disc["multicast_group"] = str(disc.get("multicast_group", "239.255.50.10")).strip()
    disc["announce_interval_sec"] = float(disc.get("announce_interval_sec", 2.0) or 2.0)
    disc["peer_timeout_sec"] = float(disc.get("peer_timeout_sec", 6.0) or 6.0)

    net = cfg.setdefault("network", {})
    if not isinstance(net, dict):
        cfg["network"] = net = {}
    net["tcp_port"] = _clamp_int("tcp_port", net.get("tcp_port", 38456), 1024, 65535, 38456)
    net["connect_timeout_sec"] = float(net.get("connect_timeout_sec", 4.0) or 4.0)

    sec = cfg.setdefault("security", {})
    if not isinstance(sec, dict):
        cfg["security"] = sec = {}
    sec["enabled"] = bool(sec.get("enabled", True))
    sec["handshake"] = str(sec.get("handshake", "x25519+aesgcm")).strip().lower()
    sec["trust_mode"] = str(sec.get("trust_mode", "prompt")).strip().lower()
    if sec["trust_mode"] not in ("prompt", "allow_all", "deny_unknown"):
        sec["trust_mode"] = "prompt"

    return cfg


# ----------------------------
# Atomic JSON read/write
# ----------------------------

_file_lock = threading.RLock()


def _read_json(path: Path) -> Any:
    if not path.exists():
        return None
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def _atomic_write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_fd, tmp_name = tempfile.mkstemp(prefix=path.name + ".", suffix=".tmp", dir=str(path.parent))
    try:
        with os.fdopen(tmp_fd, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_name, path)  # atomic on Windows
    finally:
        try:
            if os.path.exists(tmp_name):
                os.remove(tmp_name)
        except Exception:
            pass


# ----------------------------
# Config Store
# ----------------------------

def load_config() -> Dict[str, Any]:
    """
    Loads config.json; if missing or invalid, creates a sane default.
    Always returns a sanitized + forward-compatible config dict.
    """
    with _file_lock:
        defaults = default_config()
        raw = _read_json(config_path())
        if not isinstance(raw, dict):
            cfg = defaults
            cfg = _sanitize_config(cfg)
            _atomic_write_json(config_path(), cfg)
            return cfg

        merged = _merge_defaults(raw, defaults)
        merged = _sanitize_config(merged)
        # write back to ensure new keys appear
        _atomic_write_json(config_path(), merged)
        return merged


def save_config(cfg: Dict[str, Any]) -> None:
    with _file_lock:
        cfg = _merge_defaults(cfg, default_config())
        cfg = _sanitize_config(cfg)
        _atomic_write_json(config_path(), cfg)


# ----------------------------
# History Store
# ----------------------------

@dataclass(frozen=True)
class TransferHistoryItem:
    transfer_id: str
    direction: str  # "send" | "receive"
    peer_names: List[str]
    file_count: int
    total_bytes: int
    status: str  # "completed" | "error" | "canceled"
    timestamp_utc: str  # ISO8601
    avg_speed_bps: float
    error: Optional[str] = None


def _now_utc_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def load_history() -> List[Dict[str, Any]]:
    with _file_lock:
        raw = _read_json(history_path())
        if not isinstance(raw, list):
            _atomic_write_json(history_path(), [])
            return []
        return raw


def append_history(item: TransferHistoryItem) -> None:
    with _file_lock:
        hist = load_history()
        hist.append({
            "transfer_id": item.transfer_id,
            "direction": item.direction,
            "peer_names": item.peer_names,
            "file_count": item.file_count,
            "total_bytes": item.total_bytes,
            "status": item.status,
            "timestamp_utc": item.timestamp_utc,
            "avg_speed_bps": item.avg_speed_bps,
            "error": item.error
        })
        _atomic_write_json(history_path(), hist)


def record_transfer(
    transfer_id: str,
    direction: str,
    peer_names: List[str],
    file_count: int,
    total_bytes: int,
    status: str,
    avg_speed_bps: float,
    error: Optional[str] = None
) -> None:
    """
    Convenience helper used by core/network when a transfer ends.
    """
    append_history(
        TransferHistoryItem(
            transfer_id=transfer_id,
            direction=direction,
            peer_names=peer_names,
            file_count=file_count,
            total_bytes=total_bytes,
            status=status,
            timestamp_utc=_now_utc_iso(),
            avg_speed_bps=float(avg_speed_bps),
            error=error
        )
    )


# ----------------------------
# Key storage (simple file-based)
# ----------------------------

def key_file(name: str) -> Path:
    # e.g. "identity_private.key", "identity_public.key"
    safe = "".join(ch for ch in name if ch.isalnum() or ch in ("_", "-", "."))
    return keys_dir() / safe


def write_key_bytes(name: str, data: bytes) -> None:
    with _file_lock:
        p = key_file(name)
        p.parent.mkdir(parents=True, exist_ok=True)
        tmp_fd, tmp_name = tempfile.mkstemp(prefix=p.name + ".", suffix=".tmp", dir=str(p.parent))
        try:
            with os.fdopen(tmp_fd, "wb") as f:
                f.write(data)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp_name, p)
        finally:
            try:
                if os.path.exists(tmp_name):
                    os.remove(tmp_name)
            except Exception:
                pass


def read_key_bytes(name: str) -> Optional[bytes]:
    with _file_lock:
        p = key_file(name)
        if not p.exists():
            return None
        return p.read_bytes()
