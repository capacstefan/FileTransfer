from __future__ import annotations

import os
import queue
import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

import storage


# ----------------------------
# Data models
# ----------------------------

@dataclass
class Peer:
    peer_id: str           # stable-ish: "username@ip:udpport"
    username: str
    ip: str
    tcp_port: int
    availability: str      # "available" | "busy"
    last_seen: float = field(default_factory=time.time)


@dataclass
class FileItem:
    path: str
    size: int


@dataclass
class TransferProgress:
    transfer_id: str
    direction: str        # "send" | "receive"
    peer_id: str
    peer_name: str
    total_bytes: int
    done_bytes: int = 0
    status: str = "pending"  # pending/active/completed/error/canceled/rejected
    avg_speed_bps: float = 0.0
    error: Optional[str] = None


# ----------------------------
# Events from core/network to UI
# ----------------------------

@dataclass
class Event:
    type: str
    data: dict


# ----------------------------
# Core state + thread-safe API
# ----------------------------

class Core:
    def __init__(self) -> None:
        self._lock = threading.RLock()
        self.events: "queue.Queue[Event]" = queue.Queue()

        self.cfg = storage.load_config()
        self.peers: Dict[str, Peer] = {}

        # transfer_id -> per-peer progress (sender can have many receivers)
        self.transfers: Dict[str, Dict[str, TransferProgress]] = {}

        # config-based limits
        self.limits = self.cfg["limits"]

    # ----- config/profile -----

    def get_profile(self) -> dict:
        with self._lock:
            return dict(self.cfg["profile"])

    def set_username(self, username: str) -> None:
        with self._lock:
            self.cfg["profile"]["username"] = username.strip()
            storage.save_config(self.cfg)
        self.events.put(Event("profile_changed", {"profile": self.get_profile()}))

    def set_availability(self, availability: str) -> None:
        availability = availability.strip().lower()
        if availability not in ("available", "busy"):
            availability = "available"
        with self._lock:
            self.cfg["profile"]["availability"] = availability
            storage.save_config(self.cfg)
        self.events.put(Event("profile_changed", {"profile": self.get_profile()}))

    def set_download_dir(self, download_dir: str) -> None:
        with self._lock:
            self.cfg["profile"]["download_dir"] = download_dir
            storage.save_config(self.cfg)
        self.events.put(Event("profile_changed", {"profile": self.get_profile()}))

    def get_download_dir(self) -> str:
        with self._lock:
            return str(self.cfg["profile"]["download_dir"])

    # ----- peers -----

    def upsert_peer(self, peer_id: str, username: str, ip: str, tcp_port: int, availability: str) -> None:
        now = time.time()
        with self._lock:
            p = self.peers.get(peer_id)
            if p is None:
                self.peers[peer_id] = Peer(peer_id, username, ip, tcp_port, availability, last_seen=now)
                self.events.put(Event("peer_added", {"peer": self.peers[peer_id]}))
            else:
                changed = (p.username != username) or (p.availability != availability) or (p.tcp_port != tcp_port) or (p.ip != ip)
                p.username = username
                p.availability = availability
                p.tcp_port = tcp_port
                p.ip = ip
                p.last_seen = now
                if changed:
                    self.events.put(Event("peer_updated", {"peer": p}))

    def prune_peers(self) -> None:
        timeout = float(self.cfg["discovery"]["peer_timeout_sec"])
        now = time.time()
        removed: List[str] = []
        with self._lock:
            for peer_id, p in list(self.peers.items()):
                if now - p.last_seen > timeout:
                    removed.append(peer_id)
                    del self.peers[peer_id]
        for pid in removed:
            self.events.put(Event("peer_removed", {"peer_id": pid}))

    def list_peers(self) -> List[Peer]:
        with self._lock:
            return list(self.peers.values())

    # ----- transfers -----

    def new_transfer_id(self) -> str:
        return uuid.uuid4().hex

    def init_transfer(self, transfer_id: str, direction: str, peers: List[Tuple[str, str]], total_bytes: int) -> None:
        """
        peers: list of (peer_id, peer_name)
        """
        with self._lock:
            per_peer: Dict[str, TransferProgress] = {}
            for peer_id, peer_name in peers:
                per_peer[peer_id] = TransferProgress(
                    transfer_id=transfer_id,
                    direction=direction,
                    peer_id=peer_id,
                    peer_name=peer_name,
                    total_bytes=total_bytes,
                    done_bytes=0,
                    status="pending",
                )
            self.transfers[transfer_id] = per_peer
        self.events.put(Event("transfer_added", {"transfer_id": transfer_id, "items": per_peer}))

    def update_progress(self, transfer_id: str, peer_id: str, done_bytes: int, avg_speed_bps: float, status: Optional[str] = None, error: Optional[str] = None) -> None:
        with self._lock:
            t = self.transfers.get(transfer_id)
            if not t or peer_id not in t:
                return
            pr = t[peer_id]
            pr.done_bytes = done_bytes
            pr.avg_speed_bps = avg_speed_bps
            if status:
                pr.status = status
            if error:
                pr.error = error
        self.events.put(Event("transfer_progress", {"transfer_id": transfer_id, "peer_id": peer_id}))

    def finalize_transfer(self, transfer_id: str, direction: str, peer_names: List[str], file_count: int, total_bytes: int, status: str, avg_speed_bps: float, error: Optional[str] = None) -> None:
        # write history
        storage.record_transfer(
            transfer_id=transfer_id,
            direction=direction,
            peer_names=peer_names,
            file_count=file_count,
            total_bytes=total_bytes,
            status=status,
            avg_speed_bps=avg_speed_bps,
            error=error,
        )
        self.events.put(Event("history_updated", {}))

    def load_history(self) -> List[dict]:
        return storage.load_history()
