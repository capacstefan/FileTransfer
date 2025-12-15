from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, List, Optional


@dataclass(slots=True)
class PeerInfo:
    peer_id: str
    name: str
    ip: str
    status: str  # "available" or "busy"


@dataclass(slots=True)
class TransferFile:
    name: str
    size: int
    sha256: Optional[str] = None


@dataclass(slots=True)
class TransferOffer:
    peer: PeerInfo
    files: List[TransferFile]
    request_id: str


@dataclass(slots=True)
class TransferProgress:
    transfer_id: str
    peer: PeerInfo
    file: TransferFile
    bytes_transferred: int
    total_bytes: int
    speed_bps: float
    direction: str  # "send" or "receive"


@dataclass(slots=True)
class TransferResult:
    transfer_id: str
    peer: PeerInfo
    file: TransferFile
    status: str  # "completed", "error", "canceled"
    direction: str  # "send" or "receive"
    message: str = ""
    saved_path: Optional[Path] = None


@dataclass(slots=True)
class BackendCallbacks:
    on_peer_discovered: Callable[[PeerInfo], None] = field(default=lambda _: None)
    on_peer_lost: Callable[[str], None] = field(default=lambda _: None)
    on_transfer_offer: Callable[[TransferOffer], None] = field(default=lambda _: None)
    on_transfer_progress: Callable[[TransferProgress], None] = field(default=lambda _: None)
    on_transfer_result: Callable[[TransferResult], None] = field(default=lambda _: None)
