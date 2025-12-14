"""
Core module - Application state management
Completely separated from UI for clean architecture
Designed for future C/C++ integration
"""
from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from threading import RLock
from typing import Dict, List, Optional, Callable, Any

from storage import get_config, get_history, TransferRecord


# ============================================================
# Enums
# ============================================================

class Availability(str, Enum):
    AVAILABLE = "available"
    BUSY = "busy"


class TransferStatus(str, Enum):
    PENDING = "pending"
    CONNECTING = "connecting"
    TRANSFERRING = "transferring"
    COMPLETED = "completed"
    ERROR = "error"
    CANCELED = "canceled"
    REJECTED = "rejected"


class TransferDirection(str, Enum):
    SEND = "send"
    RECEIVE = "receive"


# ============================================================
# Data Classes
# ============================================================

@dataclass
class Peer:
    """Discovered peer on the network"""
    peer_id: str          # Unique: username@ip:port
    username: str
    ip: str
    port: int
    availability: Availability
    last_seen: float = field(default_factory=time.time)
    
    @property
    def is_available(self) -> bool:
        return self.availability == Availability.AVAILABLE
    
    @property
    def display_name(self) -> str:
        return f"{self.username} ({self.ip})"


@dataclass
class FileInfo:
    """File to be transferred"""
    name: str
    path: str
    size: int
    sha256: str = ""


@dataclass
class TransferProgress:
    """Progress of a single transfer"""
    transfer_id: str
    direction: TransferDirection
    peer_id: str
    peer_name: str
    files: List[FileInfo]
    total_bytes: int
    transferred_bytes: int = 0
    current_file_index: int = 0
    status: TransferStatus = TransferStatus.PENDING
    error_msg: str = ""
    start_time: float = 0.0
    end_time: float = 0.0
    
    @property
    def progress_percent(self) -> float:
        if self.total_bytes == 0:
            return 0.0
        return min(100.0, (self.transferred_bytes / self.total_bytes) * 100)
    
    @property
    def speed_mbps(self) -> float:
        if self.start_time == 0:
            return 0.0
        elapsed = (self.end_time or time.time()) - self.start_time
        if elapsed <= 0:
            return 0.0
        return (self.transferred_bytes / (1024 * 1024)) / elapsed
    
    @property
    def elapsed_seconds(self) -> float:
        if self.start_time == 0:
            return 0.0
        return (self.end_time or time.time()) - self.start_time


# ============================================================
# Event System (for UI notifications)
# ============================================================

class EventType(str, Enum):
    PEER_DISCOVERED = "peer_discovered"
    PEER_LOST = "peer_lost"
    PEER_UPDATED = "peer_updated"
    TRANSFER_STARTED = "transfer_started"
    TRANSFER_PROGRESS = "transfer_progress"
    TRANSFER_COMPLETED = "transfer_completed"
    TRANSFER_ERROR = "transfer_error"
    INCOMING_OFFER = "incoming_offer"


@dataclass
class Event:
    """Event for UI notification"""
    event_type: EventType
    data: Any = None


# ============================================================
# Core State Manager
# ============================================================

class Core:
    """
    Central state manager - the heart of the application.
    Thread-safe, separated from UI.
    """
    
    def __init__(self):
        self._lock = RLock()
        self.cfg = get_config()
        self.history = get_history()
        
        # Peers on network
        self._peers: Dict[str, Peer] = {}
        
        # Active transfers
        self._transfers: Dict[str, TransferProgress] = {}
        
        # Selected files for sending
        self._selected_files: List[str] = []
        
        # Event listeners (UI registers here)
        self._listeners: List[Callable[[Event], None]] = []
    
    # -------------------- Profile --------------------
    
    def get_profile(self) -> dict:
        """Get current profile settings"""
        return {
            "username": self.cfg.get("profile", "username"),
            "availability": self.cfg.get("profile", "availability"),
            "download_dir": self.cfg.get("profile", "download_dir"),
        }
    
    def set_username(self, name: str) -> None:
        """Change username"""
        name = name.strip()[:32] or "FIshare"
        self.cfg.set("profile", "username", name)
    
    def set_availability(self, avail: Availability) -> None:
        """Change availability status"""
        self.cfg.set("profile", "availability", avail.value)
    
    def toggle_availability(self) -> Availability:
        """Toggle between available and busy"""
        current = self.cfg.get("profile", "availability")
        new_avail = Availability.BUSY if current == "available" else Availability.AVAILABLE
        self.set_availability(new_avail)
        return new_avail
    
    def set_download_dir(self, path: str) -> None:
        """Change download directory"""
        self.cfg.set("profile", "download_dir", path)
    
    def get_download_dir(self) -> str:
        return self.cfg.get("profile", "download_dir")
    
    def is_busy(self) -> bool:
        return self.cfg.get("profile", "availability") == "busy"
    
    # -------------------- Peers --------------------
    
    def upsert_peer(self, peer_id: str, username: str, ip: str, port: int, availability: str) -> None:
        """Add or update a peer"""
        with self._lock:
            avail = Availability.AVAILABLE if availability == "available" else Availability.BUSY
            
            # If the device changed username but keeps the same ip:port, reuse the same entry
            existing_id = None
            for pid, p in self._peers.items():
                if p.ip == ip and p.port == port:
                    existing_id = pid
                    break

            if existing_id and existing_id != peer_id:
                peer = self._peers.pop(existing_id)
                peer.peer_id = peer_id
                peer.username = username
                peer.availability = avail
                peer.last_seen = time.time()
                self._peers[peer_id] = peer
                self._emit(Event(EventType.PEER_UPDATED, peer))
            elif peer_id in self._peers:
                peer = self._peers[peer_id]
                peer.username = username
                peer.availability = avail
                peer.last_seen = time.time()
                self._emit(Event(EventType.PEER_UPDATED, peer))
            else:
                peer = Peer(
                    peer_id=peer_id,
                    username=username,
                    ip=ip,
                    port=port,
                    availability=avail,
                    last_seen=time.time()
                )
                self._peers[peer_id] = peer
                self._emit(Event(EventType.PEER_DISCOVERED, peer))
    
    def remove_peer(self, peer_id: str) -> None:
        """Remove a peer"""
        with self._lock:
            if peer_id in self._peers:
                peer = self._peers.pop(peer_id)
                self._emit(Event(EventType.PEER_LOST, peer))
    
    def get_peer(self, peer_id: str) -> Optional[Peer]:
        """Get a specific peer"""
        with self._lock:
            return self._peers.get(peer_id)
    
    def list_peers(self) -> List[Peer]:
        """Get all peers"""
        with self._lock:
            return list(self._peers.values())
    
    def prune_stale_peers(self, timeout_sec: float = 6.0) -> None:
        """Remove peers not seen recently"""
        with self._lock:
            now = time.time()
            stale = [pid for pid, p in self._peers.items() 
                     if now - p.last_seen > timeout_sec]
            for pid in stale:
                self.remove_peer(pid)
    
    # -------------------- File Selection --------------------
    
    def set_selected_files(self, paths: List[str]) -> None:
        """Set files to send"""
        with self._lock:
            self._selected_files = list(paths)
    
    def get_selected_files(self) -> List[str]:
        """Get selected files"""
        with self._lock:
            return list(self._selected_files)
    
    def clear_selected_files(self) -> None:
        """Clear file selection"""
        with self._lock:
            self._selected_files = []
    
    def remove_selected_file(self, path: str) -> None:
        """Remove a single file from selection"""
        with self._lock:
            if path in self._selected_files:
                self._selected_files.remove(path)
    
    # -------------------- Transfers --------------------
    
    def create_transfer(
        self,
        direction: TransferDirection,
        peer_id: str,
        peer_name: str,
        files: List[FileInfo],
        total_bytes: int
    ) -> str:
        """Create a new transfer and return its ID"""
        with self._lock:
            transfer_id = str(uuid.uuid4())[:8]
            transfer = TransferProgress(
                transfer_id=transfer_id,
                direction=direction,
                peer_id=peer_id,
                peer_name=peer_name,
                files=files,
                total_bytes=total_bytes,
                status=TransferStatus.PENDING,
            )
            self._transfers[transfer_id] = transfer
            self._emit(Event(EventType.TRANSFER_STARTED, transfer))
            return transfer_id
    
    def update_transfer(
        self,
        transfer_id: str,
        transferred_bytes: Optional[int] = None,
        current_file_index: Optional[int] = None,
        status: Optional[TransferStatus] = None,
        error_msg: Optional[str] = None,
    ) -> None:
        """Update transfer progress"""
        with self._lock:
            transfer = self._transfers.get(transfer_id)
            if not transfer:
                return
            
            if transferred_bytes is not None:
                transfer.transferred_bytes = transferred_bytes
            if current_file_index is not None:
                transfer.current_file_index = current_file_index
            if status is not None:
                transfer.status = status
                if status == TransferStatus.TRANSFERRING and transfer.start_time == 0:
                    transfer.start_time = time.time()
                elif status in (TransferStatus.COMPLETED, TransferStatus.ERROR, TransferStatus.CANCELED):
                    transfer.end_time = time.time()
            if error_msg is not None:
                transfer.error_msg = error_msg
            
            self._emit(Event(EventType.TRANSFER_PROGRESS, transfer))
    
    def complete_transfer(self, transfer_id: str, status: TransferStatus, error_msg: str = "") -> None:
        """Mark transfer as completed and save to history"""
        with self._lock:
            transfer = self._transfers.get(transfer_id)
            if not transfer:
                return
            
            transfer.status = status
            transfer.error_msg = error_msg
            transfer.end_time = time.time()
            
            # Get peer info
            peer = self.get_peer(transfer.peer_id)
            peer_host = peer.ip if peer else "unknown"
            
            # Save to history
            record = TransferRecord(
                transfer_id=transfer_id,
                timestamp=transfer.start_time or time.time(),
                direction=transfer.direction.value,
                peer_name=transfer.peer_name,
                peer_host=peer_host,
                num_files=len(transfer.files),
                total_bytes=transfer.total_bytes,
                duration_sec=transfer.elapsed_seconds,
                status=status.value,
                error_msg=error_msg if error_msg else None,
                avg_speed_mbps=transfer.speed_mbps,
            )
            self.history.add(record)
            
            if status == TransferStatus.COMPLETED:
                self._emit(Event(EventType.TRANSFER_COMPLETED, transfer))
            else:
                self._emit(Event(EventType.TRANSFER_ERROR, transfer))
    
    def get_transfer(self, transfer_id: str) -> Optional[TransferProgress]:
        """Get a specific transfer"""
        with self._lock:
            return self._transfers.get(transfer_id)
    
    def list_active_transfers(self) -> List[TransferProgress]:
        """Get all active (non-completed) transfers"""
        with self._lock:
            return [t for t in self._transfers.values() 
                    if t.status in (TransferStatus.PENDING, TransferStatus.CONNECTING, TransferStatus.TRANSFERRING)]
    
    def list_all_transfers(self) -> List[TransferProgress]:
        """Get all transfers"""
        with self._lock:
            return list(self._transfers.values())
    
    def remove_transfer(self, transfer_id: str) -> None:
        """Remove a transfer from active list"""
        with self._lock:
            self._transfers.pop(transfer_id, None)
    
    # -------------------- Events --------------------
    
    def add_listener(self, callback: Callable[[Event], None]) -> None:
        """Register event listener"""
        with self._lock:
            self._listeners.append(callback)
    
    def remove_listener(self, callback: Callable[[Event], None]) -> None:
        """Unregister event listener"""
        with self._lock:
            if callback in self._listeners:
                self._listeners.remove(callback)
    
    def _emit(self, event: Event) -> None:
        """Emit event to all listeners"""
        with self._lock:
            listeners = list(self._listeners)
        for listener in listeners:
            try:
                listener(event)
            except Exception:
                pass
