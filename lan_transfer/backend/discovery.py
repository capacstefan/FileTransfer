from __future__ import annotations

import socket
import threading
import time
from typing import Optional

from .constants import BackendSettings
from .events import BackendCallbacks, PeerInfo


class DiscoveryService:
    """UDP broadcast discovery (skeleton).

    Sends periodic beacons and listens for peers. Real transfer logic can be
    swapped later while keeping the callbacks stable.
    """

    def __init__(
        self,
        settings: BackendSettings,
        callbacks: BackendCallbacks,
        device_name: str,
        status: str,
    ) -> None:
        self.settings = settings
        self.callbacks = callbacks
        self.device_name = device_name
        self.status = status
        self._broadcast_thread: Optional[threading.Thread] = None
        self._listen_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()

    def start(self) -> None:
        self._stop_event.clear()
        self._broadcast_thread = threading.Thread(target=self._broadcast_loop, daemon=True)
        self._listen_thread = threading.Thread(target=self._listen_loop, daemon=True)
        self._broadcast_thread.start()
        self._listen_thread.start()

    def stop(self) -> None:
        self._stop_event.set()

    def _broadcast_loop(self) -> None:
        while not self._stop_event.is_set():
            payload = f"LAN_XFER|{self.device_name}|{self.status}".encode()
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP) as s:
                    s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
                    s.settimeout(1.0)
                    s.sendto(payload, ("255.255.255.255", self.settings.udp_port))
            except OSError:
                pass
            time.sleep(self.settings.broadcast_interval)

    def _listen_loop(self) -> None:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(("", self.settings.udp_port))
            s.settimeout(1.0)
            while not self._stop_event.is_set():
                try:
                    data, addr = s.recvfrom(4096)
                except socket.timeout:
                    continue
                except OSError:
                    break
                try:
                    decoded = data.decode(errors="ignore")
                    parts = decoded.split("|")
                    if len(parts) != 3 or parts[0] != "LAN_XFER":
                        continue
                    name, status = parts[1], parts[2]
                    peer = PeerInfo(peer_id=addr[0], name=name, ip=addr[0], status=status)
                    self.callbacks.on_peer_discovered(peer)
                except Exception:
                    continue

    @property
    def is_running(self) -> bool:
        return bool(self._broadcast_thread and self._broadcast_thread.is_alive())
