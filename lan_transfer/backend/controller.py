from __future__ import annotations

from pathlib import Path
from typing import Iterable

from .constants import BackendSettings
from .discovery import DiscoveryService
from .events import BackendCallbacks, PeerInfo
from .transfer import TransferService
from ..persistence.config_store import AppConfig
from ..persistence.paths import CERT_PATH, KEY_PATH


class BackendController:
    """Owns backend services and keeps UI-facing callbacks stable."""

    def __init__(self, callbacks: BackendCallbacks, app_config: AppConfig) -> None:
        self.callbacks = callbacks
        self.app_config = app_config
        self.settings = BackendSettings(
            udp_port=app_config.udp_port,
            tcp_port=app_config.tcp_port,
            broadcast_interval=app_config.broadcast_interval,
            max_concurrent_streams=app_config.max_concurrent_streams,
            max_file_size_bytes=app_config.max_file_size_bytes,
        )
        self.discovery = DiscoveryService(
            settings=self.settings,
            callbacks=callbacks,
            device_name=app_config.username,
            status=app_config.status,
        )
        self.transfer = TransferService(
            settings=self.settings,
            callbacks=callbacks,
            download_dir=app_config.download_dir,
            device_name=app_config.username,
            status=app_config.status,
            cert_path=CERT_PATH,
            key_path=KEY_PATH,
        )

    def start(self) -> None:
        self.discovery.start()
        self.transfer.start()

    def stop(self) -> None:
        self.discovery.stop()
        self.transfer.stop()

    def refresh_config(self, app_config: AppConfig) -> None:
        self.app_config = app_config
        self.discovery.status = app_config.status
        self.discovery.device_name = app_config.username
        self.transfer.download_dir = app_config.download_dir
        self.transfer.status = app_config.status
        self.transfer.device_name = app_config.username

    def send_files(self, peer: PeerInfo, files: Iterable[Path]) -> str:
        return self.transfer.send_files(peer, files)

    def respond_to_offer(self, request_id: str, accept: bool) -> None:
        self.transfer.respond_to_offer(request_id, accept)
