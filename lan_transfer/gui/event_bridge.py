from PyQt6.QtCore import QObject, pyqtSignal

from ..backend.events import BackendCallbacks, PeerInfo, TransferOffer, TransferProgress, TransferResult


class EventBridge(QObject):
    """Qt signal bridge so backend threads communicate with the GUI safely."""

    peer_discovered = pyqtSignal(object)  # PeerInfo
    peer_lost = pyqtSignal(str)  # peer id
    transfer_offer = pyqtSignal(object)  # TransferOffer
    transfer_progress = pyqtSignal(object)  # TransferProgress
    transfer_result = pyqtSignal(object)  # TransferResult

    def __init__(self) -> None:
        super().__init__()
        self.callbacks = BackendCallbacks(
            on_peer_discovered=self.peer_discovered.emit,
            on_peer_lost=self.peer_lost.emit,
            on_transfer_offer=self.transfer_offer.emit,
            on_transfer_progress=self.transfer_progress.emit,
            on_transfer_result=self.transfer_result.emit,
        )
