from __future__ import annotations

from pathlib import Path
from typing import Dict, List

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QProgressBar,
    QTabWidget,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
    QComboBox,
)

from ..backend.controller import BackendController
from ..backend.events import PeerInfo, TransferOffer, TransferProgress, TransferResult
from ..persistence.config_store import AppConfig, ConfigStore
from ..persistence.history_store import HistoryEntry, HistoryStore
from .event_bridge import EventBridge


class MainWindow(QMainWindow):
    def __init__(
        self,
        config_store: ConfigStore,
        history_store: HistoryStore,
        backend: BackendController,
        event_bridge: EventBridge,
    ) -> None:
        super().__init__()
        self.setWindowTitle("LAN Transfer")
        self.setMinimumSize(1100, 720)
        self.config_store = config_store
        self.history_store = history_store
        self.backend = backend
        self.bridge = event_bridge

        self.config = config_store.load()
        self.peers: Dict[str, PeerInfo] = {}
        self.selected_files: List[Path] = []
        self.transfer_bars: Dict[str, QProgressBar] = {}
        self.transfer_items: Dict[str, QListWidgetItem] = {}

        self._build_ui()
        self._wire_callbacks()

    def _build_ui(self) -> None:
        self.tabs = QTabWidget()
        self.setCentralWidget(self.tabs)

        # Simple modern theming
        self.setStyleSheet(
            """
            QWidget { font-family: 'Segoe UI'; font-size: 11pt; }
            QTabWidget::pane { border: 1px solid #d0d7de; border-radius: 10px; padding: 6px; }
            QTabBar::tab { background: #f6f8fa; border: 1px solid #d0d7de; padding: 10px 16px; border-radius: 8px; margin-right: 4px; }
            QTabBar::tab:selected { background: #e9eff5; }
            QPushButton { background: #0d6efd; color: white; border-radius: 8px; padding: 8px 14px; }
            QPushButton:hover { background: #0b5ed7; }
            QPushButton:pressed { background: #0a58ca; }
            QListWidget, QTableWidget, QLineEdit, QComboBox { border: 1px solid #d0d7de; border-radius: 6px; padding: 6px; }
            QProgressBar { border: 1px solid #d0d7de; border-radius: 6px; text-align: center; }
            QProgressBar::chunk { background-color: #16a34a; border-radius: 6px; }
            """
        )

        self.tabs.addTab(self._build_main_tab(), "Main")
        self.tabs.addTab(self._build_settings_tab(), "Settings")
        self.tabs.addTab(self._build_transfers_tab(), "Transfers")
        self.tabs.addTab(self._build_history_tab(), "History")

    def _build_main_tab(self) -> QWidget:
        container = QWidget()
        layout = QHBoxLayout(container)

        # Peers list
        peer_layout = QVBoxLayout()
        peer_layout.addWidget(QLabel("Available peers"))
        self.peer_list = QListWidget()
        self.peer_list.setSelectionMode(QListWidget.SelectionMode.MultiSelection)
        self.peer_list.itemDoubleClicked.connect(self._toggle_peer_selection)
        peer_layout.addWidget(self.peer_list)
        layout.addLayout(peer_layout)

        # File selection
        file_layout = QVBoxLayout()
        file_layout.addWidget(QLabel("Files to send"))
        self.file_list = QListWidget()
        self.file_list.setSelectionMode(QListWidget.SelectionMode.MultiSelection)
        self.file_list.itemDoubleClicked.connect(self._remove_file)
        file_layout.addWidget(self.file_list)

        btn_row = QHBoxLayout()
        add_btn = QPushButton("Add files")
        add_btn.clicked.connect(self._choose_files)
        send_btn = QPushButton("Send to selected peers")
        send_btn.clicked.connect(self._send_selected)
        btn_row.addWidget(add_btn)
        btn_row.addWidget(send_btn)
        file_layout.addLayout(btn_row)

        layout.addLayout(file_layout)
        return container

    def _build_settings_tab(self) -> QWidget:
        container = QWidget()
        layout = QVBoxLayout(container)

        self.username_edit = QLineEdit(self.config.username)
        self.status_combo = QComboBox()
        self.status_combo.addItems(["available", "busy"])
        self.status_combo.setCurrentText(self.config.status)
        self.download_edit = QLineEdit(str(self.config.download_dir))
        choose_btn = QPushButton("Choose download folder")
        choose_btn.clicked.connect(self._choose_download_dir)
        save_btn = QPushButton("Save settings")
        save_btn.clicked.connect(self._save_settings)

        layout.addWidget(QLabel("Username"))
        layout.addWidget(self.username_edit)
        layout.addWidget(QLabel("Status"))
        layout.addWidget(self.status_combo)
        layout.addWidget(QLabel("Download folder"))
        layout.addWidget(self.download_edit)
        layout.addWidget(choose_btn)
        layout.addWidget(save_btn)
        layout.addStretch()
        return container

    def _build_transfers_tab(self) -> QWidget:
        container = QWidget()
        layout = QVBoxLayout(container)
        self.transfer_list = QListWidget()
        layout.addWidget(QLabel("Active transfers"))
        layout.addWidget(self.transfer_list)
        return container

    def _build_history_tab(self) -> QWidget:
        container = QWidget()
        layout = QVBoxLayout(container)
        self.history_table = QTableWidget(0, 5)
        self.history_table.setHorizontalHeaderLabels(
            ["Filename", "Size", "Peer", "Direction", "Status"]
        )
        layout.addWidget(self.history_table)
        self._refresh_history_table()
        return container

    def _wire_callbacks(self) -> None:
        self.bridge.peer_discovered.connect(self._on_peer_discovered)
        self.bridge.peer_lost.connect(self._on_peer_lost)
        self.bridge.transfer_offer.connect(self._on_transfer_offer)
        self.bridge.transfer_progress.connect(self._on_transfer_progress)
        self.bridge.transfer_result.connect(self._on_transfer_result)

    # Event handlers
    def _on_peer_discovered(self, peer: PeerInfo) -> None:
        self.peers[peer.peer_id] = peer
        self._refresh_peer_list()

    def _on_peer_lost(self, peer_id: str) -> None:
        if peer_id in self.peers:
            self.peers.pop(peer_id)
            self._refresh_peer_list()

    def _on_transfer_offer(self, offer: TransferOffer) -> None:
        msg = QMessageBox(self)
        msg.setIcon(QMessageBox.Icon.Question)
        filenames = ", ".join([f.name for f in offer.files])
        msg.setText(f"{offer.peer.name} wants to send: {filenames}\nAccept?")
        msg.setStandardButtons(QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        choice = msg.exec()
        accept = choice == QMessageBox.StandardButton.Yes
        self.backend.respond_to_offer(offer.request_id, accept)

    def _on_transfer_progress(self, progress: TransferProgress) -> None:
        bar = self.transfer_bars.get(progress.transfer_id)
        if not bar:
            bar = QProgressBar()
            bar.setMaximum(progress.total_bytes)
            widget = self._make_transfer_widget(
                f"{progress.direction.capitalize()}: {progress.file.name} -> {progress.peer.name}", bar
            )
            item = QListWidgetItem()
            item.setSizeHint(widget.sizeHint())
            self.transfer_list.addItem(item)
            self.transfer_list.setItemWidget(item, widget)
            self.transfer_bars[progress.transfer_id] = bar
            self.transfer_items[progress.transfer_id] = item
        bar.setValue(progress.bytes_transferred)

    def _on_transfer_result(self, result: TransferResult) -> None:
        entry = HistoryEntry.create(
            filename=result.file.name,
            size=result.file.size,
            peer_name=result.peer.name,
            status=result.status,
            direction=result.direction,
            message=result.message,
        )
        self.history_store.append(entry)
        self._refresh_history_table()
        bar = self.transfer_bars.pop(result.transfer_id, None)
        item = self.transfer_items.pop(result.transfer_id, None)
        if item is not None:
            idx = self.transfer_list.row(item)
            if idx >= 0:
                self.transfer_list.takeItem(idx)

    # UI actions
    def _refresh_peer_list(self) -> None:
        self.peer_list.clear()
        for peer in self.peers.values():
            item = QListWidgetItem(f"{peer.name} ({peer.ip}) [{peer.status}]")
            item.setData(Qt.ItemDataRole.UserRole, peer.peer_id)
            self.peer_list.addItem(item)

    def _choose_files(self) -> None:
        files, _ = QFileDialog.getOpenFileNames(self, "Select files to send")
        for path in files:
            p = Path(path)
            if p not in self.selected_files:
                self.selected_files.append(p)
                self.file_list.addItem(str(p))

    def _toggle_peer_selection(self, item: QListWidgetItem) -> None:
        item.setSelected(not item.isSelected())

    def _remove_file(self, item: QListWidgetItem) -> None:
        path = Path(item.text())
        self.selected_files = [p for p in self.selected_files if p != path]
        row = self.file_list.row(item)
        self.file_list.takeItem(row)

    def _send_selected(self) -> None:
        selected_items = self.peer_list.selectedItems()
        if not selected_items or not self.selected_files:
            QMessageBox.information(self, "Select peers/files", "Pick peers and files first")
            return
        peer_ids = [i.data(Qt.ItemDataRole.UserRole) for i in selected_items]
        for pid in peer_ids:
            peer = self.peers.get(pid)
            if peer:
                self.backend.send_files(peer, self.selected_files)

    def _choose_download_dir(self) -> None:
        dir_path = QFileDialog.getExistingDirectory(self, "Choose download folder", str(self.config.download_dir))
        if dir_path:
            self.download_edit.setText(dir_path)

    def _save_settings(self) -> None:
        cfg = AppConfig(
            username=self.username_edit.text() or self.config.username,
            status=self.status_combo.currentText(),
            download_dir=Path(self.download_edit.text() or self.config.download_dir),
            udp_port=self.config.udp_port,
            tcp_port=self.config.tcp_port,
            broadcast_interval=self.config.broadcast_interval,
            max_concurrent_streams=self.config.max_concurrent_streams,
            max_file_size_bytes=self.config.max_file_size_bytes,
        )
        cfg.download_dir.mkdir(parents=True, exist_ok=True)
        self.config_store.save(cfg)
        self.config = cfg
        self.backend.refresh_config(cfg)

    def _refresh_history_table(self) -> None:
        entries = self.history_store.load()
        self.history_table.setRowCount(len(entries))
        for row, entry in enumerate(entries):
            self.history_table.setItem(row, 0, QTableWidgetItem(entry.get("filename", "")))
            self.history_table.setItem(row, 1, QTableWidgetItem(str(entry.get("size", ""))))
            self.history_table.setItem(row, 2, QTableWidgetItem(entry.get("peer_name", "")))
            self.history_table.setItem(row, 3, QTableWidgetItem(entry.get("direction", "")))
            self.history_table.setItem(row, 4, QTableWidgetItem(entry.get("status", "")))

    def _make_transfer_widget(self, label_text: str, bar: QProgressBar) -> QWidget:
        container = QWidget()
        v = QVBoxLayout(container)
        v.setContentsMargins(6, 6, 6, 6)
        v.setSpacing(4)
        label = QLabel(label_text)
        label.setStyleSheet("font-weight: 600;")
        bar.setTextVisible(True)
        v.addWidget(label)
        v.addWidget(bar)
        return container
