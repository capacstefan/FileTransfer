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
    QCheckBox,
    QHeaderView,
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
        self.setMinimumSize(800, 400)

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

    # ---------------------------------------------------------------- UI

    def _build_ui(self) -> None:
        self.tabs = QTabWidget()
        self.setCentralWidget(self.tabs)

        # Futuristic minimalist theme
        self.setStyleSheet(
            """
            QWidget {
                background-color: #0f1115;
                color: #d1d5db;
                font-family: "Inter", "Segoe UI", sans-serif;
                font-size: 10.5pt;
            }

            QLabel { color: #9ca3af; }

            QTabWidget::pane {
                border: 1px solid #1f2933;
                background: #0f1115;
            }

            QTabBar::tab {
                background: #151821;
                border: 1px solid #1f2933;
                padding: 8px 14px;
                margin-right: 4px;
            }

            QTabBar::tab:selected {
                background: #1a1f2b;
                border-bottom: 2px solid #3b82f6;
            }

            QPushButton {
                background: #1a1f2b;
                border: 1px solid #1f2933;
                padding: 6px 12px;
                border-radius: 6px;
            }

            QPushButton:hover { background: #202634; }

            QLineEdit, QListWidget, QTableWidget {
                background: #151821;
                border: 1px solid #1f2933;
                padding: 6px;
            }

            QListWidget::item:selected {
                background: #1f2933;
            }

            QProgressBar {
                background: #151821;
                border: 1px solid #1f2933;
                height: 14px;
            }

            QProgressBar::chunk {
                background: #22c55e;
            }

            QCheckBox::indicator {
                width: 36px;
                height: 18px;
                border-radius: 9px;
                background: #1f2933;
            }

            QCheckBox::indicator:checked {
                background: #3b82f6;
            }
            """
        )

        self.tabs.addTab(self._build_main_tab(), "Main")
        self.tabs.addTab(self._build_settings_tab(), "Settings")
        self.tabs.addTab(self._build_transfers_tab(), "Transfers")
        self.tabs.addTab(self._build_history_tab(), "History")

    # ---------------------------------------------------------------- Tabs

    def _build_main_tab(self) -> QWidget:
        container = QWidget()
        layout = QHBoxLayout(container)
        layout.setSpacing(10)
        layout.setContentsMargins(10, 10, 10, 10)

        # Peers
        peer_layout = QVBoxLayout()
        peer_layout.addWidget(QLabel("Peers"))
        self.peer_list = QListWidget()
        self.peer_list.setSelectionMode(QListWidget.SelectionMode.MultiSelection)
        self.peer_list.itemDoubleClicked.connect(self._toggle_peer_selection)
        peer_layout.addWidget(self.peer_list)

        # Files
        file_layout = QVBoxLayout()
        file_layout.addWidget(QLabel("Files"))
        self.file_list = QListWidget()
        self.file_list.itemDoubleClicked.connect(self._remove_file)
        file_layout.addWidget(self.file_list)

        btns = QHBoxLayout()
        add_btn = QPushButton("Add")
        add_btn.clicked.connect(self._choose_files)
        send_btn = QPushButton("Send")
        send_btn.clicked.connect(self._send_selected)
        btns.addWidget(add_btn)
        btns.addWidget(send_btn)
        file_layout.addLayout(btns)

        layout.addLayout(peer_layout, 1)
        layout.addLayout(file_layout, 1)
        return container

    def _build_settings_tab(self) -> QWidget:
        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setSpacing(8)
        layout.setContentsMargins(14, 14, 14, 14)
        

        self.username_edit = QLineEdit(self.config.username)

        self.status_toggle = QCheckBox()
        self.status_toggle.setChecked(self.config.status == "available")
        self._update_status_toggle_label()
        self.status_toggle.stateChanged.connect(self._update_status_toggle_label)

        self.download_edit = QLineEdit(str(self.config.download_dir))

        choose_btn = QPushButton("Browse")
        choose_btn.clicked.connect(self._choose_download_dir)

        save_btn = QPushButton("Save")
        save_btn.clicked.connect(self._save_settings)

        layout.addWidget(QLabel("Username"))
        layout.addWidget(self.username_edit)
        layout.addWidget(self.status_toggle)
        layout.addWidget(QLabel("Download folder"))
        layout.addWidget(self.download_edit)
        layout.addWidget(choose_btn)
        layout.addWidget(save_btn)
        layout.addStretch()

        return container

    def _build_transfers_tab(self) -> QWidget:
        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(10, 10, 10, 10)
        self.transfer_list = QListWidget()
        layout.addWidget(self.transfer_list)
        return container

    def _build_history_tab(self) -> QWidget:
        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(10, 10, 10, 10)

        self.history_table = QTableWidget(0, 5)
        self.history_table.setHorizontalHeaderLabels(
            ["Filename", "Size", "Peer", "Direction", "Status"]
        )

        # --- Behavior (presentation-only) ---
        self.history_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.history_table.verticalHeader().setVisible(False)
        self.history_table.setShowGrid(False)

        # --- Column sizing ---
        header = self.history_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)          # Filename
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)          # Peer
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents) # Size
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents) # Direction
        header.setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents) # Status

        # Keep status compact
        self.history_table.setColumnWidth(4, 90)

        layout.addWidget(self.history_table)

        self._refresh_history_table()
        return container

    # ---------------------------------------------------------------- Helpers

    def _update_status_toggle_label(self) -> None:
        self.status_toggle.setText(
            "Available" if self.status_toggle.isChecked() else "Busy"
        )

    def _toggle_peer_selection(self, item: QListWidgetItem) -> None:
        item.setSelected(not item.isSelected())

    # ---------------------------------------------------------------- Wiring

    def _wire_callbacks(self) -> None:
        self.bridge.peer_discovered.connect(self._on_peer_discovered)
        self.bridge.peer_lost.connect(self._on_peer_lost)
        self.bridge.transfer_offer.connect(self._on_transfer_offer)
        self.bridge.transfer_progress.connect(self._on_transfer_progress)
        self.bridge.transfer_result.connect(self._on_transfer_result)

    # ---------------------------------------------------------------- Events

    def _on_peer_discovered(self, peer: PeerInfo) -> None:
        self.peers[peer.peer_id] = peer
        self._refresh_peer_list()

    def _on_peer_lost(self, peer_id: str) -> None:
        self.peers.pop(peer_id, None)
        self._refresh_peer_list()

    def _on_transfer_offer(self, offer: TransferOffer) -> None:
        msg = QMessageBox(self)
        msg.setText(f"{offer.peer.name} wants to send files. Accept?")
        msg.setStandardButtons(QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        self.backend.respond_to_offer(
            offer.request_id, msg.exec() == QMessageBox.StandardButton.Yes
        )

    def _on_transfer_progress(self, progress: TransferProgress) -> None:
        bar = self.transfer_bars.get(progress.transfer_id)
        if not bar:
            bar = QProgressBar()
            bar.setMaximum(progress.total_bytes)
            widget = self._make_transfer_widget(progress.file.name, bar)
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

        self.transfer_bars.pop(result.transfer_id, None)
        item = self.transfer_items.pop(result.transfer_id, None)
        if item:
            self.transfer_list.takeItem(self.transfer_list.row(item))

    # ---------------------------------------------------------------- Actions

    def _refresh_peer_list(self) -> None:
        self.peer_list.clear()
        for peer in self.peers.values():
            icon = "🟢" if peer.status == "available" else "🔴"
            item = QListWidgetItem(f"{icon} {peer.name} ({peer.ip})")
            item.setData(Qt.ItemDataRole.UserRole, peer.peer_id)
            self.peer_list.addItem(item)

    def _choose_files(self) -> None:
        files, _ = QFileDialog.getOpenFileNames(self, "Select files")
        for path in files:
            p = Path(path)
            if p not in self.selected_files:
                self.selected_files.append(p)
                self.file_list.addItem(str(p))

    def _remove_file(self, item: QListWidgetItem) -> None:
        path = Path(item.text())
        self.selected_files = [p for p in self.selected_files if p != path]
        self.file_list.takeItem(self.file_list.row(item))

    def _send_selected(self) -> None:
        peers = self.peer_list.selectedItems()
        if not peers or not self.selected_files:
            QMessageBox.information(self, "Missing selection", "Select peers and files first")
            return
        for item in peers:
            peer = self.peers.get(item.data(Qt.ItemDataRole.UserRole))
            if peer:
                self.backend.send_files(peer, self.selected_files)

    def _choose_download_dir(self) -> None:
        path = QFileDialog.getExistingDirectory(self, "Download folder")
        if path:
            self.download_edit.setText(path)

    def _save_settings(self) -> None:
        status = "available" if self.status_toggle.isChecked() else "busy"
        cfg = AppConfig(
            username=self.username_edit.text() or self.config.username,
            status=status,
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
            self.history_table.setItem(row, 0, QTableWidgetItem(entry["filename"]))
            self.history_table.setItem(row, 1, QTableWidgetItem(str(entry["size"])))
            self.history_table.setItem(row, 2, QTableWidgetItem(entry["peer_name"]))
            self.history_table.setItem(row, 3, QTableWidgetItem(entry["direction"]))

            status_item = QTableWidgetItem(entry["status"])
            status_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            self.history_table.setItem(row, 4, status_item)

    def _make_transfer_widget(self, name: str, bar: QProgressBar) -> QWidget:
        w = QWidget()
        l = QVBoxLayout(w)
        l.setContentsMargins(4, 4, 4, 4)
        l.addWidget(QLabel(name))
        l.addWidget(bar)
        return w
