from __future__ import annotations

import os
import socket
from typing import Dict, Set

from PyQt6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QLineEdit, QPushButton, QListWidget, QListWidgetItem,
    QFileDialog, QMessageBox, QTabWidget, QProgressBar, QTableWidget,
    QTableWidgetItem, QHeaderView, QAbstractItemView
)
from PyQt6.QtCore import Qt, QTimer

from state import AppStatus, TransferStatus, Device


def _local_ips() -> Set[str]:
    ips: Set[str] = set()
    try:
        hostname = socket.gethostname()
        try:
            ips.add(socket.gethostbyname(hostname))
        except Exception:
            pass
        try:
            for info in socket.getaddrinfo(hostname, None):
                ips.add(info[4][0])
        except Exception:
            pass
    except Exception:
        pass
    ips.discard("127.0.0.1")
    ips.discard("::1")
    return ips


class FIshareQtApp(QMainWindow):
    """
    UI simplificat (mai puține linii, mai puține stiluri),
    dar păstrează:
      - multi-select peers
      - send_to_multiple()
      - incoming accept dialog
      - history + monitor basic
    """

    def __init__(self, state, advertiser, scanner, history, transfer):
        super().__init__()
        self.state = state
        self.advertiser = advertiser  # Discovery
        self.scanner = scanner        # Discovery (unused but kept)
        self.history = history
        self.transfer = transfer

        self.setWindowTitle("FIshare")
        self.resize(900, 600)

        self._known_items: Dict[str, QListWidgetItem] = {}
        self._self_ips = _local_ips()

        self.tabs = QTabWidget()
        self.tabs.addTab(self._tab_transfer(), "Transfer")
        self.tabs.addTab(self._tab_settings(), "Settings")
        self.tabs.addTab(self._tab_history(), "History")
        self.tabs.addTab(self._tab_monitor(), "Monitor")
        self.setCentralWidget(self.tabs)

        self.timer = QTimer(self)
        self.timer.timeout.connect(self._tick_ui)
        self.timer.start(800)  # ✅ not too aggressive

    # ----------------------------
    # Tabs
    # ----------------------------

    def _tab_transfer(self) -> QWidget:
        w = QWidget()
        root = QVBoxLayout(w)

        # Devices
        root.addWidget(QLabel("Devices on network (Ctrl/Shift for multi-select):"))
        self.devices = QListWidget()
        self.devices.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        root.addWidget(self.devices)

        # Files
        row = QHBoxLayout()
        self.btn_add_files = QPushButton("Add files")
        self.btn_add_files.clicked.connect(self._pick_files)
        row.addWidget(self.btn_add_files)

        self.btn_clear_files = QPushButton("Clear files")
        self.btn_clear_files.clicked.connect(self._clear_files)
        row.addWidget(self.btn_clear_files)

        row.addStretch()
        root.addLayout(row)

        self.files = QListWidget()
        root.addWidget(self.files)

        # Progress + Send
        self.progress = QProgressBar()
        self.progress.setRange(0, 100)
        root.addWidget(self.progress)

        self.btn_send = QPushButton("Send")
        self.btn_send.clicked.connect(self._send)
        root.addWidget(self.btn_send)

        return w

    def _tab_settings(self) -> QWidget:
        w = QWidget()
        root = QVBoxLayout(w)

        # Name
        root.addWidget(QLabel("Device name:"))
        self.name_edit = QLineEdit(self.state.cfg.device_name)
        self.name_edit.textChanged.connect(self._on_name)
        root.addWidget(self.name_edit)

        # Status
        self.status_btn = QPushButton()
        self.status_btn.clicked.connect(self._toggle_status)
        root.addWidget(self.status_btn)
        self._update_status_btn()

        # Download dir
        root.addWidget(QLabel("Download folder:"))
        self.download_label = QLabel(self.state.cfg.download_dir)
        self.download_label.setWordWrap(True)
        root.addWidget(self.download_label)

        self.btn_download = QPushButton("Change download folder")
        self.btn_download.clicked.connect(self._change_download_folder)
        root.addWidget(self.btn_download)

        root.addStretch()
        return w

    def _tab_history(self) -> QWidget:
        w = QWidget()
        root = QVBoxLayout(w)

        top = QHBoxLayout()
        top.addWidget(QLabel("Transfer history:"))
        top.addStretch()

        self.btn_clear_history = QPushButton("Clear all")
        self.btn_clear_history.clicked.connect(self._on_clear_history)
        top.addWidget(self.btn_clear_history)
        root.addLayout(top)

        self.history_table = QTableWidget()
        self.history_table.setColumnCount(8)
        self.history_table.setHorizontalHeaderLabels([
            "Date", "Dir", "Peer", "Files", "Size", "Speed", "Status", "SHA"
        ])
        header = self.history_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(5, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(6, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(7, QHeaderView.ResizeMode.ResizeToContents)

        self.history_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.history_table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self.history_table.itemDoubleClicked.connect(self._on_history_double_click)

        root.addWidget(self.history_table)
        self._refresh_history()
        return w

    def _tab_monitor(self) -> QWidget:
        w = QWidget()
        root = QVBoxLayout(w)

        self.monitor_label = QLabel("No active transfers.")
        self.monitor_label.setWordWrap(True)
        root.addWidget(self.monitor_label)

        root.addStretch()
        return w

    # ----------------------------
    # Incoming prompt (used by TransferService)
    # ----------------------------

    def ask_incoming(self, peer_name: str, num_files: int, size: int) -> bool:
        mb = size / (1024 * 1024)
        msg = f"{peer_name} wants to send {num_files} file(s)\nSize: {mb:.2f} MB\nAccept?"
        rep = QMessageBox.question(
            self, "Incoming Transfer", msg,
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        return rep == QMessageBox.StandardButton.Yes

    # ----------------------------
    # Actions
    # ----------------------------

    def _on_name(self, text: str):
        self.state.cfg.device_name = text.strip()[:32]
        self.state.cfg.save()
        # Discovery sender reads current values live => will propagate

    def _toggle_status(self):
        if self.state.status == AppStatus.AVAILABLE:
            self.state.set_status(AppStatus.BUSY)
            self.state.cfg.allow_incoming = False
        else:
            self.state.set_status(AppStatus.AVAILABLE)
            self.state.cfg.allow_incoming = True
        self.state.cfg.save()
        self._update_status_btn()

    def _update_status_btn(self):
        if self.state.status == AppStatus.AVAILABLE:
            self.status_btn.setText("Available (accept incoming)")
        else:
            self.status_btn.setText("Busy (reject incoming)")

    def _pick_files(self):
        f, _ = QFileDialog.getOpenFileNames(self, "Select Files")
        if f:
            self.state.selected_files = list(f)

    def _clear_files(self):
        self.state.selected_files = []

    def _send(self):
        if not self.state.selected_files:
            QMessageBox.warning(self, "No files", "Select files first.")
            return

        selected_items = self.devices.selectedItems()
        if not selected_items:
            QMessageBox.warning(self, "No device", "Select at least one device.")
            return

        selected_devices = []
        for item in selected_items:
            dev_id = item.data(Qt.ItemDataRole.UserRole)
            dev = self.state.devices.get(dev_id)
            if dev:
                selected_devices.append(dev)

        if not selected_devices:
            QMessageBox.warning(self, "Invalid", "No valid devices selected.")
            return

        self.transfer.send_to_multiple(selected_devices, self.state.selected_files)

        QMessageBox.information(
            self, "Started",
            f"Transfer started to {len(selected_devices)} device(s)."
        )

    def _change_download_folder(self):
        folder = QFileDialog.getExistingDirectory(self, "Select Download Folder", self.state.cfg.download_dir)
        if folder:
            self.state.cfg.download_dir = folder
            self.state.cfg.save()
            self.download_label.setText(folder)

    # ----------------------------
    # Periodic UI refresh (NO GLITCH)
    # ----------------------------

    def _tick_ui(self):
        # prune dead devices
        try:
            self.state.prune_devices()
        except Exception:
            pass

        self._refresh_devices_incremental()
        self._refresh_files()
        self._refresh_progress()
        self._refresh_history()
        self._refresh_monitor()

    def _refresh_devices_incremental(self):
        # ✅ IMPORTANT: DO NOT clear() -> preserves selection
        # Remove stale items
        alive_ids = set(self.state.devices.keys())
        for dev_id in list(self._known_items.keys()):
            if dev_id not in alive_ids:
                item = self._known_items.pop(dev_id)
                row = self.devices.row(item)
                if row >= 0:
                    self.devices.takeItem(row)

        # Upsert new/updated items
        for dev in self.state.devices.values():
            # Skip self (no disabled/unselectable glitchy items)
            if dev.host in self._self_ips or dev.device_id in self._self_ips:
                continue
            if dev.name == self.state.cfg.device_name:
                continue

            text = f"{'🟢' if dev.status == AppStatus.AVAILABLE else '🔴'} {dev.name} ({dev.host})"
            item = self._known_items.get(dev.device_id)

            if item is None:
                item = QListWidgetItem(text)
                item.setData(Qt.ItemDataRole.UserRole, dev.device_id)
                self.devices.addItem(item)
                self._known_items[dev.device_id] = item
            else:
                if item.text() != text:
                    item.setText(text)

            # Optional: make BUSY devices visibly non-selectable (but still visible)
            if dev.status == AppStatus.BUSY:
                item.setFlags(Qt.ItemFlag.ItemIsEnabled)  # not selectable
            else:
                item.setFlags(Qt.ItemFlag.ItemIsEnabled | Qt.ItemFlag.ItemIsSelectable)

    def _refresh_files(self):
        # simple refresh (small list, safe)
        self.files.clear()
        for f in self.state.selected_files:
            self.files.addItem(os.path.basename(f))

    def _refresh_progress(self):
        # Show overall progress: average of running transfers (if any)
        vals = []
        for dev_id, st in self.state.transfer_status.items():
            if st == TransferStatus.RUNNING:
                vals.append(self.state.get_progress(dev_id))

        if not vals:
            self.progress.setValue(0)
            return

        avg = sum(vals) / max(1, len(vals))
        self.progress.setValue(int(avg * 100))

    def _refresh_history(self):
        records = self.history.get_all()
        self.history_table.setRowCount(len(records))

        for row, record in enumerate(records):
            self.history_table.setItem(row, 0, QTableWidgetItem(record.timestamp_str))
            self.history_table.setItem(row, 1, QTableWidgetItem("sent" if record.direction == "sent" else "recv"))
            self.history_table.setItem(row, 2, QTableWidgetItem(f"{record.peer_name} ({record.peer_host})"))
            self.history_table.setItem(row, 3, QTableWidgetItem(str(record.num_files)))
            self.history_table.setItem(row, 4, QTableWidgetItem(self._format_size(record.total_size)))
            self.history_table.setItem(row, 5, QTableWidgetItem(f"{record.speed_mbps:.2f} MB/s" if record.status == "completed" else "—"))
            self.history_table.setItem(row, 6, QTableWidgetItem(record.status))
            self.history_table.setItem(row, 7, QTableWidgetItem("✓" if record.sha256_ok else ("✗" if record.sha256_ok is False else "n/a")))

    def _refresh_monitor(self):
        # Minimal monitor summary
        running = []
        for dev_id, st in self.state.transfer_status.items():
            if st == TransferStatus.RUNNING:
                dev = self.state.devices.get(dev_id)
                name = dev.name if dev else dev_id
                speed = self.state.get_speed(dev_id)
                prog = self.state.get_progress(dev_id) * 100
                running.append(f"- {name}: {prog:.0f}% @ {speed:.2f} MB/s")

        if running:
            self.monitor_label.setText("Active transfers:\n" + "\n".join(running))
        else:
            self.monitor_label.setText("No active transfers.")

    def _format_size(self, size_bytes: int) -> str:
        if size_bytes < 1024:
            return f"{size_bytes} B"
        if size_bytes < 1024 * 1024:
            return f"{size_bytes / 1024:.1f} KB"
        if size_bytes < 1024**3:
            return f"{size_bytes / (1024 * 1024):.1f} MB"
        return f"{size_bytes / (1024**3):.2f} GB"

    # ----------------------------
    # History actions
    # ----------------------------

    def _on_history_double_click(self, item):
        row = item.row()
        records = self.history.get_all()
        if row < len(records):
            record = records[row]
            reply = QMessageBox.question(
                self,
                "Delete Record",
                f"Delete transfer to/from {record.peer_name}?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No,
            )
            if reply == QMessageBox.StandardButton.Yes:
                self.history.delete_record(row)

    def _on_clear_history(self):
        if not self.history.get_all():
            QMessageBox.information(self, "No History", "There is no history to clear.")
            return

        reply = QMessageBox.question(
            self,
            "Clear History",
            "Are you sure you want to delete all transfer history?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if reply == QMessageBox.StandardButton.Yes:
            self.history.clear_all()
