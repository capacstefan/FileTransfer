"""
UI Module - PyQt6 User Interface
All user interaction happens here
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Dict, List, Optional, Set

from PyQt6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QLineEdit, QPushButton, QListWidget, QListWidgetItem,
    QFileDialog, QMessageBox, QTabWidget, QProgressBar,
    QTableWidget, QTableWidgetItem, QHeaderView, QAbstractItemView,
    QGroupBox, QFrame, QSplitter, QScrollArea
)
from PyQt6.QtCore import Qt, QTimer, pyqtSignal, QObject
from PyQt6.QtGui import QFont, QColor

from core import Core, Peer, TransferProgress, TransferStatus, TransferDirection, Availability
from network import IncomingOffer


# ============================================================
# Signal Bridge (for thread-safe UI updates)
# ============================================================

class SignalBridge(QObject):
    """Signals for thread-safe UI updates from network threads"""
    incoming_offer = pyqtSignal(object)  # IncomingOffer
    refresh_requested = pyqtSignal()


# ============================================================
# Helper Functions
# ============================================================

def get_local_ips() -> Set[str]:
    """Get local IP addresses to detect self"""
    import socket
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


def format_size(size_bytes: int) -> str:
    """Format bytes to human readable"""
    if size_bytes < 1024:
        return f"{size_bytes} B"
    elif size_bytes < 1024 * 1024:
        return f"{size_bytes / 1024:.1f} KB"
    elif size_bytes < 1024 ** 3:
        return f"{size_bytes / (1024 * 1024):.1f} MB"
    else:
        return f"{size_bytes / (1024 ** 3):.2f} GB"


# ============================================================
# Main Window
# ============================================================

class MainWindow(QMainWindow):
    """Main application window"""
    
    def __init__(self, core: Core, discovery, transfer_service):
        super().__init__()
        self.core = core
        self.discovery = discovery
        self.transfer_service = transfer_service
        
        # Signal bridge for thread-safe updates
        self.signals = SignalBridge()
        self.signals.incoming_offer.connect(self._show_incoming_offer)
        
        # Track known peers for incremental updates
        self._known_peers: Dict[str, QListWidgetItem] = {}
        self._local_ips = get_local_ips()
        
        self.setWindowTitle("FIshare - LAN File Transfer")
        self.setMinimumSize(900, 600)
        self.resize(1000, 700)
        
        self._setup_ui()
        self._apply_styles()
        
        # Refresh timer
        self._timer = QTimer(self)
        self._timer.timeout.connect(self._tick)
        self._timer.start(500)
    
    def _setup_ui(self) -> None:
        """Build the UI"""
        self.tabs = QTabWidget()
        self.tabs.addTab(self._create_transfer_tab(), "📂 Transfer")
        self.tabs.addTab(self._create_settings_tab(), "⚙️ Settings")
        self.tabs.addTab(self._create_monitor_tab(), "📊 Monitor")
        self.tabs.addTab(self._create_history_tab(), "📜 History")
        self.setCentralWidget(self.tabs)
    
    # -------------------- Transfer Tab --------------------
    
    def _create_transfer_tab(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setSpacing(15)
        layout.setContentsMargins(15, 15, 15, 15)
        
        # Peers section
        peers_group = QGroupBox("📡 Available Devices (Click to select, Ctrl+Click for multiple)")
        peers_layout = QVBoxLayout(peers_group)
        
        self.peers_list = QListWidget()
        self.peers_list.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        self.peers_list.setMinimumHeight(150)
        self.peers_list.itemDoubleClicked.connect(self._on_peer_double_click)
        peers_layout.addWidget(self.peers_list)
        
        layout.addWidget(peers_group)
        
        # Files section
        files_group = QGroupBox("📁 Files to Send (Double-click to remove)")
        files_layout = QVBoxLayout(files_group)
        
        self.files_list = QListWidget()
        self.files_list.setMinimumHeight(120)
        self.files_list.itemDoubleClicked.connect(self._on_file_double_click)
        files_layout.addWidget(self.files_list)
        
        btn_row = QHBoxLayout()
        self.btn_add_files = QPushButton("➕ Add Files")
        self.btn_add_files.clicked.connect(self._pick_files)
        btn_row.addWidget(self.btn_add_files)
        
        self.btn_add_folder = QPushButton("📂 Add Folder")
        self.btn_add_folder.clicked.connect(self._pick_folder)
        btn_row.addWidget(self.btn_add_folder)
        
        self.btn_clear_files = QPushButton("🗑️ Clear All")
        self.btn_clear_files.clicked.connect(self._clear_files)
        btn_row.addWidget(self.btn_clear_files)
        
        btn_row.addStretch()
        files_layout.addLayout(btn_row)
        
        layout.addWidget(files_group)
        
        # Send button
        self.btn_send = QPushButton("🚀 SEND FILES")
        self.btn_send.setMinimumHeight(50)
        self.btn_send.setFont(QFont("Segoe UI", 14, QFont.Weight.Bold))
        self.btn_send.clicked.connect(self._send_files)
        layout.addWidget(self.btn_send)
        
        return widget
    
    # -------------------- Settings Tab --------------------
    
    def _create_settings_tab(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setSpacing(20)
        layout.setContentsMargins(20, 20, 20, 20)
        
        # Username section
        name_group = QGroupBox("🏷️ Device Name")
        name_layout = QVBoxLayout(name_group)
        
        self.name_edit = QLineEdit(self.core.get_profile()["username"])
        self.name_edit.setMaxLength(32)
        self.name_edit.textChanged.connect(self._on_name_changed)
        name_layout.addWidget(self.name_edit)
        
        layout.addWidget(name_group)
        
        # Availability section
        status_group = QGroupBox("📡 Availability Status")
        status_layout = QVBoxLayout(status_group)
        
        status_info = QLabel("When BUSY, incoming transfer requests are automatically rejected.")
        status_info.setWordWrap(True)
        status_layout.addWidget(status_info)
        
        self.status_btn = QPushButton()
        self.status_btn.setMinimumHeight(45)
        self.status_btn.clicked.connect(self._toggle_status)
        status_layout.addWidget(self.status_btn)
        self._update_status_button()
        
        layout.addWidget(status_group)
        
        # Download directory section
        download_group = QGroupBox("📂 Download Location")
        download_layout = QVBoxLayout(download_group)
        
        self.download_path_label = QLabel(self.core.get_download_dir())
        self.download_path_label.setWordWrap(True)
        download_layout.addWidget(self.download_path_label)
        
        self.btn_change_download = QPushButton("📁 Change Download Folder")
        self.btn_change_download.clicked.connect(self._change_download_dir)
        download_layout.addWidget(self.btn_change_download)
        
        layout.addWidget(download_group)
        
        layout.addStretch()
        return widget
    
    # -------------------- Monitor Tab --------------------
    
    def _create_monitor_tab(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setSpacing(15)
        layout.setContentsMargins(15, 15, 15, 15)
        
        # Sending transfers
        send_group = QGroupBox("📤 Outgoing Transfers")
        send_layout = QVBoxLayout(send_group)
        self.send_progress_container = QVBoxLayout()
        send_layout.addLayout(self.send_progress_container)
        self.send_empty_label = QLabel("No active outgoing transfers.")
        send_layout.addWidget(self.send_empty_label)
        layout.addWidget(send_group)
        
        # Receiving transfers
        recv_group = QGroupBox("📥 Incoming Transfers")
        recv_layout = QVBoxLayout(recv_group)
        self.recv_progress_container = QVBoxLayout()
        recv_layout.addLayout(self.recv_progress_container)
        self.recv_empty_label = QLabel("No active incoming transfers.")
        recv_layout.addWidget(self.recv_empty_label)
        layout.addWidget(recv_group)
        
        layout.addStretch()
        return widget
    
    # -------------------- History Tab --------------------
    
    def _create_history_tab(self) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setSpacing(10)
        layout.setContentsMargins(15, 15, 15, 15)
        
        # Header with clear button
        header = QHBoxLayout()
        header.addWidget(QLabel("📜 Transfer History"))
        header.addStretch()
        
        self.btn_clear_history = QPushButton("🗑️ Clear History")
        self.btn_clear_history.clicked.connect(self._clear_history)
        header.addWidget(self.btn_clear_history)
        
        layout.addLayout(header)
        
        # History table
        self.history_table = QTableWidget()
        self.history_table.setColumnCount(8)
        self.history_table.setHorizontalHeaderLabels([
            "Date/Time", "Direction", "Peer", "Files", "Size", "Speed", "Status", "Duration"
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
        
        layout.addWidget(self.history_table)
        
        self._refresh_history()
        return widget
    
    # -------------------- Styles --------------------
    
    def _apply_styles(self) -> None:
        """Apply modern dark theme"""
        self.setStyleSheet("""
            QMainWindow, QWidget {
                background-color: #0d1117;
                color: #c9d1d9;
                font-family: 'Segoe UI', Arial, sans-serif;
            }
            
            QGroupBox {
                font-size: 13px;
                font-weight: bold;
                border: 1px solid #30363d;
                border-radius: 8px;
                margin-top: 12px;
                padding-top: 10px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                subcontrol-position: top left;
                padding: 0 8px;
                color: #58a6ff;
            }
            
            QListWidget {
                background-color: #161b22;
                border: 1px solid #30363d;
                border-radius: 6px;
                padding: 5px;
            }
            QListWidget::item {
                padding: 8px;
                border-radius: 4px;
            }
            QListWidget::item:selected {
                background-color: #238636;
                color: white;
            }
            QListWidget::item:hover:!selected {
                background-color: #21262d;
            }
            
            QPushButton {
                background-color: #21262d;
                color: #c9d1d9;
                border: 1px solid #30363d;
                padding: 8px 16px;
                border-radius: 6px;
                font-weight: 600;
            }
            QPushButton:hover {
                background-color: #30363d;
                border-color: #58a6ff;
            }
            QPushButton:pressed {
                background-color: #161b22;
            }
            
            QLineEdit {
                background-color: #161b22;
                color: #c9d1d9;
                border: 1px solid #30363d;
                border-radius: 6px;
                padding: 8px;
            }
            QLineEdit:focus {
                border-color: #58a6ff;
            }
            
            QProgressBar {
                background-color: #161b22;
                border: 1px solid #30363d;
                border-radius: 4px;
                text-align: center;
                color: white;
            }
            QProgressBar::chunk {
                background-color: #238636;
                border-radius: 3px;
            }
            
            QTableWidget {
                background-color: #161b22;
                border: 1px solid #30363d;
                border-radius: 6px;
                gridline-color: #30363d;
            }
            QTableWidget::item {
                padding: 5px;
            }
            QTableWidget::item:selected {
                background-color: #1f6feb;
            }
            QHeaderView::section {
                background-color: #21262d;
                color: #c9d1d9;
                padding: 8px;
                border: none;
                border-bottom: 1px solid #30363d;
                font-weight: bold;
            }
            
            QTabWidget::pane {
                border: 1px solid #30363d;
                border-radius: 6px;
            }
            QTabBar::tab {
                background-color: #21262d;
                color: #8b949e;
                padding: 10px 20px;
                border-top-left-radius: 6px;
                border-top-right-radius: 6px;
                margin-right: 2px;
            }
            QTabBar::tab:selected {
                background-color: #0d1117;
                color: #58a6ff;
            }
            QTabBar::tab:hover:!selected {
                background-color: #30363d;
            }
            
            QLabel {
                color: #c9d1d9;
            }
        """)
        
        # Special styling for send button
        self.btn_send.setStyleSheet("""
            QPushButton {
                background-color: #238636;
                color: white;
                border: none;
                border-radius: 8px;
            }
            QPushButton:hover {
                background-color: #2ea043;
            }
            QPushButton:pressed {
                background-color: #1a7f37;
            }
        """)
    
    # -------------------- Actions --------------------
    
    def _on_peer_double_click(self, item: QListWidgetItem) -> None:
        """Deselect peer on double-click"""
        item.setSelected(False)
    
    def _on_file_double_click(self, item: QListWidgetItem) -> None:
        """Remove file on double-click"""
        path = item.data(Qt.ItemDataRole.UserRole)
        if path:
            self.core.remove_selected_file(path)
            self._refresh_files()
    
    def _pick_files(self) -> None:
        """Open file picker dialog"""
        files, _ = QFileDialog.getOpenFileNames(self, "Select Files")
        if files:
            current = self.core.get_selected_files()
            current.extend(files)
            self.core.set_selected_files(current)
            self._refresh_files()
    
    def _pick_folder(self) -> None:
        """Open folder picker dialog"""
        folder = QFileDialog.getExistingDirectory(self, "Select Folder")
        if folder:
            # Add all files in folder
            files = []
            for root, dirs, filenames in os.walk(folder):
                for name in filenames:
                    files.append(os.path.join(root, name))
            
            current = self.core.get_selected_files()
            current.extend(files)
            self.core.set_selected_files(current)
            self._refresh_files()
    
    def _clear_files(self) -> None:
        """Clear all selected files"""
        self.core.clear_selected_files()
        self._refresh_files()
    
    def _send_files(self) -> None:
        """Send files to selected peers"""
        files = self.core.get_selected_files()
        if not files:
            QMessageBox.warning(self, "No Files", "Please select files to send.")
            return
        
        selected_items = self.peers_list.selectedItems()
        if not selected_items:
            QMessageBox.warning(self, "No Device", "Please select at least one device.")
            return
        
        # Get selected peers
        peers: List[Peer] = []
        for item in selected_items:
            peer_id = item.data(Qt.ItemDataRole.UserRole)
            if peer_id:
                peer = self.core.get_peer(peer_id)
                if peer:
                    peers.append(peer)
        
        if not peers:
            QMessageBox.warning(self, "Invalid Selection", "No valid devices selected.")
            return
        
        # Confirmation for multiple peers
        if len(peers) > 1:
            names = ", ".join(p.username for p in peers)
            reply = QMessageBox.question(
                self, "Confirm Send",
                f"Send {len(files)} file(s) to {len(peers)} devices?\n\n{names}",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
            )
            if reply != QMessageBox.StandardButton.Yes:
                return
        
        # Start sending
        self.transfer_service.send_to_peers(peers, files)
        QMessageBox.information(self, "Transfer Started", 
                                f"Sending to {len(peers)} device(s)...")
    
    def _on_name_changed(self, text: str) -> None:
        """Handle username change"""
        self.core.set_username(text)
    
    def _toggle_status(self) -> None:
        """Toggle availability status"""
        self.core.toggle_availability()
        self._update_status_button()
    
    def _update_status_button(self) -> None:
        """Update status button appearance"""
        profile = self.core.get_profile()
        if profile["availability"] == "available":
            self.status_btn.setText("✅ AVAILABLE - Accepting Transfers")
            self.status_btn.setStyleSheet("""
                QPushButton {
                    background-color: #238636;
                    color: white;
                    border: none;
                    border-radius: 6px;
                    font-weight: bold;
                }
                QPushButton:hover { background-color: #2ea043; }
            """)
        else:
            self.status_btn.setText("🔴 BUSY - Rejecting Transfers")
            self.status_btn.setStyleSheet("""
                QPushButton {
                    background-color: #da3633;
                    color: white;
                    border: none;
                    border-radius: 6px;
                    font-weight: bold;
                }
                QPushButton:hover { background-color: #f85149; }
            """)
    
    def _change_download_dir(self) -> None:
        """Change download directory"""
        folder = QFileDialog.getExistingDirectory(
            self, "Select Download Folder", 
            self.core.get_download_dir()
        )
        if folder:
            self.core.set_download_dir(folder)
            self.download_path_label.setText(folder)
            QMessageBox.information(self, "Success", f"Download folder changed to:\n{folder}")
    
    def _clear_history(self) -> None:
        """Clear all history"""
        records = self.core.history.get_all()
        if not records:
            QMessageBox.information(self, "Empty", "History is already empty.")
            return
        
        reply = QMessageBox.question(
            self, "Confirm Clear",
            "Delete all transfer history?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        if reply == QMessageBox.StandardButton.Yes:
            self.core.history.clear()
            self._refresh_history()
    
    def _on_history_double_click(self, item: QTableWidgetItem) -> None:
        """Delete history record on double-click"""
        row = item.row()
        records = self.core.history.get_all()
        if row < len(records):
            record = records[row]
            reply = QMessageBox.question(
                self, "Delete Record",
                f"Delete this transfer record?\n{record.peer_name} - {record.status}",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
            )
            if reply == QMessageBox.StandardButton.Yes:
                self.core.history.delete(row)
                self._refresh_history()
    
    # -------------------- Incoming Offers --------------------
    
    def handle_incoming_offer(self, offer: IncomingOffer) -> None:
        """Called from network thread when offer arrives"""
        # Use signal to safely update UI from main thread
        self.signals.incoming_offer.emit(offer)
    
    def _show_incoming_offer(self, offer: IncomingOffer) -> None:
        """Show accept/reject dialog (runs in UI thread)"""
        size_str = format_size(offer.total_bytes)
        msg = (
            f"📥 Incoming Transfer Request\n\n"
            f"From: {offer.sender_name} ({offer.sender_ip})\n"
            f"Files: {len(offer.files)}\n"
            f"Total Size: {size_str}\n\n"
            f"Accept this transfer?"
        )
        
        reply = QMessageBox.question(
            self, "Incoming Transfer", msg,
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        
        if reply == QMessageBox.StandardButton.Yes:
            self.transfer_service.accept_offer(offer)
        else:
            self.transfer_service.reject_offer(offer)
    
    # -------------------- Refresh Methods --------------------
    
    def _tick(self) -> None:
        """Periodic UI refresh"""
        try:
            self.core.prune_stale_peers()
        except Exception:
            pass
        
        self._refresh_peers()
        self._refresh_files()
        self._refresh_monitor()
        self._refresh_history()
    
    def _refresh_peers(self) -> None:
        """Refresh peers list (incremental to preserve selection)"""
        peers = self.core.list_peers()
        current_ids = {p.peer_id for p in peers}
        my_username = self.core.get_profile()["username"]
        
        # Remove stale items
        for peer_id in list(self._known_peers.keys()):
            if peer_id not in current_ids:
                item = self._known_peers.pop(peer_id)
                row = self.peers_list.row(item)
                if row >= 0:
                    self.peers_list.takeItem(row)
        
        # Add/update items
        for peer in peers:
            # Skip self
            if peer.ip in self._local_ips and peer.username == my_username:
                continue
            
            status_icon = "🟢" if peer.is_available else "🔴"
            display = f"{status_icon} {peer.username} ({peer.ip})"
            
            if peer.peer_id in self._known_peers:
                # Update existing
                item = self._known_peers[peer.peer_id]
                item.setText(display)
            else:
                # Add new
                item = QListWidgetItem(display)
                item.setData(Qt.ItemDataRole.UserRole, peer.peer_id)
                item.setFlags(item.flags() | Qt.ItemFlag.ItemIsSelectable | Qt.ItemFlag.ItemIsEnabled)
                self.peers_list.addItem(item)
                self._known_peers[peer.peer_id] = item
    
    def _refresh_files(self) -> None:
        """Refresh files list"""
        files = self.core.get_selected_files()
        self.files_list.clear()
        
        total_size = 0
        for path in files:
            p = Path(path)
            if p.exists():
                size = p.stat().st_size
                total_size += size
                display = f"📄 {p.name} ({format_size(size)})"
            else:
                display = f"❌ {p.name} (not found)"
            
            item = QListWidgetItem(display)
            item.setData(Qt.ItemDataRole.UserRole, path)
            self.files_list.addItem(item)
        
        # Update button text with count
        count = len(files)
        if count > 0:
            self.btn_send.setText(f"🚀 SEND {count} FILE(S) ({format_size(total_size)})")
        else:
            self.btn_send.setText("🚀 SEND FILES")
    
    def _refresh_monitor(self) -> None:
        """Refresh active transfers monitor"""
        transfers = self.core.list_active_transfers()
        
        # Separate by direction
        sending = [t for t in transfers if t.direction == TransferDirection.SEND]
        receiving = [t for t in transfers if t.direction == TransferDirection.RECEIVE]
        
        # Update sending section
        self.send_empty_label.setVisible(len(sending) == 0)
        # Clear old progress bars (simplified - in production would reuse widgets)
        while self.send_progress_container.count() > 0:
            item = self.send_progress_container.takeAt(0)
            if item.widget():
                item.widget().deleteLater()
        
        for transfer in sending:
            widget = self._create_progress_widget(transfer)
            self.send_progress_container.addWidget(widget)
        
        # Update receiving section
        self.recv_empty_label.setVisible(len(receiving) == 0)
        while self.recv_progress_container.count() > 0:
            item = self.recv_progress_container.takeAt(0)
            if item.widget():
                item.widget().deleteLater()
        
        for transfer in receiving:
            widget = self._create_progress_widget(transfer)
            self.recv_progress_container.addWidget(widget)
    
    def _create_progress_widget(self, transfer: TransferProgress) -> QWidget:
        """Create a progress widget for a transfer"""
        widget = QFrame()
        widget.setStyleSheet("""
            QFrame {
                background-color: #161b22;
                border: 1px solid #30363d;
                border-radius: 6px;
                padding: 8px;
            }
        """)
        
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(5)
        
        # Header: peer name and speed
        header = QHBoxLayout()
        header.addWidget(QLabel(f"👤 {transfer.peer_name}"))
        header.addStretch()
        header.addWidget(QLabel(f"⚡ {transfer.speed_mbps:.2f} MB/s"))
        layout.addLayout(header)
        
        # Progress bar
        progress = QProgressBar()
        progress.setRange(0, 100)
        progress.setValue(int(transfer.progress_percent))
        progress.setFormat(f"{transfer.progress_percent:.1f}% - {format_size(transfer.transferred_bytes)}/{format_size(transfer.total_bytes)}")
        layout.addWidget(progress)
        
        return widget
    
    def _refresh_history(self) -> None:
        """Refresh history table"""
        records = self.core.history.get_all()
        self.history_table.setRowCount(len(records))
        
        for row, record in enumerate(records):
            # Date/Time
            self.history_table.setItem(row, 0, QTableWidgetItem(record.timestamp_str))
            
            # Direction
            direction = "📤 Send" if record.direction == "send" else "📥 Receive"
            self.history_table.setItem(row, 1, QTableWidgetItem(direction))
            
            # Peer
            self.history_table.setItem(row, 2, QTableWidgetItem(f"{record.peer_name} ({record.peer_host})"))
            
            # Files
            self.history_table.setItem(row, 3, QTableWidgetItem(str(record.num_files)))
            
            # Size
            self.history_table.setItem(row, 4, QTableWidgetItem(format_size(record.total_bytes)))
            
            # Speed
            speed_text = f"{record.avg_speed_mbps:.2f} MB/s" if record.avg_speed_mbps > 0 else "—"
            self.history_table.setItem(row, 5, QTableWidgetItem(speed_text))
            
            # Status
            status_item = QTableWidgetItem(record.status.upper())
            if record.status == "completed":
                status_item.setForeground(QColor("#3fb950"))
            elif record.status == "error":
                status_item.setForeground(QColor("#f85149"))
            elif record.status == "canceled":
                status_item.setForeground(QColor("#d29922"))
            self.history_table.setItem(row, 6, status_item)
            
            # Duration
            duration = f"{record.duration_sec:.1f}s" if record.duration_sec > 0 else "—"
            self.history_table.setItem(row, 7, QTableWidgetItem(duration))
