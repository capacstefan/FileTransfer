from PyQt6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QLineEdit, QPushButton, QListWidget, QFileDialog, QMessageBox,
    QTabWidget, QListWidgetItem, QProgressBar, QTableWidget, QTableWidgetItem,
    QHeaderView, QGroupBox, QComboBox, QScrollArea, QFrame
)
from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtGui import QFont

from state import AppStatus


class MonitorPanel(QWidget):
    def __init__(self, state):
        super().__init__()
        self.state = state

        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(15)
        self.labels = {}

        # Title
        title = QLabel("📊 Real-time Statistics")
        title.setFont(QFont("Segoe UI", 16, QFont.Weight.Bold))
        title.setStyleSheet("color: #e6e9ee; margin-bottom: 10px;")
        layout.addWidget(title)

        # Stats grid
        stats_layout = QVBoxLayout()
        stats_layout.setSpacing(12)
        
        stats = [
            ("total_bytes_sent", "📤 Data Sent", "0 MB"),
            ("total_bytes_received", "📥 Data Received", "0 MB"),
            ("last_speed_mb_s", "⚡ Current Speed", "0 MB/s"),
            ("active_transfers", "🔄 Active Transfers", "0"),
            ("errors", "⚠️ Errors", "0")
        ]

        for key, label_text, default_value in stats:
            stat_widget = self._create_stat_widget(label_text, default_value)
            stats_layout.addWidget(stat_widget)
            self.labels[key] = stat_widget.findChild(QLabel, "value_label")

        layout.addLayout(stats_layout)
        layout.addStretch()

        self.timer = QTimer(timeout=self.refresh)
        self.timer.start(1000)

    def _create_stat_widget(self, label_text, default_value):
        widget = QFrame()
        widget.setStyleSheet("""
            QFrame {
                background: #1a1f26;
                border: 1px solid #2a313a;
                border-radius: 10px;
                padding: 15px;
            }
        """)
        
        layout = QHBoxLayout(widget)
        layout.setContentsMargins(15, 15, 15, 15)
        
        label = QLabel(label_text)
        label.setFont(QFont("Segoe UI", 11))
        label.setStyleSheet("color: #b7bfca; border: none;")
        layout.addWidget(label)
        
        layout.addStretch()
        
        value = QLabel(default_value)
        value.setObjectName("value_label")
        value.setFont(QFont("Segoe UI", 12, QFont.Weight.Bold))
        value.setStyleSheet("color: #58a6ff; border: none;")
        layout.addWidget(value)
        
        return widget

    def refresh(self):
        if not self.state.monitor:
            return
        try:
            dev_id, stats = next(iter(self.state.monitor.items()))

            self.labels["total_bytes_sent"].setText(f"{stats.total_bytes_sent / (1024*1024):.2f} MB")
            self.labels["total_bytes_received"].setText(f"{stats.total_bytes_received / (1024*1024):.2f} MB")
            self.labels["last_speed_mb_s"].setText(f"{stats.last_speed_mb_s:.2f} MB/s")
            self.labels["active_transfers"].setText(str(stats.active_transfers))
            self.labels["errors"].setText(str(stats.errors))
        except (StopIteration, AttributeError):
            pass


class FIshareQtApp(QMainWindow):
    def __init__(self, state, advertiser, scanner, history, transfer):
        super().__init__()
        self.state = state
        self.advertiser = advertiser
        self.scanner = scanner
        self.history = history
        self.transfer = transfer

        self.setWindowTitle("FIshare - Modern File Transfer")
        self.resize(1200, 800)
        self._apply_style()

        # Create tabs
        self.tabs = QTabWidget()
        self.tabs.setStyleSheet("""
            QTabWidget::pane {
                border: 1px solid #2a313a;
                border-radius: 8px;
                background: #0b0e12;
            }
            QTabBar::tab {
                background: #1a1f26;
                color: #b7bfca;
                padding: 12px 24px;
                margin-right: 4px;
                border-top-left-radius: 8px;
                border-top-right-radius: 8px;
                font-size: 13px;
                font-weight: 600;
            }
            QTabBar::tab:selected {
                background: #2d333b;
                color: #58a6ff;
            }
            QTabBar::tab:hover {
                background: #252c35;
            }
        """)
        
        self.tabs.addTab(self._main_ui(), "🏠 Transfer")
        self.tabs.addTab(self._settings_ui(), "⚙️ Settings")
        self.tabs.addTab(MonitorPanel(state), "📊 Monitor")
        self.tabs.addTab(self._history_ui(), "📜 History")

        self.setCentralWidget(self.tabs)

    def _main_ui(self):
        w = QWidget()
        main_layout = QVBoxLayout(w)
        main_layout.setContentsMargins(20, 20, 20, 20)
        main_layout.setSpacing(20)

        # Device section
        device_group = QGroupBox("📱 Available Devices")
        device_group.setStyleSheet("""
            QGroupBox {
                font-size: 14px;
                font-weight: bold;
                color: #e6e9ee;
                border: 2px solid #2a313a;
                border-radius: 10px;
                margin-top: 12px;
                padding-top: 15px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                subcontrol-position: top left;
                padding: 5px 10px;
                color: #58a6ff;
            }
        """)
        device_layout = QVBoxLayout(device_group)
        device_layout.setSpacing(10)
        
        # Device selection info
        info_label = QLabel("✓ Select one or more devices (Ctrl+Click for multiple)")
        info_label.setStyleSheet("color: #58a6ff; font-size: 11px; font-style: italic;")
        device_layout.addWidget(info_label)
        
        # Device list (multi-selection enabled)
        self.devices = QListWidget()
        self.devices.setMinimumHeight(150)
        self.devices.setSelectionMode(QListWidget.SelectionMode.ExtendedSelection)
        self.devices.setStyleSheet("""
            QListWidget {
                background: #13171c;
                color: #e6e9ee;
                border: 1px solid #2a313a;
                border-radius: 8px;
                padding: 8px;
                font-size: 12px;
            }
            QListWidget::item {
                padding: 10px;
                border-radius: 4px;
                margin: 2px;
            }
            QListWidget::item:selected {
                background: #238636;
                color: white;
                font-weight: bold;
            }
            QListWidget::item:hover {
                background: #1a2332;
            }
            QListWidget::item:disabled {
                background: #1a1f26;
                color: #6e7681;
            }
        """)
        device_layout.addWidget(self.devices)
        main_layout.addWidget(device_group)

        # Files section
        files_group = QGroupBox("📁 Selected Files")
        files_group.setStyleSheet("""
            QGroupBox {
                font-size: 14px;
                font-weight: bold;
                color: #e6e9ee;
                border: 2px solid #2a313a;
                border-radius: 10px;
                margin-top: 12px;
                padding-top: 15px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                subcontrol-position: top left;
                padding: 5px 10px;
                color: #58a6ff;
            }
        """)
        files_layout = QVBoxLayout(files_group)
        files_layout.setSpacing(10)
        
        self.files = QListWidget()
        self.files.setStyleSheet("""
            QListWidget {
                background: #13171c;
                color: #e6e9ee;
                border: 1px solid #2a313a;
                border-radius: 8px;
                padding: 8px;
                font-size: 12px;
            }
            QListWidget::item {
                padding: 8px;
                border-radius: 4px;
            }
            QListWidget::item:hover {
                background: #1a2332;
            }
        """)
        files_layout.addWidget(self.files)
        
        btn_file = QPushButton("➕ Add Files")
        btn_file.setMinimumHeight(40)
        btn_file.setCursor(Qt.CursorShape.PointingHandCursor)
        btn_file.clicked.connect(self._pick_files)
        files_layout.addWidget(btn_file)
        
        main_layout.addWidget(files_group)

        # Progress section
        progress_group = QGroupBox("📊 Transfer Progress")
        progress_group.setStyleSheet("""
            QGroupBox {
                font-size: 14px;
                font-weight: bold;
                color: #e6e9ee;
                border: 2px solid #2a313a;
                border-radius: 10px;
                margin-top: 12px;
                padding-top: 15px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                subcontrol-position: top left;
                padding: 5px 10px;
                color: #58a6ff;
            }
        """)
        progress_layout = QVBoxLayout(progress_group)
        
        self.progress = QProgressBar()
        self.progress.setMinimumHeight(30)
        self.progress.setStyleSheet("""
            QProgressBar {
                background: #13171c;
                border: 1px solid #2a313a;
                border-radius: 6px;
                text-align: center;
                color: #e6e9ee;
                font-weight: bold;
            }
            QProgressBar::chunk {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #238636, stop:1 #2ea043);
                border-radius: 5px;
            }
        """)
        progress_layout.addWidget(self.progress)
        main_layout.addWidget(progress_group)

        # Send button
        btn_send = QPushButton("🚀 Send Files")
        btn_send.setMinimumHeight(50)
        btn_send.setCursor(Qt.CursorShape.PointingHandCursor)
        btn_send.setStyleSheet("""
            QPushButton {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #238636, stop:1 #2ea043);
                color: white;
                border: none;
                border-radius: 8px;
                font-size: 15px;
                font-weight: bold;
            }
            QPushButton:hover {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #2ea043, stop:1 #3fb950);
            }
            QPushButton:pressed {
                background: #238636;
            }
        """)
        btn_send.clicked.connect(self._send)
        main_layout.addWidget(btn_send)

        self.timer = QTimer(timeout=self._refresh)
        self.timer.start(500)

        return w

    def _settings_ui(self):
        w = QWidget()
        layout = QVBoxLayout(w)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(20)

        # Device name section
        name_group = QGroupBox("🏷️ Device Identity")
        name_group.setStyleSheet("""
            QGroupBox {
                font-size: 14px;
                font-weight: bold;
                color: #e6e9ee;
                border: 2px solid #2a313a;
                border-radius: 10px;
                margin-top: 12px;
                padding-top: 15px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                subcontrol-position: top left;
                padding: 5px 10px;
                color: #58a6ff;
            }
        """)
        name_layout = QVBoxLayout(name_group)
        
        name_label = QLabel("Device Name:")
        name_label.setStyleSheet("color: #b7bfca; font-size: 12px; font-weight: normal;")
        name_layout.addWidget(name_label)
        
        self.name_edit = QLineEdit(self.state.cfg.device_name)
        self.name_edit.setMinimumHeight(35)
        self.name_edit.setStyleSheet("""
            QLineEdit {
                background: #13171c;
                color: #e6e9ee;
                border: 1px solid #2a313a;
                border-radius: 6px;
                padding: 8px 12px;
                font-size: 13px;
            }
            QLineEdit:focus {
                border: 1px solid #58a6ff;
            }
        """)
        self.name_edit.textChanged.connect(self._on_name)
        name_layout.addWidget(self.name_edit)
        
        layout.addWidget(name_group)

        # Status section
        status_group = QGroupBox("📡 Availability Status")
        status_group.setStyleSheet("""
            QGroupBox {
                font-size: 14px;
                font-weight: bold;
                color: #e6e9ee;
                border: 2px solid #2a313a;
                border-radius: 10px;
                margin-top: 12px;
                padding-top: 15px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                subcontrol-position: top left;
                padding: 5px 10px;
                color: #58a6ff;
            }
        """)
        status_layout = QVBoxLayout(status_group)
        
        self.status_btn = QPushButton()
        self._update_status_button()
        self.status_btn.setMinimumHeight(45)
        self.status_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.status_btn.clicked.connect(self._toggle_status)
        status_layout.addWidget(self.status_btn)
        
        layout.addWidget(status_group)

        # Download location section
        download_group = QGroupBox("📂 Download Location")
        download_group.setStyleSheet("""
            QGroupBox {
                font-size: 14px;
                font-weight: bold;
                color: #e6e9ee;
                border: 2px solid #2a313a;
                border-radius: 10px;
                margin-top: 12px;
                padding-top: 15px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                subcontrol-position: top left;
                padding: 5px 10px;
                color: #58a6ff;
            }
        """)
        download_layout = QVBoxLayout(download_group)
        
        current_path_label = QLabel("Current Location:")
        current_path_label.setStyleSheet("color: #b7bfca; font-size: 12px; font-weight: normal;")
        download_layout.addWidget(current_path_label)
        
        self.download_path_label = QLabel(self.state.cfg.download_dir)
        self.download_path_label.setWordWrap(True)
        self.download_path_label.setStyleSheet("""
            QLabel {
                background: #13171c;
                color: #58a6ff;
                border: 1px solid #2a313a;
                border-radius: 6px;
                padding: 10px;
                font-size: 11px;
            }
        """)
        download_layout.addWidget(self.download_path_label)
        
        btn_change_location = QPushButton("📁 Change Download Folder")
        btn_change_location.setMinimumHeight(40)
        btn_change_location.setCursor(Qt.CursorShape.PointingHandCursor)
        btn_change_location.clicked.connect(self._change_download_location)
        download_layout.addWidget(btn_change_location)
        
        layout.addWidget(download_group)
        layout.addStretch()

        return w

    def _history_ui(self):
        w = QWidget()
        layout = QVBoxLayout(w)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(15)

        # Title and controls
        header_layout = QHBoxLayout()
        title = QLabel("📜 Transfer History")
        title.setFont(QFont("Segoe UI", 16, QFont.Weight.Bold))
        title.setStyleSheet("color: #e6e9ee;")
        header_layout.addWidget(title)
        header_layout.addStretch()

        self.clear_history_btn = QPushButton("🗑️ Clear All")
        self.clear_history_btn.setMinimumHeight(35)
        self.clear_history_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.clear_history_btn.setStyleSheet("""
            QPushButton {
                background: #da3633;
                color: white;
                border: none;
                border-radius: 6px;
                padding: 8px 16px;
                font-size: 12px;
                font-weight: 600;
            }
            QPushButton:hover {
                background: #e5534b;
            }
            QPushButton:pressed {
                background: #c93026;
            }
        """)
        self.clear_history_btn.clicked.connect(self._on_clear_history)
        header_layout.addWidget(self.clear_history_btn)

        layout.addLayout(header_layout)

        # History table
        self.history_table = QTableWidget()
        self.history_table.setColumnCount(8)
        self.history_table.setHorizontalHeaderLabels([
            "Date & Time", "Direction", "Peer", "Files", "Size", "Speed", "Status", "SHA-256"
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
        self.history_table.setAlternatingRowColors(True)
        self.history_table.itemDoubleClicked.connect(self._on_history_double_click)

        self.history_table.setStyleSheet("""
            QTableWidget {
                background: #13171c;
                color: #e6e9ee;
                border: 1px solid #2a313a;
                border-radius: 8px;
                font-size: 12px;
                gridline-color: #2a313a;
            }
            QTableWidget::item {
                padding: 8px;
            }
            QTableWidget::item:selected {
                background: #1e3a5f;
            }
            QTableWidget::item:hover {
                background: #1a2332;
            }
            QHeaderView::section {
                background: #1a1f26;
                color: #b7bfca;
                padding: 12px;
                border: none;
                border-bottom: 2px solid #2a313a;
                font-weight: bold;
                font-size: 12px;
            }
        """)

        layout.addWidget(self.history_table)

        # Refresh history initially
        self._refresh_history()

        return w

    def _apply_style(self):
        self.setStyleSheet("""
            QMainWindow {
                background: #0b0e12;
                color: #e6e9ee;
            }
            QWidget {
                background: #0b0e12;
                color: #e6e9ee;
                font-family: 'Segoe UI', Arial, sans-serif;
            }
            QLabel {
                color: #e6e9ee;
            }
            QPushButton {
                background: #1c2128;
                color: #e6e9ee;
                border: 1px solid #30363d;
                padding: 10px 16px;
                border-radius: 8px;
                font-size: 13px;
                font-weight: 600;
            }
            QPushButton:hover {
                background: #2d333b;
                border: 1px solid #58a6ff;
            }
            QPushButton:pressed {
                background: #1a1f26;
            }
            QListWidget {
                background: #13171c;
                color: #e6e9ee;
                border: 1px solid #2a313a;
                border-radius: 8px;
            }
            QLineEdit {
                background: #13171c;
                color: #e6e9ee;
                border: 1px solid #30363d;
                padding: 8px;
                border-radius: 6px;
            }
        """)

    def ask_incoming(self, peer_name: str, num_files: int, size: int) -> bool:
        mb = size / (1024*1024)
        msg = f"{peer_name} wants to send {num_files} file(s)\nSize: {mb:.2f} MB\nAccept?"
        rep = QMessageBox.question(self, "Incoming Transfer", msg,
                                   QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        return rep == QMessageBox.StandardButton.Yes

    def _on_name(self, text):
        self.state.cfg.device_name = text.strip()
        self.state.cfg.save()

    def _toggle_status(self):
        if self.state.status == AppStatus.AVAILABLE:
            self.state.set_status(AppStatus.BUSY)
        else:
            self.state.set_status(AppStatus.AVAILABLE)
        self._update_status_button()

    def _update_status_button(self):
        if self.state.status == AppStatus.AVAILABLE:
            self.status_btn.setText("✅ Available")
            self.status_btn.setStyleSheet("""
                QPushButton {
                    background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                        stop:0 #238636, stop:1 #2ea043);
                    color: white;
                    border: none;
                    border-radius: 8px;
                    font-size: 14px;
                    font-weight: bold;
                }
                QPushButton:hover {
                    background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                        stop:0 #2ea043, stop:1 #3fb950);
                }
            """)
        else:
            self.status_btn.setText("🔴 Busy")
            self.status_btn.setStyleSheet("""
                QPushButton {
                    background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                        stop:0 #da3633, stop:1 #e5534b);
                    color: white;
                    border: none;
                    border-radius: 8px;
                    font-size: 14px;
                    font-weight: bold;
                }
                QPushButton:hover {
                    background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                        stop:0 #e5534b, stop:1 #f0635e);
                }
            """)

    def _pick_files(self):
        f, _ = QFileDialog.getOpenFileNames(self, "Select Files")
        self.state.selected_files = list(f)

    def _refresh(self):
        # Update devices list
        self.devices.clear()
        
        import socket
        # Obține IP-ul local pentru a detecta propriul device
        try:
            hostname = socket.gethostname()
            local_ips = [socket.gethostbyname(hostname)]
            # Încearcă să obții toate IP-urile locale
            try:
                local_ips.extend([ip[4][0] for ip in socket.getaddrinfo(hostname, None)])
            except:
                pass
            local_ips = set(local_ips)
        except:
            local_ips = set()
        
        for dev in self.state.devices.values():
            status_icon = "🟢" if dev.status == AppStatus.AVAILABLE else "🔴"
            
            # Verifică dacă e propriul device
            is_self = (
                dev.host in local_ips or 
                dev.name == self.state.cfg.device_name or
                dev.device_id in local_ips
            )
            
            if is_self:
                # Marcheză ca fiind propriul device - nu poate fi selectat
                item_text = f"🔵 {dev.name} (This Device)"
                item = QListWidgetItem(item_text)
                item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsEnabled)  # Disable selection
                item.setData(Qt.ItemDataRole.UserRole, None)  # No device ID
                self.devices.addItem(item)
            else:
                item_text = f"{status_icon} {dev.name} ({dev.host})"
                item = QListWidgetItem(item_text)
                item.setData(Qt.ItemDataRole.UserRole, dev.device_id)  # Store device ID
                self.devices.addItem(item)

        # Update files
        self.files.clear()
        for f in self.state.selected_files:
            import os
            filename = os.path.basename(f)
            self.files.addItem(f"📄 {filename}")

        # Update progress bar
        if len(self.state.devices) > 0:
            d = next(iter(self.state.devices.keys()))
            ratio = self.state.get_progress(d)
            self.progress.setValue(int(ratio * 100))
        
        # Refresh history in the history tab
        self._refresh_history()

    def _send(self):
        if not self.state.selected_files:
            QMessageBox.warning(self, "No Files", "Please select files to send first.")
            return
        
        # Obține toate device-urile selectate
        selected_items = self.devices.selectedItems()
        if not selected_items:
            QMessageBox.warning(self, "No Device", "Please select at least one device to send to.")
            return
        
        # Extrage device-urile valide (exclude propriul device)
        selected_devices = []
        for item in selected_items:
            dev_id = item.data(Qt.ItemDataRole.UserRole)
            if dev_id and dev_id in self.state.devices:
                selected_devices.append(self.state.devices[dev_id])
        
        if not selected_devices:
            QMessageBox.warning(self, "Invalid Selection", "No valid devices selected.")
            return
        
        # Confirmă trimiterea către mai multe device-uri
        if len(selected_devices) > 1:
            device_names = ", ".join([d.name for d in selected_devices])
            reply = QMessageBox.question(
                self,
                "Send to Multiple Devices",
                f"Send {len(self.state.selected_files)} file(s) to {len(selected_devices)} devices?\n\n"
                f"Devices: {device_names}",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.Yes
            )
            if reply != QMessageBox.StandardButton.Yes:
                return
        
        # Trimite către toate device-urile selectate
        self.transfer.send_to_multiple(selected_devices, self.state.selected_files)
        
        QMessageBox.information(
            self,
            "Transfer Started",
            f"Transfer started to {len(selected_devices)} device(s)."
        )

    def _change_download_location(self):
        folder = QFileDialog.getExistingDirectory(
            self,
            "Select Download Folder",
            self.state.cfg.download_dir
        )
        if folder:
            self.state.cfg.download_dir = folder
            self.state.cfg.save()
            self.download_path_label.setText(folder)
            QMessageBox.information(
                self,
                "Success",
                f"Download location changed to:\n{folder}"
            )

    def _refresh_history(self):
        records = self.history.get_all()
        self.history_table.setRowCount(len(records))

        for row, record in enumerate(records):
            self.history_table.setItem(row, 0, QTableWidgetItem(record.timestamp_str))
            
            direction = "📤 Sent" if record.direction == "sent" else "📥 Received"
            self.history_table.setItem(row, 1, QTableWidgetItem(direction))

            peer_text = f"{record.peer_name} ({record.peer_host})"
            self.history_table.setItem(row, 2, QTableWidgetItem(peer_text))
            self.history_table.setItem(row, 3, QTableWidgetItem(str(record.num_files)))
            self.history_table.setItem(row, 4, QTableWidgetItem(self._format_size(record.total_size)))

            if record.status == "completed":
                speed_text = f"{record.speed_mbps:.2f} MB/s"
            else:
                speed_text = "—"
            self.history_table.setItem(row, 5, QTableWidgetItem(speed_text))

            status_item = QTableWidgetItem(record.status.upper())
            if record.status == "completed":
                status_item.setForeground(Qt.GlobalColor.green)
            elif record.status == "canceled":
                status_item.setForeground(Qt.GlobalColor.yellow)
            else:
                status_item.setForeground(Qt.GlobalColor.red)
            self.history_table.setItem(row, 6, status_item)

            if record.sha256_ok is None:
                sha_item = QTableWidgetItem("n/a")
            else:
                sha_item = QTableWidgetItem("✓" if record.sha256_ok else "✗")
                if record.sha256_ok:
                    sha_item.setForeground(Qt.GlobalColor.green)
                else:
                    sha_item.setForeground(Qt.GlobalColor.red)
            self.history_table.setItem(row, 7, sha_item)

    def _format_size(self, size_bytes: int) -> str:
        if size_bytes < 1024:
            return f"{size_bytes} B"
        elif size_bytes < 1024 * 1024:
            return f"{size_bytes / 1024:.1f} KB"
        elif size_bytes < 1024**3:
            return f"{size_bytes / (1024 * 1024):.1f} MB"
        else:
            return f"{size_bytes / (1024**3):.2f} GB"

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
                self._refresh_history()

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
            self._refresh_history()
            QMessageBox.information(self, "Success", "All history has been cleared.")
