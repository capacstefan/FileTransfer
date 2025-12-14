from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QTableWidget, QTableWidgetItem, QHeaderView, QMessageBox
)

from history import TransferHistory


class HistoryWindow(QDialog):
    def __init__(self, history: TransferHistory, parent=None):
        super().__init__(parent)
        self.history = history
        self.setWindowTitle("Transfer History")
        self.resize(950, 600)
        self._setup_ui()
        self._apply_styles()
        self.refresh()

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(15)
        layout.setContentsMargins(20, 20, 20, 20)

        title = QLabel("Transfer History")
        title.setStyleSheet("font-size: 20px; font-weight: bold; color: #e6e9ee;")
        layout.addWidget(title)

        self.table = QTableWidget()
        self.table.setColumnCount(8)
        self.table.setHorizontalHeaderLabels([
            "Date & Time", "Direction", "Peer", "Files", "Size", "Speed", "Status", "SHA-256"
        ])

        header = self.table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(5, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(6, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(7, QHeaderView.ResizeMode.ResizeToContents)

        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self.table.setAlternatingRowColors(True)
        self.table.itemDoubleClicked.connect(self._on_double_click)

        layout.addWidget(self.table)

        btn_layout = QHBoxLayout()
        btn_layout.addStretch()
        self.clear_btn = QPushButton("Clear History")
        self.clear_btn.clicked.connect(self._on_clear)
        btn_layout.addWidget(self.clear_btn)

        self.close_btn = QPushButton("Close")
        self.close_btn.clicked.connect(self.accept)
        btn_layout.addWidget(self.close_btn)

        layout.addLayout(btn_layout)

    def _apply_styles(self):
        self.setStyleSheet("""
            QDialog {
                background: #0b0e12;
                color: #e6e9ee;
            }
            QTableWidget {
                background: #13171c;
                color: #e6e9ee;
                border: 1px solid #2a313a;
                border-radius: 8px;
                font-size: 13px;
                gridline-color: #2a313a;
            }
            QTableWidget::item:selected {
                background: #1e3a5f;
            }
            QHeaderView::section {
                background: #1a1f26;
                color: #b7bfca;
                padding: 10px;
                border: none;
                border-bottom: 2px solid #2a313a;
                font-weight: bold;
            }
            QPushButton {
                background: #2b3037;
                color: #e6e9ee;
                border: none;
                padding: 10px 20px;
                border-radius: 6px;
                font-size: 13px;
                font-weight: 600;
                min-width: 100px;
            }
            QPushButton:hover {
                background: #3a4047;
            }
            QPushButton:pressed {
                background: #1f2428;
            }
        """)

    def refresh(self):
        records = self.history.get_all()
        self.table.setRowCount(len(records))

        for row, record in enumerate(records):
            self.table.setItem(row, 0, QTableWidgetItem(record.timestamp_str))
            direction = "📤 Sent" if record.direction == "sent" else "📥 Received"
            self.table.setItem(row, 1, QTableWidgetItem(direction))

            peer_text = f"{record.peer_name} ({record.peer_host})"
            self.table.setItem(row, 2, QTableWidgetItem(peer_text))
            self.table.setItem(row, 3, QTableWidgetItem(str(record.num_files)))
            self.table.setItem(row, 4, QTableWidgetItem(self._format_size(record.total_size)))

            if record.status == "completed":
                speed_text = f"{record.speed_mbps:.2f} MB/s"
            else:
                speed_text = "—"
            self.table.setItem(row, 5, QTableWidgetItem(speed_text))

            status_item = QTableWidgetItem(record.status.upper())
            if record.status == "completed":
                status_item.setForeground(Qt.GlobalColor.green)
            elif record.status == "canceled":
                status_item.setForeground(Qt.GlobalColor.yellow)
            else:
                status_item.setForeground(Qt.GlobalColor.red)
            self.table.setItem(row, 6, status_item)

            if record.sha256_ok is None:
                sha_item = QTableWidgetItem("n/a")
            else:
                sha_item = QTableWidgetItem("OK" if record.sha256_ok else "FAIL")
            self.table.setItem(row, 7, sha_item)

    def _format_size(self, size_bytes: int) -> str:
        if size_bytes < 1024:
            return f"{size_bytes} B"
        elif size_bytes < 1024 * 1024:
            return f"{size_bytes / 1024:.1f} KB"
        elif size_bytes < 1024**3:
            return f"{size_bytes / (1024 * 1024):.1f} MB"
        else:
            return f"{size_bytes / (1024**3):.2f} GB"

    def _on_double_click(self, item):
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
                self.refresh()

    def _on_clear(self):
        if not self.history.get_all():
            return
        reply = QMessageBox.question(
            self,
            "Clear History",
            "Delete all transfer history?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if reply == QMessageBox.StandardButton.Yes:
            self.history.clear_all()
            self.refresh()
