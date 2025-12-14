"""
FIshare - LAN File Transfer Application
Main Entry Point

Usage: python app.py
"""
from __future__ import annotations

import sys
import signal
from pathlib import Path

from PyQt6.QtWidgets import QApplication, QMessageBox, QSystemTrayIcon, QMenu
from PyQt6.QtCore import QThread
from PyQt6.QtGui import QIcon

# Add current directory to path for imports
sys.path.insert(0, str(Path(__file__).parent))

from core import Core
from network import DiscoveryService, TransferService, IncomingOffer
from ui import MainWindow


# ============================================================
# Application Class
# ============================================================

class FIshareApp:
    """Main application controller"""
    
    def __init__(self):
        # Create Qt application first
        self.qt_app = QApplication(sys.argv)
        self.qt_app.setApplicationName("FIshare")
        self.qt_app.setApplicationVersion("2.0.0")
        
        # Initialize core components
        self.core = Core()
        
        # Create network services
        self.discovery = DiscoveryService(self.core)
        self.transfer_service = TransferService(self.core)
        
        # Create main window
        self.window = MainWindow(self.core, self.discovery, self.transfer_service)
        
        # Connect incoming offer callback
        self.transfer_service.set_on_incoming(self._handle_incoming_offer)
        
        # Setup clean shutdown
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
        self.qt_app.aboutToQuit.connect(self._cleanup)
    
    def _handle_incoming_offer(self, offer: IncomingOffer) -> None:
        """Handle incoming transfer request (called from network thread)"""
        # Check availability
        profile = self.core.get_profile()
        if profile["availability"] == "busy":
            # Auto-reject if busy
            self.transfer_service.reject_offer(offer)
            return
        
        # Show dialog via signal (thread-safe)
        self.window.handle_incoming_offer(offer)
    
    def _signal_handler(self, signum, frame):
        """Handle system signals"""
        self._cleanup()
        sys.exit(0)
    
    def _cleanup(self) -> None:
        """Clean shutdown"""
        try:
            self.discovery.stop()
        except Exception:
            pass
        
        try:
            self.transfer_service.shutdown()
        except Exception:
            pass
    
    def run(self) -> int:
        """Start the application"""
        # Start network services
        self.discovery.start()
        self.transfer_service.start()
        
        # Show window
        self.window.show()
        
        # Run Qt event loop
        return self.qt_app.exec()


# ============================================================
# Entry Point
# ============================================================

def main() -> int:
    """Main entry point"""
    try:
        app = FIshareApp()
        return app.run()
    except KeyboardInterrupt:
        return 0
    except Exception as e:
        print(f"Fatal error: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
