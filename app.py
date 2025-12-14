from PyQt6.QtWidgets import QApplication
import sys

from config import Config, setup_logging
from state import AppState
from network import Discovery, TransferService
from history import TransferHistory
from main_window import FIshareQtApp


def main():
    """
    FIshare - Modern File Transfer Application
    Main entry point for the application
    """
    setup_logging()

    # Initialize configuration and state
    cfg = Config.load()
    state = AppState(cfg)
    history = TransferHistory()

    # Create Qt application
    app = QApplication(sys.argv)
    app.setApplicationName("FIshare")
    app.setOrganizationName("FIshare")

    # Initialize network discovery
    discovery = Discovery(state, cfg)
    discovery.start()

    # Initialize transfer service
    transfer = TransferService(state, None, history)

    # Create and show main window
    win = FIshareQtApp(state, discovery, discovery, history, transfer)
    transfer.main_window = win  # needed for incoming transfer popup
    win.show()

    sys.exit(app.exec())


if __name__ == "__main__":
    main()
