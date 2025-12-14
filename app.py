from PyQt6.QtWidgets import QApplication
import sys

from config import Config, setup_logging
from state import AppState
from network import Discovery, TransferService
from history import TransferHistory
from main_window import FIshareQtApp


def main():
    setup_logging()

    cfg = Config.load()
    state = AppState(cfg)
    history = TransferHistory()

    app = QApplication(sys.argv)
    app.setApplicationName("FIshare")
    app.setOrganizationName("FIshare")

    discovery = Discovery(state, cfg)
    discovery.start()

    transfer = TransferService(state, None, history)

    win = FIshareQtApp(state, discovery, discovery, history, transfer)
    transfer.main_window = win
    win.show()

    sys.exit(app.exec())


if __name__ == "__main__":
    main()
