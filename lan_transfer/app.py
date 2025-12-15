import sys
from PyQt6.QtWidgets import QApplication

from .persistence.config_store import AppConfig, ConfigStore
from .persistence.history_store import HistoryStore
from .gui.main_window import MainWindow
from .gui.event_bridge import EventBridge
from .backend.controller import BackendController


def main() -> None:
    app = QApplication(sys.argv)

    config_store = ConfigStore()
    history_store = HistoryStore()
    app_config: AppConfig = config_store.load()

    bridge = EventBridge()
    backend = BackendController(callbacks=bridge.callbacks, app_config=app_config)

    window = MainWindow(
        config_store=config_store,
        history_store=history_store,
        backend=backend,
        event_bridge=bridge,
    )
    window.show()

    backend.start()
    exit_code = app.exec()
    backend.stop()
    sys.exit(exit_code)
