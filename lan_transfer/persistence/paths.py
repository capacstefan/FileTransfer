from __future__ import annotations

from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
STATE_DIR = PROJECT_ROOT / "state"
CERT_DIR = STATE_DIR / "certs"
CONFIG_PATH = STATE_DIR / "config.json"
HISTORY_PATH = STATE_DIR / "history.json"
CERT_PATH = CERT_DIR / "selfsigned.pem"
KEY_PATH = CERT_DIR / "selfsigned.key"


def ensure_state_dirs() -> None:
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    CERT_DIR.mkdir(parents=True, exist_ok=True)
