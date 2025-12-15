from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import List

from .paths import HISTORY_PATH, ensure_state_dirs


@dataclass(slots=True)
class HistoryEntry:
    filename: str
    size: int
    peer_name: str
    status: str  # completed|error|canceled
    direction: str  # send|receive
    timestamp: str
    message: str = ""

    @classmethod
    def create(
        cls, filename: str, size: int, peer_name: str, status: str, direction: str, message: str = ""
    ) -> "HistoryEntry":
        return cls(
            filename=filename,
            size=size,
            peer_name=peer_name,
            status=status,
            direction=direction,
            timestamp=datetime.now(timezone.utc).isoformat(),
            message=message,
        )


class HistoryStore:
    def __init__(self, path: Path = HISTORY_PATH) -> None:
        self.path = path

    def append(self, entry: HistoryEntry) -> None:
        ensure_state_dirs()
        history = self.load()
        history.append(asdict(entry))
        self.path.write_text(json.dumps(history, indent=2))

    def load(self) -> List[dict]:
        ensure_state_dirs()
        if not self.path.exists():
            return []
        try:
            return json.loads(self.path.read_text())
        except (json.JSONDecodeError, OSError):
            return []
