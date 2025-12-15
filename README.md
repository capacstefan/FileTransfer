# LAN Transfer (PyQt6 skeleton)

Python LAN file transfer app with strict GUI/backend separation so the core can be swapped for C/C++ later. Current state includes TLS discovery/transfer scaffolding, resumable transfers, SHA-256 verification, UI approvals, and JSON persistence.

## Run
1. Activate the venv: `Scripts\activate` on Windows.
2. Install deps: `pip install pyqt6 cryptography`.
3. Launch: `python -m lan_transfer`.

## Layout
- `lan_transfer/app.py` – entrypoint wiring GUI, backend, persistence.
- `lan_transfer/gui/` – PyQt6 tabs and signal bridge.
- `lan_transfer/backend/` – discovery, transfer skeletons, callbacks, TLS helper.
- `lan_transfer/persistence/` – config/history JSON stores and state paths.
- `state/` – runtime data (config, history, certs, downloads); ignored except `.gitkeep`.

## Defaults
- UDP discovery port 48201, broadcast every 3s.
- TCP transfer port 48202, max 4 concurrent streams placeholder.
- Max file size configured at 3 GiB.
- Self-signed cert/key generated under `state/certs` on first run.

## Next steps
- Harden protocol (timeouts, retries, peer fingerprint pinning for TLS).
- Add richer progress UI (per-file speeds, ETA, cancel/pause).
- Package as EXE (PyInstaller) once features are stable.
