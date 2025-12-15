from __future__ import annotations

import hashlib
import json
import socket
import ssl
import struct
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Dict, Iterable, Optional

from .certs import ensure_cert_pair
from .constants import BackendSettings
from .events import BackendCallbacks, PeerInfo, TransferFile, TransferOffer, TransferProgress, TransferResult

CHUNK_SIZE = 64 * 1024


def _send_json(sock: ssl.SSLSocket, payload: Dict) -> None:
    data = json.dumps(payload).encode()
    header = struct.pack("!I", len(data))
    sock.sendall(header + data)


def _recv_json(sock: ssl.SSLSocket) -> Optional[Dict]:
    header = _recv_exact(sock, 4)
    if not header:
        return None
    (length,) = struct.unpack("!I", header)
    buf = _recv_exact(sock, length)
    if buf is None:
        return None
    return json.loads(buf.decode())


def _recv_exact(sock: ssl.SSLSocket, length: int) -> Optional[bytes]:
    buf = b""
    while len(buf) < length:
        chunk = sock.recv(length - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf


def _sha256_path(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(CHUNK_SIZE), b""):
            h.update(chunk)
    return h.hexdigest()


class TransferService:
    """TLS-wrapped TCP transfer service with resume, hashing, and approvals."""

    def __init__(
        self,
        settings: BackendSettings,
        callbacks: BackendCallbacks,
        download_dir: Path,
        device_name: str,
        status: str,
        cert_path: Path,
        key_path: Path,
    ) -> None:
        self.settings = settings
        self.callbacks = callbacks
        self.download_dir = download_dir
        self.device_name = device_name
        self.status = status
        self.cert_path, self.key_path = ensure_cert_pair(cert_path, key_path)
        self._server_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._executor = ThreadPoolExecutor(max_workers=settings.max_concurrent_streams)
        self._pending_offers: Dict[str, tuple[threading.Event, Optional[bool]]] = {}
        self._pending_lock = threading.Lock()

    def start(self) -> None:
        self._stop_event.clear()
        self._server_thread = threading.Thread(target=self._accept_loop, daemon=True)
        self._server_thread.start()

    def stop(self) -> None:
        self._stop_event.set()
        self._executor.shutdown(wait=False)

    def respond_to_offer(self, request_id: str, accept: bool) -> None:
        with self._pending_lock:
            if request_id in self._pending_offers:
                event, _ = self._pending_offers[request_id]
                self._pending_offers[request_id] = (event, accept)
                event.set()

    def send_files(self, peer: PeerInfo, files: Iterable[Path]) -> str:
        file_list = list(files)
        for p in file_list:
            if p.stat().st_size > self.settings.max_file_size_bytes:
                raise ValueError(f"File {p} exceeds max allowed size")
        transfer_id = str(uuid.uuid4())
        self._executor.submit(self._send_job, transfer_id, peer, file_list)
        return transfer_id

    def _accept_loop(self) -> None:
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        context.load_cert_chain(certfile=str(self.cert_path), keyfile=str(self.key_path))
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0) as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(("", self.settings.tcp_port))
            sock.listen(5)
            sock.settimeout(1.0)
            while not self._stop_event.is_set():
                try:
                    client, addr = sock.accept()
                except socket.timeout:
                    continue
                except OSError:
                    break
                self._executor.submit(self._handle_client, client, addr, context)

    def _handle_client(self, client: socket.socket, addr, context: ssl.SSLContext) -> None:
        try:
            with context.wrap_socket(client, server_side=True) as tls:
                hello = _recv_json(tls)
                if not hello or hello.get("type") != "HELLO":
                    return
                remote_name = hello.get("name", addr[0])
                offer_msg = _recv_json(tls)
                if not offer_msg or offer_msg.get("type") != "OFFER":
                    return

                files_meta = offer_msg.get("files", [])
                if any(f.get("size", 0) > self.settings.max_file_size_bytes for f in files_meta):
                    _send_json(tls, {"type": "REJECT", "reason": "file too large"})
                    return

                if self.status == "busy":
                    _send_json(tls, {"type": "REJECT", "reason": "busy"})
                    return

                peer = PeerInfo(peer_id=addr[0], name=remote_name, ip=addr[0], status="available")
                offer = TransferOffer(
                    peer=peer,
                    files=[
                        TransferFile(
                            name=f["name"],
                            size=int(f.get("size", 0)),
                            sha256=f.get("sha256"),
                        )
                        for f in files_meta
                    ],
                    request_id=offer_msg.get("request_id", str(uuid.uuid4())),
                )

                decision = self._await_offer_decision(offer)
                if not decision:
                    _send_json(tls, {"type": "REJECT", "reason": "declined"})
                    return

                offsets = self._compute_offsets(peer, offer)
                _send_json(
                    tls,
                    {
                        "type": "ACCEPT",
                        "request_id": offer.request_id,
                        "offsets": offsets,
                    },
                )

                for tf in offer.files:
                    start_msg = _recv_json(tls)
                    if not start_msg or start_msg.get("type") != "FILE_START":
                        break
                    offset = int(start_msg.get("offset", 0))
                    expected_hash = start_msg.get("sha256")
                    save_path, written = self._recv_file(tls, offer.request_id, peer, tf, offset)
                    status = "completed"
                    message = ""
                    computed = _sha256_path(save_path) if save_path.exists() else ""
                    if computed != expected_hash:
                        status = "error"
                        message = "Hash mismatch"
                    if status == "completed":
                        final_path = self._final_path(peer, tf)
                        save_path.replace(final_path)
                        saved_path = final_path
                    else:
                        saved_path = save_path
                    _send_json(
                        tls,
                        {
                            "type": "FILE_DONE",
                            "name": tf.name,
                            "status": status,
                            "message": message,
                        },
                    )
                    result = TransferResult(
                        transfer_id=offer.request_id,
                        peer=peer,
                        file=tf,
                        status=status,
                        direction="receive",
                        message=message,
                        saved_path=saved_path,
                    )
                    self.callbacks.on_transfer_result(result)
                _send_json(tls, {"type": "ALL_DONE"})
        except ssl.SSLError:
            pass
        except OSError:
            pass

    def _send_job(self, transfer_id: str, peer: PeerInfo, files: list[Path]) -> None:
        metadata = [
            TransferFile(name=p.name, size=p.stat().st_size, sha256=_sha256_path(p)) for p in files
        ]
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        try:
            with socket.create_connection((peer.ip, self.settings.tcp_port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=peer.ip) as tls:
                    _send_json(tls, {"type": "HELLO", "name": self.device_name, "status": self.status})
                    _send_json(
                        tls,
                        {
                            "type": "OFFER",
                            "request_id": transfer_id,
                            "files": [
                                {"name": m.name, "size": m.size, "sha256": m.sha256} for m in metadata
                            ],
                        },
                    )
                    resp = _recv_json(tls)
                    if not resp or resp.get("type") != "ACCEPT":
                        self._signal_reject(peer, metadata, transfer_id, resp)
                        return
                    offsets = resp.get("offsets", {})
                    for tf, path in zip(metadata, files):
                        offset = int(offsets.get(tf.name, 0))
                        self._send_file(tls, peer, tf, path, transfer_id, offset)
                    done = _recv_json(tls)
                    if not done or done.get("type") != "ALL_DONE":
                        pass
        except (OSError, ssl.SSLError):
            for tf in metadata:
                result = TransferResult(
                    transfer_id=transfer_id,
                    peer=peer,
                    file=tf,
                    status="error",
                    direction="send",
                    message="Connection failed",
                )
                self.callbacks.on_transfer_result(result)

    def _send_file(
        self,
        tls: ssl.SSLSocket,
        peer: PeerInfo,
        tf: TransferFile,
        path: Path,
        transfer_id: str,
        offset: int,
    ) -> None:
        remaining = tf.size - offset
        _send_json(
            tls,
            {
                "type": "FILE_START",
                "name": tf.name,
                "size": tf.size,
                "sha256": tf.sha256,
                "offset": offset,
            },
        )
        sent = 0
        start_time = time.monotonic()
        with path.open("rb") as f:
            f.seek(offset)
            while sent < remaining:
                chunk = f.read(min(CHUNK_SIZE, remaining - sent))
                if not chunk:
                    break
                tls.sendall(chunk)
                sent += len(chunk)
                elapsed = max(time.monotonic() - start_time, 0.001)
                speed = sent / elapsed
                progress = TransferProgress(
                    transfer_id=transfer_id,
                    peer=peer,
                    file=tf,
                    bytes_transferred=offset + sent,
                    total_bytes=tf.size,
                    speed_bps=speed,
                    direction="send",
                )
                self.callbacks.on_transfer_progress(progress)
        resp = _recv_json(tls)
        status = resp.get("status") if resp else "error"
        message = resp.get("message", "") if resp else "no response"
        result = TransferResult(
            transfer_id=transfer_id,
            peer=peer,
            file=tf,
            status=status,
            direction="send",
            message=message,
        )
        self.callbacks.on_transfer_result(result)

    def _recv_file(
        self,
        tls: ssl.SSLSocket,
        transfer_id: str,
        peer: PeerInfo,
        tf: TransferFile,
        offset: int,
    ) -> tuple[Path, int]:
        dir_path = self.download_dir / peer.name
        dir_path.mkdir(parents=True, exist_ok=True)
        partial_path = dir_path / f"{tf.name}.part"
        bytes_expected = tf.size - offset
        received = 0
        start_time = time.monotonic()
        mode = "r+b" if partial_path.exists() else "wb"
        with open(partial_path, mode) as f:
            f.seek(offset)
            while received < bytes_expected:
                chunk = tls.recv(min(CHUNK_SIZE, bytes_expected - received))
                if not chunk:
                    break
                f.write(chunk)
                received += len(chunk)
                elapsed = max(time.monotonic() - start_time, 0.001)
                speed = received / elapsed
                progress = TransferProgress(
                    transfer_id=transfer_id,
                    peer=peer,
                    file=tf,
                    bytes_transferred=offset + received,
                    total_bytes=tf.size,
                    speed_bps=speed,
                    direction="receive",
                )
                self.callbacks.on_transfer_progress(progress)
        return partial_path, received

    def _compute_offsets(self, peer: PeerInfo, offer: TransferOffer) -> Dict[str, int]:
        offsets: Dict[str, int] = {}
        for tf in offer.files:
            part = self.download_dir / peer.name / f"{tf.name}.part"
            if part.exists():
                current = part.stat().st_size
                if 0 < current < tf.size:
                    offsets[tf.name] = current
        return offsets

    def _final_path(self, peer: PeerInfo, tf: TransferFile) -> Path:
        return self.download_dir / peer.name / tf.name

    def _await_offer_decision(self, offer: TransferOffer, timeout: float = 60.0) -> bool:
        event = threading.Event()
        with self._pending_lock:
            self._pending_offers[offer.request_id] = (event, None)
        self.callbacks.on_transfer_offer(offer)
        event.wait(timeout)
        with self._pending_lock:
            _, decision = self._pending_offers.pop(offer.request_id, (event, False))
        return bool(decision)

    def _signal_reject(self, peer: PeerInfo, metadata: list[TransferFile], transfer_id: str, resp: Optional[dict]) -> None:
        reason = resp.get("reason") if resp else "rejected"
        for tf in metadata:
            result = TransferResult(
                transfer_id=transfer_id,
                peer=peer,
                file=tf,
                status="canceled",
                direction="send",
                message=reason,
            )
            self.callbacks.on_transfer_result(result)
