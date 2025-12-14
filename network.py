from __future__ import annotations

import json
import os
import socket
import struct
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple

import security
import storage
from core import Core


# ----------------------------
# Message framing: length-prefixed JSON and optional binary frames
# ----------------------------

def send_json(sock: socket.socket, msg: dict) -> None:
    data = json.dumps(msg, ensure_ascii=False).encode("utf-8")
    sock.sendall(struct.pack("!I", len(data)) + data)


def recv_exact(sock: socket.socket, n: int) -> bytes:
    chunks = []
    got = 0
    while got < n:
        part = sock.recv(n - got)
        if not part:
            raise ConnectionError("socket closed")
        chunks.append(part)
        got += len(part)
    return b"".join(chunks)


def recv_json(sock: socket.socket) -> dict:
    (ln,) = struct.unpack("!I", recv_exact(sock, 4))
    data = recv_exact(sock, ln)
    return json.loads(data.decode("utf-8"))


def send_bin(sock: socket.socket, b: bytes) -> None:
    sock.sendall(struct.pack("!I", len(b)) + b)


def recv_bin(sock: socket.socket) -> bytes:
    (ln,) = struct.unpack("!I", recv_exact(sock, 4))
    return recv_exact(sock, ln)


# ----------------------------
# Discovery (UDP multicast + fallback broadcast)
# ----------------------------

class DiscoveryService:
    def __init__(self, core: Core) -> None:
        self.core = core
        self.cfg = core.cfg
        self._stop = threading.Event()
        self._tx_thread: Optional[threading.Thread] = None
        self._rx_thread: Optional[threading.Thread] = None

    def start(self) -> None:
        self._stop.clear()
        self._tx_thread = threading.Thread(target=self._announce_loop, daemon=True)
        self._rx_thread = threading.Thread(target=self._listen_loop, daemon=True)
        self._tx_thread.start()
        self._rx_thread.start()

    def stop(self) -> None:
        self._stop.set()

    def _announce_loop(self) -> None:
        disc = self.cfg["discovery"]
        udp_port = int(disc["udp_port"])
        group = str(disc["multicast_group"])
        interval = float(disc["announce_interval_sec"])
        method = str(disc["method"]).lower()

        tcp_port = int(self.cfg["network"]["tcp_port"])

        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        # multicast TTL small
        try:
            s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 1)
        except Exception:
            pass

        while not self._stop.is_set():
            profile = self.core.get_profile()
            payload = {
                "type": "DISCOVERY",
                "v": 1,
                "username": profile["username"],
                "availability": profile["availability"],
                "tcp_port": tcp_port,
                "ts": time.time(),
            }
            data = json.dumps(payload, ensure_ascii=False).encode("utf-8")

            try:
                if method == "multicast":
                    s.sendto(data, (group, udp_port))
                else:
                    s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
                    s.sendto(data, ("255.255.255.255", udp_port))
            except Exception:
                # fallback to broadcast if multicast fails
                try:
                    s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
                    s.sendto(data, ("255.255.255.255", udp_port))
                except Exception:
                    pass

            time.sleep(interval)

    def _listen_loop(self) -> None:
        disc = self.cfg["discovery"]
        udp_port = int(disc["udp_port"])
        group = str(disc["multicast_group"])

        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        try:
            s.bind(("", udp_port))
        except OSError:
            # If bind fails, try binding to localhost (some envs)
            s.bind(("0.0.0.0", udp_port))

        # join multicast group
        try:
            mreq = struct.pack("=4sl", socket.inet_aton(group), socket.INADDR_ANY)
            s.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
        except Exception:
            # multicast may be blocked; still receive broadcast on the port
            pass

        s.settimeout(0.5)
        while not self._stop.is_set():
            try:
                data, addr = s.recvfrom(64 * 1024)
            except socket.timeout:
                continue
            except Exception:
                continue

            ip = addr[0]
            try:
                msg = json.loads(data.decode("utf-8", errors="ignore"))
            except Exception:
                continue
            if msg.get("type") != "DISCOVERY":
                continue

            profile = self.core.get_profile()
            # ignore our own beacons by username+tcp_port heuristic
            if msg.get("username") == profile["username"] and int(msg.get("tcp_port", -1)) == int(self.cfg["network"]["tcp_port"]):
                continue

            username = str(msg.get("username", "Unknown"))
            availability = str(msg.get("availability", "available")).lower()
            tcp_port = int(msg.get("tcp_port", self.cfg["network"]["tcp_port"]))
            peer_id = f"{username}@{ip}:{tcp_port}"
            self.core.upsert_peer(peer_id, username, ip, tcp_port, availability)


# ----------------------------
# Transfer Server + Client
# ----------------------------

@dataclass
class IncomingOffer:
    transfer_id: str
    sender_name: str
    sender_peer_id: str
    files: List[dict]         # [{"name":..., "size":...}]
    total_bytes: int
    sock: socket.socket       # kept open while waiting accept/reject
    sender_pub: bytes         # identity pub bytes


class TransferService:
    def __init__(self, core: Core, on_incoming_offer: Callable[[IncomingOffer], None]) -> None:
        self.core = core
        self.on_incoming_offer = on_incoming_offer

        self._stop = threading.Event()
        self._server_thread: Optional[threading.Thread] = None
        self._server_sock: Optional[socket.socket] = None

        self._active_lock = threading.RLock()
        self._active_threads: List[threading.Thread] = []

    def start(self) -> None:
        self._stop.clear()
        self._server_thread = threading.Thread(target=self._server_loop, daemon=True)
        self._server_thread.start()

    def stop(self) -> None:
        self._stop.set()
        try:
            if self._server_sock:
                self._server_sock.close()
        except Exception:
            pass

    # ---------- server side ----------

    def _server_loop(self) -> None:
        port = int(self.core.cfg["network"]["tcp_port"])
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("0.0.0.0", port))
        srv.listen(50)
        srv.settimeout(0.5)
        self._server_sock = srv

        while not self._stop.is_set():
            try:
                client, addr = srv.accept()
            except socket.timeout:
                continue
            except Exception:
                continue

            t = threading.Thread(target=self._handle_client, args=(client, addr), daemon=True)
            t.start()
            with self._active_lock:
                self._active_threads.append(t)

    def _handle_client(self, sock: socket.socket, addr: Tuple[str, int]) -> None:
        sock.settimeout(10.0)
        try:
            hello = recv_json(sock)
            if hello.get("type") != "HELLO":
                sock.close()
                return

            sender_name = str(hello.get("username", "Unknown"))
            sender_tcp = int(hello.get("tcp_port", 0))
            sender_pub_hex = hello.get("identity_pub_hex", "")
            sender_pub = bytes.fromhex(sender_pub_hex) if sender_pub_hex else b""
            sender_ip = addr[0]
            sender_peer_id = f"{sender_name}@{sender_ip}:{sender_tcp}"

            # Return our identity pub
            our_pub = security.load_identity_public_bytes()
            send_json(sock, {"type": "HELLO_OK", "identity_pub_hex": our_pub.hex()})

            offer = recv_json(sock)
            if offer.get("type") != "TRANSFER_OFFER":
                sock.close()
                return

            transfer_id = str(offer.get("transfer_id"))
            files = offer.get("files", [])
            total_bytes = int(offer.get("total_bytes", 0))

            incoming = IncomingOffer(
                transfer_id=transfer_id,
                sender_name=sender_name,
                sender_peer_id=sender_peer_id,
                files=files,
                total_bytes=total_bytes,
                sock=sock,
                sender_pub=sender_pub,
            )
            # UI will decide accept/reject; keep socket open
            self.on_incoming_offer(incoming)

        except Exception:
            try:
                sock.close()
            except Exception:
                pass

    # ---------- accept/reject (called by App) ----------

    def reject_offer(self, offer: IncomingOffer, reason: str = "rejected") -> None:
        try:
            send_json(offer.sock, {"type": "TRANSFER_RESPONSE", "accept": False, "reason": reason})
        except Exception:
            pass
        try:
            offer.sock.close()
        except Exception:
            pass

    def accept_offer(self, offer: IncomingOffer) -> None:
        """
        Accept and start receiving in a dedicated thread.
        """
        try:
            send_json(offer.sock, {"type": "TRANSFER_RESPONSE", "accept": True})
        except Exception:
            try:
                offer.sock.close()
            except Exception:
                pass
            return

        t = threading.Thread(target=self._receive_files, args=(offer,), daemon=True)
        t.start()
        with self._active_lock:
            self._active_threads.append(t)

    # ---------- receiving ----------

    def _receive_files(self, offer: IncomingOffer) -> None:
        sock = offer.sock
        transfer_id = offer.transfer_id
        sender_peer_id = offer.sender_peer_id
        sender_name = offer.sender_name
        total_bytes = offer.total_bytes

        # init progress in core
        self.core.init_transfer(transfer_id, "receive", [(sender_peer_id, sender_name)], total_bytes)

        start = time.time()
        done = 0
        try:
            # Handshake: exchange ephemeral keys
            # Receiver generates ephemeral, sends to sender; sender replies with ephemeral + salt; both derive same AES key.
            recv_eph_sk, recv_eph_pk = security.generate_ephemeral()
            send_json(sock, {"type": "HS1", "eph_pub_hex": recv_eph_pk.hex()})

            hs2 = recv_json(sock)
            if hs2.get("type") != "HS2":
                raise ConnectionError("handshake failed")
            sender_eph_pub = bytes.fromhex(hs2["eph_pub_hex"])
            salt = bytes.fromhex(hs2["salt_hex"])

            shared = security.compute_shared_secret(recv_eph_sk, sender_eph_pub)
            keys = security.derive_session_key(shared, salt)

            # Now receive file stream: FILE_BEGIN (json), then repeated CHUNK (bin) frames, then FILE_END
            download_dir = Path(self.core.get_download_dir())
            download_dir.mkdir(parents=True, exist_ok=True)

            counter = 1
            while True:
                hdr = recv_json(sock)
                mtype = hdr.get("type")
                if mtype == "DONE":
                    break
                if mtype != "FILE_BEGIN":
                    raise ConnectionError("protocol error: expected FILE_BEGIN")

                rel_name = str(hdr["name"])
                fsize = int(hdr["size"])

                out_path = download_dir / rel_name
                out_path.parent.mkdir(parents=True, exist_ok=True)

                with out_path.open("wb") as f:
                    remaining = fsize
                    while remaining > 0:
                        enc = recv_bin(sock)
                        # encrypted chunk: nonce(12) + ciphertext
                        nonce = security.make_nonce(counter)
                        counter += 1
                        chunk = security.aesgcm_decrypt(keys.key, nonce, enc, aad=b"chunk")
                        f.write(chunk)
                        remaining -= len(chunk)
                        done += len(chunk)

                        elapsed = max(0.001, time.time() - start)
                        speed = done / elapsed
                        self.core.update_progress(transfer_id, sender_peer_id, done, speed, status="active")

                end = recv_json(sock)
                if end.get("type") != "FILE_END":
                    raise ConnectionError("protocol error: expected FILE_END")

            elapsed = max(0.001, time.time() - start)
            speed = done / elapsed
            self.core.update_progress(transfer_id, sender_peer_id, done, speed, status="completed")
            self.core.finalize_transfer(transfer_id, "receive", [sender_name], len(offer.files), total_bytes, "completed", speed)

        except Exception as e:
            elapsed = max(0.001, time.time() - start)
            speed = done / elapsed
            self.core.update_progress(transfer_id, sender_peer_id, done, speed, status="error", error=str(e))
            self.core.finalize_transfer(transfer_id, "receive", [sender_name], len(offer.files), total_bytes, "error", speed, error=str(e))
        finally:
            try:
                sock.close()
            except Exception:
                pass

    # ---------- sending ----------

    def send_files(self, transfer_id: str, peer_ip: str, peer_tcp_port: int, peer_id: str, peer_name: str, files: List[str]) -> None:
        """
        Sends one transfer to one peer in a thread. App will call this multiple times for multiple receivers,
        but limits are enforced by Core/config in app.py.
        """
        t = threading.Thread(
            target=self._send_files_thread,
            args=(transfer_id, peer_ip, peer_tcp_port, peer_id, peer_name, files),
            daemon=True,
        )
        t.start()
        with self._active_lock:
            self._active_threads.append(t)

    def _send_files_thread(self, transfer_id: str, peer_ip: str, peer_tcp_port: int, peer_id: str, peer_name: str, files: List[str]) -> None:
        cfg = self.core.cfg
        timeout = float(cfg["network"]["connect_timeout_sec"])
        profile = self.core.get_profile()

        # Build offer metadata
        file_meta: List[dict] = []
        total_bytes = 0
        for p in files:
            try:
                st = os.stat(p)
                size = int(st.st_size)
            except Exception:
                continue
            name = os.path.basename(p)
            file_meta.append({"name": name, "size": size})
            total_bytes += size

        # init progress entry if not already
        # (Core.init_transfer is done by app for all receivers; safe to update anyway)
        start = time.time()
        done = 0

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        try:
            sock.connect((peer_ip, peer_tcp_port))
            sock.settimeout(15.0)

            our_pub = security.load_identity_public_bytes()
            send_json(sock, {
                "type": "HELLO",
                "username": profile["username"],
                "tcp_port": int(cfg["network"]["tcp_port"]),
                "identity_pub_hex": our_pub.hex(),
            })
            hello_ok = recv_json(sock)
            if hello_ok.get("type") != "HELLO_OK":
                raise ConnectionError("peer did not accept HELLO")

            peer_identity_pub = bytes.fromhex(hello_ok.get("identity_pub_hex", "")) if hello_ok.get("identity_pub_hex") else b""

            # Offer
            send_json(sock, {
                "type": "TRANSFER_OFFER",
                "transfer_id": transfer_id,
                "files": file_meta,
                "total_bytes": total_bytes,
            })
            resp = recv_json(sock)
            if resp.get("type") != "TRANSFER_RESPONSE" or not resp.get("accept", False):
                self.core.update_progress(transfer_id, peer_id, 0, 0.0, status="rejected", error=str(resp.get("reason", "rejected")))
                self.core.finalize_transfer(transfer_id, "send", [peer_name], len(file_meta), total_bytes, "canceled", 0.0, error="rejected")
                return

            # Handshake
            # Sender waits HS1 (receiver eph), then replies HS2 (sender eph + salt)
            hs1 = recv_json(sock)
            if hs1.get("type") != "HS1":
                raise ConnectionError("handshake failed (HS1)")
            recv_eph_pub = bytes.fromhex(hs1["eph_pub_hex"])
            sender_eph_sk, sender_eph_pk = security.generate_ephemeral()
            salt = os.urandom(16)

            send_json(sock, {"type": "HS2", "eph_pub_hex": sender_eph_pk.hex(), "salt_hex": salt.hex()})
            shared = security.compute_shared_secret(sender_eph_sk, recv_eph_pub)
            keys = security.derive_session_key(shared, salt)

            # Stream files
            counter = 1
            for meta, path in zip(file_meta, files):
                name = meta["name"]
                size = meta["size"]

                send_json(sock, {"type": "FILE_BEGIN", "name": name, "size": size})
                with open(path, "rb") as f:
                    while True:
                        chunk = f.read(int(cfg["limits"]["chunk_size_kb"]) * 1024)
                        if not chunk:
                            break
                        nonce = security.make_nonce(counter)
                        counter += 1
                        enc = security.aesgcm_encrypt(keys.key, nonce, chunk, aad=b"chunk")
                        send_bin(sock, enc)

                        done += len(chunk)
                        elapsed = max(0.001, time.time() - start)
                        speed = done / elapsed
                        self.core.update_progress(transfer_id, peer_id, done, speed, status="active")

                send_json(sock, {"type": "FILE_END", "name": name})

            send_json(sock, {"type": "DONE"})
            elapsed = max(0.001, time.time() - start)
            speed = done / elapsed
            self.core.update_progress(transfer_id, peer_id, done, speed, status="completed")
            self.core.finalize_transfer(transfer_id, "send", [peer_name], len(file_meta), total_bytes, "completed", speed)

        except Exception as e:
            elapsed = max(0.001, time.time() - start)
            speed = done / elapsed
            self.core.update_progress(transfer_id, peer_id, done, speed, status="error", error=str(e))
            self.core.finalize_transfer(transfer_id, "send", [peer_name], len(file_meta), total_bytes, "error", speed, error=str(e))
        finally:
            try:
                sock.close()
            except Exception:
                pass
