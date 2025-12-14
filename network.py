import socket
import threading
import struct
import json
import os
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List
import logging

from security import key_agree, sha256_file
from state import AppState, Device, TransferStatus
from history import TransferRecord
from config import Config
from security import Identity, TrustedPeers

logger = logging.getLogger(__name__)

CHUNK_SIZE = 1024 * 1024  # 1MB
STREAMS_PER_FILE = 4      # conexiuni paralele per fișier
MAX_WORKER_THREADS = 16   # pool global pentru toate transferurile


# ==============================
# Multicast Discovery
# ==============================

class Discovery:
    def __init__(self, state: AppState, cfg: Config):
        self.state = state
        self.cfg = cfg
        self.stop_flag = False

    def start(self):
        threading.Thread(target=self._sender, daemon=True).start()
        threading.Thread(target=self._listener, daemon=True).start()

    def _sender(self):
        msg = json.dumps({
            "name": self.state.cfg.device_name,
            "port": self.cfg.listen_port,
            "status": self.state.status
        }).encode()

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)

        while not self.stop_flag:
            sock.sendto(msg, ("239.255.255.250", self.cfg.discovery_port))
            time.sleep(1)

    def _listener(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("", self.cfg.discovery_port))
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP,
                        struct.pack("4sl", socket.inet_aton("239.255.255.250"), socket.INADDR_ANY))

        while not self.stop_flag:
            try:
                data, addr = sock.recvfrom(2048)
                info = json.loads(data.decode())
                dev_id = addr[0]
                dev = Device(dev_id, info["name"], addr[0], info["port"], info["status"])
                self.state.upsert_device(dev)
            except Exception:
                pass


# ==============================
# Transfer Protocol
# ==============================

def _send_json(sock, obj):
    b = json.dumps(obj).encode()
    sock.sendall(struct.pack("!I", len(b)) + b)


def _recv_json(sock):
    header = sock.recv(4)
    if not header:
        return None
    ln = struct.unpack("!I", header)[0]
    buf = b""
    while len(buf) < ln:
        chunk = sock.recv(ln - len(buf))
        if not chunk:
            break
        buf += chunk
    return json.loads(buf.decode())


class TransferService:
    def __init__(self, state: AppState, main_window, history):
        self.state = state
        self.main_window = main_window
        self.history = history
        self.identity = Identity()
        self.identity.load_or_create()
        self.trusted = TrustedPeers()
        
        # Thread pool global pentru toate conexiunile
        self.thread_pool = ThreadPoolExecutor(
            max_workers=MAX_WORKER_THREADS,
            thread_name_prefix="FIshare-Transfer"
        )
        
        # Pornește listener-ul în pool-ul de thread-uri
        self.thread_pool.submit(self._listener)

    # ==========================
    # LISTENER (incoming)
    # ==========================

    def _listener(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind(("", self.state.cfg.listen_port))
        sock.listen(50)
        logger.info(f"Transfer listener started on port {self.state.cfg.listen_port}")

        while True:
            try:
                conn, addr = sock.accept()
                # Folosește thread pool în loc de thread-uri raw
                self.thread_pool.submit(self._handle_incoming, conn, addr)
            except Exception as e:
                logger.error(f"Listener error: {e}")
                break

    def _handle_incoming(self, conn: socket.socket, addr):
        try:
            peer_id = addr[0]
            aead = key_agree(conn, self.identity, self.trusted, peer_id)

            meta = _recv_json(conn)
            if not meta:
                conn.close()
                return

            # UI confirm dialog
            accepted = self.main_window.ask_incoming(
                meta["peer_name"], len(meta["files"]), meta["total_size"]
            )
            _send_json(conn, {"accepted": accepted})
            if not accepted:
                conn.close()
                return

            start_time = time.time()
            sha_ok = True

            self.state.start_transfer(peer_id)

            download_dir = self.state.cfg.download_dir
            os.makedirs(download_dir, exist_ok=True)

            for fmeta in meta["files"]:
                path = os.path.join(download_dir, fmeta["name"])
                temp_path = path + ".part"

                # resume: ce avem deja?
                resume_offset = 0
                if os.path.exists(temp_path):
                    resume_offset = os.path.getsize(temp_path)

                _send_json(conn, {"resume": resume_offset})

                # multi-stream: creează sub-conexiuni
                streams = []
                for _ in range(fmeta["streams"]):
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.connect((addr[0], fmeta["data_port"]))
                    s = self._wrap_aead(s, aead)
                    _send_json(s, {"file_id": fmeta["id"], "offset": resume_offset})
                    streams.append(s)

                # scriere fișier
                with open(temp_path, "ab") as out:
                    received = resume_offset
                    total = fmeta["size"]

                    done_flag = False

                    def receiver_thread(sock_stream):
                        nonlocal received, done_flag
                        while not done_flag:
                            try:
                                chunk = sock_stream.recv(CHUNK_SIZE + 32)
                                if not chunk:
                                    break
                                out.write(chunk)
                                received += len(chunk)
                                ratio = received / total
                                self.state.update_progress(peer_id, ratio, received, "received")
                                if received >= total:
                                    done_flag = True
                                    break
                            except:
                                break

                    # Folosește thread pool pentru receiver threads
                    futures = []
                    for s in streams:
                        future = self.thread_pool.submit(receiver_thread, s)
                        futures.append(future)

                    # Așteaptă finalizarea tuturor stream-urilor
                    for future in as_completed(futures):
                        try:
                            future.result()
                        except Exception as e:
                            logger.error(f"Receiver thread error: {e}")

                # verificare SHA-256
                if os.path.exists(temp_path):
                    if sha256_file(temp_path) == fmeta["sha256"]:
                        os.rename(temp_path, path)
                    else:
                        sha_ok = False
                        os.remove(temp_path)

            duration = time.time() - start_time
            status = "completed" if sha_ok else "error"
            self.state.finish_transfer(peer_id, TransferStatus.COMPLETED if sha_ok else TransferStatus.ERROR)

            rec = TransferRecord(
                timestamp=time.time(),
                direction="received",
                peer_name=meta["peer_name"],
                peer_host=addr[0],
                num_files=len(meta["files"]),
                total_size=meta["total_size"],
                duration=duration,
                status=status,
                sha256_ok=sha_ok
            )
            self.history.add_record(rec)
        except Exception:
            pass
        finally:
            conn.close()

    def _wrap_aead(self, sock: socket.socket, aead):
        """ Returnează un wrapper simplu cu encrypt/decrypt în send/recv. """
        class Wrapped:
            def sendall(self_inner, data):
                sock.sendall(aead.encrypt(data))

            def recv(self_inner, n):
                try:
                    enc = sock.recv(n + 32)
                    if not enc:
                        return b""
                    return aead.decrypt(enc)
                except:
                    return b""

            def close(self_inner):
                sock.close()

        return Wrapped()

    # ==========================
    # SENDER - Multi-peer support
    # ==========================

    def send_to_multiple(self, devices: List[Device], file_paths: List[str]):
        """Trimite fișiere către mai multe dispozitive simultan folosind thread pool."""
        if not devices or not file_paths:
            logger.warning("No devices or files selected")
            return
        
        logger.info(f"Starting multi-peer transfer to {len(devices)} device(s)")
        
        # Lansează transferuri paralele pentru fiecare device
        futures = []
        for device in devices:
            future = self.thread_pool.submit(self._send_to_single, device, file_paths)
            futures.append((device, future))
        
        # Monitorizează progresul
        for device, future in futures:
            try:
                future.result()  # Așteaptă finalizarea
                logger.info(f"Transfer to {device.name} completed")
            except Exception as e:
                logger.error(f"Transfer to {device.name} failed: {e}")
    
    def send_to(self, device: Device, file_paths: List[str]):
        """Wrapper pentru compatibilitate - trimite către un singur device."""
        self.send_to_multiple([device], file_paths)

    def _send_to_single(self, device: Device, file_paths: List[str]):
        """Transferă fișiere către un singur device (rulează în thread pool)."""
        host = device.host
        port = device.port
        total_size = sum(os.path.getsize(f) for f in file_paths)
        
        logger.info(f"Starting transfer to {device.name} ({host}:{port})")

        meta = {
            "peer_name": self.state.cfg.device_name,
            "files": [],
            "total_size": total_size
        }

        # pregătim port data pentru fluxuri paralele
        data_port = port + 1
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.bind(("", data_port))
        listener.listen(50)

        def accept_data():
            while True:
                try:
                    c, a = listener.accept()
                    yield c
                except:
                    break

        accept_iter = accept_data()

        # handshake
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((host, port))
        aead = key_agree(sock, self.identity, self.trusted, device.device_id)

        # pregătim meta per fișier
        for i, path in enumerate(file_paths):
            meta["files"].append({
                "id": i,
                "name": os.path.basename(path),
                "size": os.path.getsize(path),
                "sha256": sha256_file(path),
                "streams": STREAMS_PER_FILE,
                "data_port": data_port
            })

        _send_json(sock, meta)
        resp = _recv_json(sock)
        if not resp or not resp.get("accepted"):
            sock.close()
            return

        self.state.start_transfer(device.device_id)
        start_time = time.time()

        # transfer fișiere
        for fmeta in meta["files"]:
            path = [p for p in file_paths if os.path.basename(p) == fmeta["name"]][0]
            total = fmeta["size"]

            # resume offset
            sock2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock2.connect((host, port))
            aead2 = key_agree(sock2, self.identity, self.trusted, device.device_id)

            info = _recv_json(sock2)  # {"resume": offset}
            sock2.close()

            offset = info["resume"]
            streams = []

            for _ in range(STREAMS_PER_FILE):
                c = next(accept_iter)
                wc = self._wrap_aead(c, aead)
                _send_json(wc, {"file_id": fmeta["id"], "offset": offset})
                streams.append(wc)

            with open(path, "rb") as f:
                f.seek(offset)
                sent = offset

                done_flag = False

                def sender_thread(wrap_sock):
                    nonlocal sent, done_flag
                    while not done_flag:
                        chunk = f.read(CHUNK_SIZE)
                        if not chunk:
                            done_flag = True
                            break
                        try:
                            wrap_sock.sendall(chunk)
                            sent += len(chunk)
                            ratio = sent / total
                            self.state.update_progress(device.device_id, ratio, sent, "sent")
                        except:
                            break

                # Folosește thread pool pentru sender threads
                futures = []
                for w in streams:
                    future = self.thread_pool.submit(sender_thread, w)
                    futures.append(future)

                # Așteaptă finalizarea tuturor stream-urilor
                for future in as_completed(futures):
                    try:
                        future.result()
                    except Exception as e:
                        logger.error(f"Sender thread error: {e}")

        duration = time.time() - start_time
        self.state.finish_transfer(device.device_id, TransferStatus.COMPLETED)

        rec = TransferRecord(
            timestamp=time.time(),
            direction="sent",
            peer_name=device.name,
            peer_host=device.host,
            num_files=len(file_paths),
            total_size=total_size,
            duration=duration,
            status="completed",
            sha256_ok=True
        )
        self.history.add_record(rec)
