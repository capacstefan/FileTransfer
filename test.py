"""
p2p_wifidirect_udp_tcp.py
P2P file transfer for Windows Wi-Fi Direct networks using UDP discovery + TCP transfer.
Features:
 - Discovery: UDP broadcast advertising + listening (continual), devices appear live in UI.
 - Transfer: TCP stream, chunk size 64 bytes.
 - Security: X25519 (ECDH) -> HKDF -> AES-GCM. PIN (6 digits) derived from shared secret for manual verification.
 - Accept/Reject: receiver is prompted to accept or reject incoming transfer.
 - UI: customtkinter + tkinter Listbox for device listing and file dialogs.
 - Received files saved to ./received_files
"""

import os
import socket
import threading
import time
import struct
import json
import hashlib
from pathlib import Path
from queue import Queue, Empty
import tkinter as tk
from tkinter import filedialog, messagebox
import customtkinter as ctk

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# ----------------------
# Config
# ----------------------
UDP_PORT = 37020
TCP_PORT = 50000
BROADCAST_INTERVAL = 1.0
DISCOVERY_TIMEOUT = 6.0
CHUNK_SIZE = 64  # EXACT requirement
RECV_DIR = Path("received_files")
RECV_DIR.mkdir(exist_ok=True)
DISPLAY_NAME = socket.gethostname()
# ----------------------

def derive_key(shared_secret: bytes) -> bytes:
    hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"p2p-file-transfer")
    return hkdf.derive(shared_secret)

def compute_pin(shared_secret: bytes, window_seconds: int = 60) -> str:
    now_window = int(time.time() // window_seconds)
    h = hashlib.sha256(shared_secret + now_window.to_bytes(8, "big")).digest()
    pin = int.from_bytes(h, "big") % 1000000
    return f"{pin:06d}"

# ----------------------
# Networking: Discovery (UDP broadcast + listener)
# ----------------------
class Discovery:
    def __init__(self, display_name=DISPLAY_NAME, udp_port=UDP_PORT, tcp_port=TCP_PORT):
        self.display_name = display_name
        self.udp_port = udp_port
        self.tcp_port = tcp_port
        self.running = False
        self.devices = {}  # ip -> (name, last_seen, tcp_port)
        self.lock = threading.Lock()

    def start(self):
        self.running = True
        threading.Thread(target=self._broadcaster, daemon=True).start()
        threading.Thread(target=self._listener, daemon=True).start()
        threading.Thread(target=self._reaper, daemon=True).start()

    def stop(self):
        self.running = False

    def _broadcaster(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        payload = {"name": self.display_name, "tcp_port": self.tcp_port}
        encoded = json.dumps(payload).encode("utf-8")
        while self.running:
            try:
                s.sendto(encoded, ("<broadcast>", self.udp_port))
            except Exception:
                pass
            time.sleep(BROADCAST_INTERVAL)

    def _listener(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.bind(("", self.udp_port))
        except Exception as e:
            print("Discovery bind error:", e)
            return
        s.settimeout(1.0)
        my_ips = self._get_local_ips()
        while self.running:
            try:
                data, addr = s.recvfrom(4096)
                ip = addr[0]
                if ip in my_ips:
                    continue
                try:
                    info = json.loads(data.decode("utf-8"))
                    name = info.get("name", ip)
                    tcp_port = int(info.get("tcp_port", TCP_PORT))
                except Exception:
                    name = ip
                    tcp_port = TCP_PORT
                with self.lock:
                    self.devices[ip] = (name, time.time(), tcp_port)
            except socket.timeout:
                continue
            except Exception:
                continue

    def _reaper(self):
        while self.running:
            now = time.time()
            with self.lock:
                stale = [ip for ip, v in self.devices.items() if now - v[1] > DISCOVERY_TIMEOUT]
                for ip in stale:
                    del self.devices[ip]
            time.sleep(1.0)

    def get_devices(self):
        with self.lock:
            return [(ip, info[0], info[2]) for ip, info in self.devices.items()]

    def _get_local_ips(self):
        ips = set()
        try:
            hostname = socket.gethostname()
            for res in socket.getaddrinfo(hostname, None):
                ips.add(res[4][0])
        except Exception:
            pass
        # also try the common trick
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ips.add(s.getsockname()[0])
            s.close()
        except Exception:
            pass
        if not ips:
            ips.add("127.0.0.1")
        return ips

# ----------------------
# TCP server: accept incoming connections
# ----------------------
class ReceiverServer:
    def __init__(self, port: int, on_conn):
        self.port = port
        self.on_conn = on_conn
        self.running = False
        self.sock = None

    def start(self):
        self.running = True
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.bind(("", self.port))
            s.listen(5)
            s.settimeout(1.0)
            self.sock = s
            while self.running:
                try:
                    conn, addr = s.accept()
                    threading.Thread(target=self.on_conn, args=(conn, addr), daemon=True).start()
                except socket.timeout:
                    continue
                except Exception:
                    continue
        except Exception as e:
            print("Receiver server error:", e)
        finally:
            try:
                s.close()
            except:
                pass

    def stop(self):
        self.running = False
        try:
            if self.sock:
                self.sock.close()
        except:
            pass

# ----------------------
# Protocol helpers: length-prefixed messages
# ----------------------
def send_with_len(sock: socket.socket, bts: bytes):
    sock.sendall(struct.pack("!I", len(bts)) + bts)

def recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("Connection closed")
        buf += chunk
    return buf

def recv_with_len(sock: socket.socket) -> bytes:
    header = recv_exact(sock, 4)
    (l,) = struct.unpack("!I", header)
    if l == 0:
        return b""
    return recv_exact(sock, l)

# ----------------------
# Incoming connection handler (handshake only) - executed in server thread
# ----------------------
def handle_incoming_handshake(conn: socket.socket, addr, ui_queue: Queue):
    try:
        # receive sender public key
        peer_pub_bytes = recv_with_len(conn)
        peer_pub = X25519PublicKey.from_public_bytes(peer_pub_bytes)
        # create own key, send public
        priv = X25519PrivateKey.generate()
        my_pub_bytes = priv.public_key().public_bytes()
        send_with_len(conn, my_pub_bytes)
        shared = priv.exchange(peer_pub)
        key = derive_key(shared)
        pin = compute_pin(shared)
        # notify UI: incoming offer; UI will accept/reject and then call proceed_receive if accept
        ui_queue.put(("incoming_offer", addr[0], pin, shared, key, conn))
        return
    except Exception as e:
        try:
            conn.close()
        except:
            pass

# ----------------------
# After UI accepts: proceed to receive files on that connection
# ----------------------
def proceed_receive(conn: socket.socket, addr_ip: str, shared: bytes, key: bytes, ui_queue: Queue):
    try:
        aesgcm = AESGCM(key)
        # Wait for encrypted ACCEPT/REJECT from receiver in previous code? In our flow, receiver already sent ACCEPT encrypted.
        # However in this implementation: after UI accept we send encrypted ACCEPT back to sender — but the sender expects an encrypted acknowledgement.
        # To simplify: receiver already sent ACCEPT encrypted in UI handler. Now proceed to read metadata.
        # First: read number of files (length-prefixed 4-byte)
        raw = recv_with_len(conn)
        if not raw:
            raise ConnectionError("No metadata (num_files) received")
        (num_files,) = struct.unpack("!I", raw)
        for _ in range(num_files):
            meta = recv_with_len(conn)
            fname_len = struct.unpack("!H", meta[:2])[0]
            fname = meta[2:2+fname_len].decode("utf-8")
            fsize = struct.unpack("!Q", meta[2+fname_len:2+fname_len+8])[0]
            out_path = RECV_DIR / fname
            # Ensure no directory traversal
            out_path = out_path.resolve()
            if not str(out_path).startswith(str(RECV_DIR.resolve())):
                raise PermissionError("Invalid filename from sender")
            with open(out_path, "wb") as f:
                received = 0
                while True:
                    payload = recv_with_len(conn)
                    if payload == b"":
                        break
                    nonce = payload[:12]
                    ciphertext = payload[12:]
                    chunk = aesgcm.decrypt(nonce, ciphertext, None)
                    f.write(chunk)
                    received += len(chunk)
                    ui_queue.put(("progress_inc", len(chunk)))
            ui_queue.put(("received_file", str(out_path)))
        final = recv_with_len(conn)
        if final == b"__TRANSFER_DONE__":
            ui_queue.put(("receive_done", addr_ip))
        conn.close()
    except Exception as e:
        ui_queue.put(("receive_error", f"{addr_ip}: {e}"))
        try:
            conn.close()
        except:
            pass

# ----------------------
# Sender flow: connect, handshake, wait for accept (encrypted), then send files chunked
# ----------------------
def send_files(target_ip: str, target_port: int, filepaths: list, ui_queue: Queue):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        sock.connect((target_ip, target_port))
        sock.settimeout(None)
        # handshake: send my pub, receive peer pub
        priv = X25519PrivateKey.generate()
        my_pub = priv.public_key().public_bytes()
        send_with_len(sock, my_pub)
        peer_pub_bytes = recv_with_len(sock)
        peer_pub = X25519PublicKey.from_public_bytes(peer_pub_bytes)
        shared = priv.exchange(peer_pub)
        key = derive_key(shared)
        pin = compute_pin(shared)
        # ask UI to show PIN and wait for user confirm that receiver showed same PIN -> UI will send accept boolean through queue
        resp_q = Queue()
        ui_queue.put(("outgoing_pin", target_ip, pin, resp_q))
        try:
            accepted = resp_q.get(timeout=60)
        except Empty:
            sock.close()
            ui_queue.put(("send_error", f"{target_ip}: timeout waiting for local confirmation"))
            return
        if not accepted:
            sock.close()
            ui_queue.put(("send_error", f"{target_ip}: sending canceled by user"))
            return
        # Wait for receiver's encrypted ACCEPT message (receiver will encrypt "ACCEPT" with AESGCM using derived key)
        # We'll read a length-prefixed payload, decrypt and check
        enc = recv_with_len(sock)
        if not enc:
            sock.close()
            ui_queue.put(("send_error", f"{target_ip}: no accept message"))
            return
        try:
            aesgcm = AESGCM(key)
            nonce = (0).to_bytes(12, "big")
            dec = aesgcm.decrypt(nonce, enc, None)
            if dec != b"ACCEPT":
                sock.close()
                ui_queue.put(("send_error", f"{target_ip}: receiver rejected"))
                return
        except Exception:
            sock.close()
            ui_queue.put(("send_error", f"{target_ip}: decryption error or reject"))
            return
        # send number of files
        send_with_len(sock, struct.pack("!I", len(filepaths)))
        # total bytes for progress
        total_bytes = sum(os.path.getsize(p) for p in filepaths)
        ui_queue.put(("set_progress_total", total_bytes))
        for path in filepaths:
            fname = os.path.basename(path)
            bname = fname.encode("utf-8")
            meta = struct.pack("!H", len(bname)) + bname + struct.pack("!Q", os.path.getsize(path))
            send_with_len(sock, meta)
            nonce_counter = 1  # start from 1, since 0 is used for ACCEPT/REJECT
            with open(path, "rb") as f:
                while True:
                    chunk = f.read(CHUNK_SIZE)
                    if not chunk:
                        break
                    nonce = nonce_counter.to_bytes(12, "big")
                    ciphertext = aesgcm.encrypt(nonce, chunk, None)
                    payload = nonce + ciphertext
                    send_with_len(sock, payload)
                    ui_queue.put(("progress_inc", len(chunk)))
                    nonce_counter += 1
            # end-of-file marker
            send_with_len(sock, b"")
        # final marker
        send_with_len(sock, b"__TRANSFER_DONE__")
        sock.close()
        ui_queue.put(("send_ok", f"Sent {len(filepaths)} file(s) to {target_ip}"))
    except Exception as e:
        ui_queue.put(("send_error", f"{target_ip}: {e}"))
        try:
            sock.close()
        except:
            pass

# ----------------------
# UI (customtkinter)
# ----------------------
class App:
    def __init__(self, root):
        self.root = root
        ctk.set_appearance_mode("System")
        ctk.set_default_color_theme("blue")
        root.title("P2P Wi-Fi Direct File Transfer")
        root.geometry("720x460")
        self.uiq = Queue()

        # Discovery + server
        self.discovery = Discovery()
        self.discovery.start()
        self.receiver = ReceiverServer(TCP_PORT, lambda conn, addr: handle_incoming_handshake(conn, addr, self.uiq))
        self.receiver.start()

        # files to send
        self.files = []
        self.progress_total = 0
        self.progress_val = 0

        self._build_ui()
        self.root.after(200, self._process_uiq)

    def _build_ui(self):
        frame = ctk.CTkFrame(self.root, corner_radius=12)
        frame.pack(fill="both", expand=True, padx=12, pady=12)

        top = ctk.CTkFrame(frame, fg_color="transparent")
        top.pack(fill="both", expand=True)

        left = ctk.CTkFrame(top, corner_radius=8)
        left.pack(side="left", fill="both", padx=(0,12))
        lbl = ctk.CTkLabel(left, text="Dispozitive descoperite", font=ctk.CTkFont(size=14, weight="bold"))
        lbl.pack(padx=8, pady=(6,2))
        self.listbox = tk.Listbox(left, width=34)
        self.listbox.pack(padx=8, pady=6, fill="both", expand=True)
        refresh = ctk.CTkButton(left, text="Refresh", command=self._refresh_devices)
        refresh.pack(padx=8, pady=6)

        right = ctk.CTkFrame(top, corner_radius=8)
        right.pack(side="left", fill="both", expand=True)
        lblf = ctk.CTkLabel(right, text="Fișiere de trimis", font=ctk.CTkFont(size=14, weight="bold"))
        lblf.pack(padx=8, pady=(6,2))
        self.files_listbox = tk.Listbox(right)
        self.files_listbox.pack(padx=8, pady=6, fill="both", expand=True)
        btnf = ctk.CTkFrame(right, fg_color="transparent")
        btnf.pack(fill="x", padx=8, pady=6)
        add_btn = ctk.CTkButton(btnf, text="Adaugă fișiere", command=self._add_files)
        add_btn.pack(side="left", padx=(0,6))
        rem_btn = ctk.CTkButton(btnf, text="Șterge select", command=self._remove_selected_files)
        rem_btn.pack(side="left")
        send_btn = ctk.CTkButton(btnf, text="Trimite la selectat", fg_color="#2b8cff", command=self._start_send)
        send_btn.pack(side="right")

        bottom = ctk.CTkFrame(frame, corner_radius=8)
        bottom.pack(fill="x", pady=(12,0))
        self.status = ctk.CTkLabel(bottom, text="Idle", anchor="w")
        self.status.pack(side="left", padx=8)
        self.progress = ctk.CTkProgressBar(bottom)
        self.progress.set(0.0)
        self.progress.pack(side="right", padx=8, pady=8, fill="x", expand=True)

    def _refresh_devices(self):
        self.listbox.delete(0, tk.END)
        devs = self.discovery.get_devices()
        for ip, name, port in devs:
            self.listbox.insert(tk.END, f"{name} — {ip}:{port}")

    def _add_files(self):
        paths = filedialog.askopenfilenames(title="Alege fișiere")
        for p in paths:
            if p not in self.files:
                self.files.append(p)
                self.files_listbox.insert(tk.END, p)
        self._set_status(f"{len(self.files)} fișier(e) pregătite")

    def _remove_selected_files(self):
        sel = list(self.files_listbox.curselection())
        sel.reverse()
        for i in sel:
            self.files_listbox.delete(i)
            del self.files[i]
        self._set_status(f"{len(self.files)} fișier(e) rămase")

    def _start_send(self):
        sel = self.listbox.curselection()
        if not sel:
            messagebox.showinfo("Selectează", "Selectează un dispozitiv din listă.")
            return
        idx = sel[0]
        item = self.listbox.get(idx)
        parts = item.split("—")[-1].strip()
        if ":" in parts:
            ip, port = parts.split(":")
            ip = ip.strip(); port = int(port)
        else:
            ip = parts; port = TCP_PORT
        if not self.files:
            messagebox.showinfo("Fișiere", "Adaugă fișiere de trimis.")
            return
        # start thread
        threading.Thread(target=send_files, args=(ip, port, list(self.files), self.uiq), daemon=True).start()
        self._set_status(f"Trimitere către {ip}...")

    def _process_uiq(self):
        try:
            while True:
                ev = self.uiq.get_nowait()
                self._handle(ev)
        except Empty:
            pass
        # periodic refresh of devices
        self._refresh_devices()
        self.root.after(700, self._process_uiq)

    def _handle(self, ev):
        typ = ev[0]
        if typ == "incoming_offer":
            _, ip, pin, shared, key, conn = ev
            # Prompt user in UI thread
            def prompt():
                ans = messagebox.askyesno("Oferta de transfer",
                                          f"Dispozitiv {ip} încearcă să trimită fișiere.\nPIN: {pin}\nAcceptați?")
                aesgcm = AESGCM(key)
                nonce = (0).to_bytes(12, "big")
                if ans:
                    # send encrypted ACCEPT
                    try:
                        payload = aesgcm.encrypt(nonce, b"ACCEPT", None)
                        send_with_len(conn, payload)
                    except Exception:
                        try: conn.close()
                        except: pass
                        self._set_status("Eroare la trimitere ACCEPT")
                        return
                    # begin receiving in background
                    threading.Thread(target=proceed_receive, args=(conn, ip, shared, key, self.uiq), daemon=True).start()
                    self._set_status(f"Acceptat transfer de la {ip}")
                    # reset progress
                    self.progress_total = 0
                    self.progress_val = 0
                    self._set_progress(0.0)
                else:
                    try:
                        payload = aesgcm.encrypt(nonce, b"REJECT", None)
                        send_with_len(conn, payload)
                    except:
                        pass
                    try:
                        conn.close()
                    except:
                        pass
                    self._set_status(f"Refuzat transfer de la {ip}")
            self.root.after(10, prompt)

        elif typ == "outgoing_pin":
            _, ip, pin, resp_q = ev
            def ask():
                ans = messagebox.askyesno("Confirmare PIN",
                                          f"PIN pentru conexiunea cu {ip}:\n{pin}\nConfirmi că PIN-ul afișat pe dispozitivul receptor este același?")
                resp_q.put(ans)
            self.root.after(10, ask)

        elif typ == "set_progress_total":
            _, total = ev
            self.progress_total = total
            self.progress_val = 0
            self._set_progress(0.0)

        elif typ == "progress_inc":
            _, n = ev
            if self.progress_total > 0:
                self.progress_val += n
                frac = min(1.0, self.progress_val / self.progress_total)
                self._set_progress(frac)
            else:
                # indeterminate-ish
                self.progress_val = (self.progress_val + n) % 1000
                self._set_progress((self.progress_val % 100) / 100.0)

        elif typ == "send_ok":
            _, msg = ev
            messagebox.showinfo("Trimis", msg)
            self._set_status(msg)
            self.files = []
            self.files_listbox.delete(0, tk.END)
            self._set_progress(0.0)

        elif typ == "send_error":
            _, msg = ev
            messagebox.showerror("Eroare trimitere", msg)
            self._set_status(msg)
            self._set_progress(0.0)

        elif typ == "received_file":
            _, path = ev
            self._set_status(f"Fișier salvat: {path}")

        elif typ == "receive_done":
            _, ip = ev
            messagebox.showinfo("Recepție completă", f"Recepție finalizată de la {ip}")
            self._set_status("Idle")
            self._set_progress(0.0)

        elif typ == "receive_error":
            _, msg = ev
            messagebox.showerror("Eroare recepție", msg)
            self._set_status(msg)
            self._set_progress(0.0)

    def _set_status(self, text):
        try:
            self.status.configure(text=text)
        except Exception:
            pass

    def _set_progress(self, frac: float):
        try:
            self.progress.set(frac)
        except Exception:
            pass

def main():
    root = ctk.CTk()
    app = App(root)
    def on_close():
        if messagebox.askokcancel("Ieșire", "Dorești să închizi aplicația?"):
            try:
                app.discovery.stop()
                app.receiver.stop()
            except:
                pass
            root.destroy()
    root.protocol("WM_DELETE_WINDOW", on_close)
    root.mainloop()

if __name__ == "__main__":
    main()
