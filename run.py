import socket
import threading
import time
import os
import sys
import struct
import hashlib
import queue
from tkinter import Listbox, END
import customtkinter as ctk

# ==========================
# Config simple
# ==========================
APP_NAME = "Fishare"
ADVERTISING_PORT = 50000          # UDP broadcast pentru advertising
TRANSFER_PORT = 50010             # TCP server pentru transfer
ADVERTISING_INTERVAL = 1.0        # secunde
SCAN_CLEANUP_SECONDS = 10         # sterge device-urile inactive
CHUNK_SIZE = 64 * 1024            # 64KB
PIN_ROTATE_SECONDS = 180          # 3 minute
AES_NONCE_SIZE = 12               # AES-GCM standard
UI_REFRESH_MS = 500               # tick UI
SALT = b"FishareSaltV1"           # salt fix pentru derivarea cheii din PIN

# ==========================
# Cryptography (AES-GCM)
# ==========================
try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.backends import default_backend
except ImportError:
    print("E nevoie de cryptography: pip install cryptography")
    sys.exit(1)

def derive_key_from_pin(pin_str: str) -> bytes:
    """
    Deriva o cheie AES-256 (32 bytes) din PIN-ul dinamic + SALT, prin PBKDF2-HMAC-SHA256.
    Iteratii moderate pentru MVP.
    """
    pin_bytes = pin_str.encode("utf-8")
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=SALT, iterations=100_000, backend=default_backend())
    return kdf.derive(pin_bytes)

def aesgcm_encrypt(key: bytes, nonce: bytes, plaintext: bytes, aad: bytes = b"") -> bytes:
    """
    AES-GCM: encrypt returns ciphertext + tag concatenat.
    Protocol: trimitem [len 4B big-endian][cipher_with_tag]
    """
    aesgcm = AESGCM(key)
    return aesgcm.encrypt(nonce, plaintext, aad if aad else None)

def aesgcm_decrypt(key: bytes, nonce: bytes, cipher_with_tag: bytes, aad: bytes = b"") -> bytes:
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, cipher_with_tag, aad if aad else None)

# ==========================
# PIN dinamic (seed + timp)
# ==========================
"""
Elimina “secret” global. Utilizatorul introduce un PIN seed (de ex. 6-8 cifre).
PIN-ul dinamic afisat/folosit se calculeaza determinist la fiecare fereastra de 3 minute:

dynamic_pin = SHA256(seed + ":" + window_index) % 1_000_000 (6 cifre)

Astfel, ambele device-uri care au același seed și timp rezonabil sincronizat
vor avea același PIN dinamic în fereastra curentă. Cheia AES se derivă din PIN-ul dinamic + SALT.
"""

def current_window_index() -> int:
    return int(time.time() // PIN_ROTATE_SECONDS)

def dynamic_pin(seed: str) -> str:
    win_idx = current_window_index()
    data = f"{seed}:{win_idx}".encode("utf-8")
    digest = hashlib.sha256(data).digest()
    pin6 = int.from_bytes(digest[:4], "big") % 1_000_000
    return f"{pin6:06d}"

def seconds_until_next_window() -> int:
    now = int(time.time())
    return PIN_ROTATE_SECONDS - (now % PIN_ROTATE_SECONDS)

# ==========================
# Protocol
# ==========================
"""
TCP Protocol:

Handshake:
Client -> Server:
  [magic "FSHR" 4B][proto_ver 1B=1][session_nonce 12B][pin_window_index 8B]
Server -> Client:
  [magic "FSOK" 4B]

Pentru fiecare fișier:
Header (AES-GCM, AAD="FILEHDR", nonce=make_nonce):
  Plaintext:
    [name_len 2B][name ...][file_size 8B]
Trimitem: [len 4B][cipher_with_tag]

Chunk-uri (AES-GCM, AAD="FILECHK"):
  Plaintext:
    [offset 8B][data]
Trimitem: [len 4B][cipher_with_tag]

Final (AES-GCM, AAD="FILEEND"):
  Plaintext:
    [file_size 8B]
Trimitem: [len 4B][cipher_with_tag]

Nonce per pachet: derivat din session_nonce si counter monoton.
"""

MAGIC_REQ = b"FSHR"
MAGIC_OK = b"FSOK"
PROTOCOL_VERSION = 1

def make_nonce(session_nonce: bytes, counter: int) -> bytes:
    # 12 bytes total: primii 8 = XOR(session_nonce[:8], counter_be), ultimii 4 = session_nonce[8:12]
    counter_bytes = struct.pack(">Q", counter)
    p8 = bytes(a ^ b for a, b in zip(session_nonce[:8], counter_bytes))
    return p8 + session_nonce[8:12]

# ==========================
# Advertising / Scan
# ==========================
def get_local_hostname():
    try:
        return socket.gethostname()
    except:
        return "unknown"

def get_local_ip_for_broadcast():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
    except:
        ip = "127.0.0.1"
    finally:
        s.close()
    return ip

def advertising_loop(stop_event: threading.Event, name: str):
    ip = get_local_ip_for_broadcast()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    msg_base = f"{APP_NAME}|{name}|{ip}|{TRANSFER_PORT}".encode("utf-8")
    while not stop_event.is_set():
        try:
            sock.sendto(msg_base, ("255.255.255.255", ADVERTISING_PORT))
        except Exception:
            pass
        time.sleep(ADVERTISING_INTERVAL)
    sock.close()

def scan_loop(stop_event: threading.Event, devices: dict, devices_lock: threading.Lock, events_q: queue.Queue):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.bind(("", ADVERTISING_PORT))
    except Exception:
        for p in range(ADVERTISING_PORT, ADVERTISING_PORT + 10):
            try:
                sock.bind(("", p))
                break
            except:
                continue
    sock.settimeout(0.5)
    last_cleanup = time.time()
    while not stop_event.is_set():
        try:
            data, addr = sock.recvfrom(1024)
            text = data.decode("utf-8", errors="ignore")
            parts = text.split("|")
            if len(parts) == 4 and parts[0] == APP_NAME:
                name = parts[1]
                ip = parts[2]
                port = int(parts[3])
                with devices_lock:
                    devices[(ip, port)] = {"name": name, "last": time.time()}
                events_q.put(("devices_updated", None))
        except socket.timeout:
            pass
        except Exception:
            pass

        # cleanup
        if time.time() - last_cleanup > 2:
            with devices_lock:
                now = time.time()
                to_del = [k for k, v in devices.items() if now - v["last"] > SCAN_CLEANUP_SECONDS]
                for k in to_del:
                    del devices[k]
            last_cleanup = time.time()
    sock.close()

# ==========================
# TCP server (primire)
# ==========================
def ensure_received_dir():
    try:
        os.makedirs("received", exist_ok=True)
    except Exception:
        pass

def tcp_server_loop(stop_event: threading.Event, pin_seed_getter, events_q: queue.Queue):
    ensure_received_dir()
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("", TRANSFER_PORT))
    srv.listen(5)
    srv.settimeout(0.5)

    def handle_client(conn, addr):
        try:
            hdr = conn.recv(4 + 1 + AES_NONCE_SIZE + 8)
            if len(hdr) < (4 + 1 + AES_NONCE_SIZE + 8):
                conn.close()
                return
            magic = hdr[:4]
            ver = hdr[4]
            session_nonce = hdr[5:5+AES_NONCE_SIZE]
            pin_window_index = struct.unpack(">Q", hdr[5+AES_NONCE_SIZE:5+AES_NONCE_SIZE+8])[0]
            if magic != MAGIC_REQ or ver != PROTOCOL_VERSION:
                conn.close()
                return

            # Derivam PIN dinamic din seed-ul local (acelasi pe ambele, ideal)
            seed = pin_seed_getter()
            pin_val = dynamic_pin(seed)
            key = derive_key_from_pin(pin_val)

            conn.sendall(MAGIC_OK)

            counter = 1
            while True:
                # Header fisier: [len 4B][cipher_with_tag]
                raw = recvall(conn, 4)
                if not raw:
                    break
                clen = struct.unpack(">I", raw)[0]
                cipher = recvall(conn, clen)
                if cipher is None or len(cipher) < clen:
                    break

                nonce = make_nonce(session_nonce, counter)
                counter += 1
                try:
                    pt = aesgcm_decrypt(key, nonce, cipher, b"FILEHDR")
                except Exception:
                    break

                # parse header
                if len(pt) < 2 + 8:
                    break
                name_len = struct.unpack(">H", pt[:2])[0]
                if len(pt) < 2 + name_len + 8:
                    break
                name = pt[2:2+name_len].decode("utf-8", errors="ignore")
                file_size = struct.unpack(">Q", pt[2+name_len:2+name_len+8])[0]

                safe_name = os.path.basename(name)
                out_path = os.path.join("received", safe_name)
                f = open(out_path, "wb")
                received = 0
                events_q.put(("receive_started", {"name": safe_name, "size": file_size}))

                # chunks
                while received < file_size:
                    raw = recvall(conn, 4)
                    if not raw:
                        break
                    clen = struct.unpack(">I", raw)[0]
                    cipher = recvall(conn, clen)
                    if cipher is None or len(cipher) < clen:
                        break
                    nonce = make_nonce(session_nonce, counter)
                    counter += 1
                    try:
                        pt = aesgcm_decrypt(key, nonce, cipher, b"FILECHK")
                    except Exception:
                        break
                    if len(pt) < 8:
                        break
                    offset = struct.unpack(">Q", pt[:8])[0]
                    data = pt[8:]
                    if offset != received:
                        f.close()
                        try:
                            os.remove(out_path)
                        except:
                            pass
                        break
                    f.write(data)
                    received += len(data)
                    events_q.put(("receive_progress", {"name": safe_name, "received": received, "size": file_size}))

                # final
                raw = recvall(conn, 4)
                if not raw:
                    f.close()
                    continue
                clen = struct.unpack(">I", raw)[0]
                cipher = recvall(conn, clen)
                if cipher is None or len(cipher) < clen:
                    f.close()
                    continue
                nonce = make_nonce(session_nonce, counter)
                counter += 1
                try:
                    pt = aesgcm_decrypt(key, nonce, cipher, b"FILEEND")
                except Exception:
                    f.close()
                    continue
                if len(pt) < 8:
                    f.close()
                    continue
                end_size = struct.unpack(">Q", pt[:8])[0]
                f.flush()
                f.close()
                if end_size != received:
                    try:
                        os.remove(out_path)
                    except:
                        pass
                    events_q.put(("receive_failed", {"name": safe_name}))
                else:
                    events_q.put(("receive_done", {"name": safe_name, "size": received}))
        except Exception:
            pass
        finally:
            try:
                conn.close()
            except:
                pass

    while not stop_event.is_set():
        try:
            conn, addr = srv.accept()
            t = threading.Thread(target=handle_client, args=(conn, addr), daemon=True)
            t.start()
        except socket.timeout:
            pass
        except Exception:
            pass
    srv.close()

def recvall(conn, n) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = conn.recv(n - len(buf))
        if not chunk:
            return None if len(buf) == 0 else buf
        buf += chunk
    return buf

# ==========================
# Client TCP (trimitere)
# ==========================
def send_files(host: str, port: int, files: list, pin_seed_getter, events_q: queue.Queue):
    paths = [p for p in files if os.path.isfile(p)]
    if not paths:
        return

    session_nonce = os.urandom(AES_NONCE_SIZE)
    seed = pin_seed_getter()
    pin_val = dynamic_pin(seed)
    key = derive_key_from_pin(pin_val)
    pin_window_index = current_window_index()

    try:
        conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        conn.settimeout(5)
        conn.connect((host, port))
        conn.sendall(MAGIC_REQ + bytes([PROTOCOL_VERSION]) + session_nonce + struct.pack(">Q", pin_window_index))
        ok = recvall(conn, 4)
        if ok != MAGIC_OK:
            conn.close()
            return
        counter = 1

        for path in paths:
            name = os.path.basename(path)
            size = os.path.getsize(path)
            events_q.put(("send_started", {"name": name, "size": size, "dest": f"{host}:{port}"}))
            name_bytes = name.encode("utf-8")
            hdr_pt = struct.pack(">H", len(name_bytes)) + name_bytes + struct.pack(">Q", size)
            nonce = make_nonce(session_nonce, counter)
            counter += 1
            cipher = aesgcm_encrypt(key, nonce, hdr_pt, b"FILEHDR")
            conn.sendall(struct.pack(">I", len(cipher)) + cipher)

            sent = 0
            with open(path, "rb") as f:
                while sent < size:
                    data = f.read(CHUNK_SIZE)
                    if not data:
                        break
                    pt = struct.pack(">Q", sent) + data
                    nonce = make_nonce(session_nonce, counter)
                    counter += 1
                    cipher = aesgcm_encrypt(key, nonce, pt, b"FILECHK")
                    conn.sendall(struct.pack(">I", len(cipher)) + cipher)
                    sent += len(data)
                    events_q.put(("send_progress", {"name": name, "sent": sent, "size": size, "dest": f"{host}:{port}"}))

            pt = struct.pack(">Q", size)
            nonce = make_nonce(session_nonce, counter)
            counter += 1
            cipher = aesgcm_encrypt(key, nonce, pt, b"FILEEND")
            conn.sendall(struct.pack(">I", len(cipher)) + cipher)
            events_q.put(("send_done", {"name": name, "size": size, "dest": f"{host}:{port}"}))

        conn.close()
    except Exception:
        try:
            conn.close()
        except:
            pass
        events_q.put(("send_failed", {"dest": f"{host}:{port}"}))

# ==========================
# UI (CustomTkinter) – mărită și clară
# ==========================
class FishareApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("dark-blue")
        self.title("Fishare - LAN File Transfer")
        self.geometry("1024x700")
        self.resizable(True, True)

        # State
        self.stop_event = threading.Event()
        self.events_q = queue.Queue()
        self.devices = {}
        self.devices_lock = threading.Lock()
        self.files = []
        self.pin_seed = "123456"  # utilizatorul poate schimba
        self.last_window_idx = current_window_index()

        # Titlu
        self.top_label = ctk.CTkLabel(self, text="FISHARE", font=("Segoe UI", 34, "bold"))
        self.top_label.pack(pady=(16, 10))

        # PIN seed + pin dinamic + countdown
        pin_frame = ctk.CTkFrame(self)
        pin_frame.pack(fill="x", padx=16, pady=(0, 12))

        self.pin_seed_entry = ctk.CTkEntry(pin_frame, placeholder_text="PIN seed (ex. 6-8 cifre)", width=260, font=("Segoe UI", 18))
        self.pin_seed_entry.insert(0, self.pin_seed)
        self.pin_seed_entry.pack(side="left", padx=10, pady=10)

        self.pin_set_btn = ctk.CTkButton(pin_frame, text="Set PIN seed", font=("Segoe UI", 18, "bold"), command=self.on_set_pin_seed)
        self.pin_set_btn.pack(side="left", padx=10)

        self.pin_dynamic_label = ctk.CTkLabel(pin_frame, text=self.pin_dynamic_text(), font=("Segoe UI", 22, "bold"))
        self.pin_dynamic_label.pack(side="left", padx=20)

        self.pin_timer_label = ctk.CTkLabel(pin_frame, text=self.pin_timer_text(), font=("Segoe UI", 18))
        self.pin_timer_label.pack(side="left", padx=12)

        # Zone principale
        mid_frame = ctk.CTkFrame(self)
        mid_frame.pack(fill="both", expand=True, padx=16, pady=10)

        left_frame = ctk.CTkFrame(mid_frame)
        left_frame.pack(side="left", fill="both", expand=True, padx=(10, 6), pady=10)

        right_frame = ctk.CTkFrame(mid_frame)
        right_frame.pack(side="left", fill="both", expand=True, padx=(6, 10), pady=10)

        # Devices
        dev_title = ctk.CTkLabel(left_frame, text="Device-uri disponibile", font=("Segoe UI", 24, "bold"))
        dev_title.pack(pady=(10, 6))
        self.devices_list = Listbox(left_frame, height=16, font=("Segoe UI", 16), activestyle="none")
        self.devices_list.pack(fill="both", expand=True, padx=10, pady=(0, 8))
        self.refresh_btn = ctk.CTkButton(left_frame, text="Refresh lista", font=("Segoe UI", 18, "bold"), command=self.refresh_devices_list)
        self.refresh_btn.pack(pady=(0, 10))

        # Files
        files_title = ctk.CTkLabel(right_frame, text="Fișiere de trimis", font=("Segoe UI", 24, "bold"))
        files_title.pack(pady=(10, 6))
        self.files_list = Listbox(right_frame, height=16, font=("Segoe UI", 16), activestyle="none")
        self.files_list.pack(fill="both", expand=True, padx=10, pady=(0, 8))

        files_btn_frame = ctk.CTkFrame(right_frame)
        files_btn_frame.pack(fill="x", padx=10, pady=(0, 10))
        self.add_file_btn = ctk.CTkButton(files_btn_frame, text="Adaugă fișiere", font=("Segoe UI", 18, "bold"), command=self.on_add_file)
        self.add_file_btn.pack(side="left", padx=6)
        self.clear_files_btn = ctk.CTkButton(files_btn_frame, text="Curăță lista", font=("Segoe UI", 18, "bold"), command=self.on_clear_files)
        self.clear_files_btn.pack(side="left", padx=6)

        # Send
        send_frame = ctk.CTkFrame(self)
        send_frame.pack(fill="x", padx=16, pady=8)
        self.send_btn = ctk.CTkButton(send_frame, text="Trimite către device selectat", font=("Segoe UI", 20, "bold"), command=self.on_send)
        self.send_btn.pack(pady=10)

        # Progress jos
        bottom_frame = ctk.CTkFrame(self, fg_color="#002600")
        bottom_frame.pack(fill="x", padx=0, pady=(6, 0))
        self.progress_label = ctk.CTkLabel(bottom_frame, text="Progres transfer", font=("Segoe UI", 22, "bold"))
        self.progress_label.pack(pady=(8, 4))
        self.progress = ctk.CTkProgressBar(bottom_frame, height=20, progress_color="green")
        self.progress.pack(fill="x", padx=16, pady=(0, 12))
        self.progress.set(0.0)

        # Status
        self.status_label = ctk.CTkLabel(self, text="", font=("Segoe UI", 18))
        self.status_label.pack(pady=(6, 10))

        # Threads
        self.name = get_local_hostname()
        self.stop_event.clear()
        self.advertising_thread = threading.Thread(target=advertising_loop, args=(self.stop_event, self.name), daemon=True)
        self.scan_thread = threading.Thread(target=scan_loop, args=(self.stop_event, self.devices, self.devices_lock, self.events_q), daemon=True)
        self.server_thread = threading.Thread(target=tcp_server_loop, args=(self.stop_event, self.get_pin_seed, self.events_q), daemon=True)

        self.advertising_thread.start()
        self.scan_thread.start()
        self.server_thread.start()

        # UI ticks
        self.after(UI_REFRESH_MS, self.ui_tick)
        self.after(500, self.update_pin_display)

        # Close
        self.protocol("WM_DELETE_WINDOW", self.on_close)

    # ----- PIN seed / afisari -----
    def get_pin_seed(self) -> str:
        return self.pin_seed

    def on_set_pin_seed(self):
        val = self.pin_seed_entry.get().strip()
        if not val:
            self.status("Introdu un PIN seed.")
            return
        self.pin_seed = val
        self.status("PIN seed setat. Folosește același seed pe ambele device-uri.")
        self.update_pin_display()

    def pin_dynamic_text(self) -> str:
        return f"PIN: {dynamic_pin(self.pin_seed)}"

    def pin_timer_text(self) -> str:
        secs = seconds_until_next_window()
        mm = secs // 60
        ss = secs % 60
        return f"Se schimbă în {mm:02d}:{ss:02d}"

    def update_pin_display(self):
        self.pin_dynamic_label.configure(text=self.pin_dynamic_text())
        self.pin_timer_label.configure(text=self.pin_timer_text())
        self.after(500, self.update_pin_display)  # live, din 0.5s

    # ----- Files -----
    def on_add_file(self):
        try:
            from tkinter import filedialog
            paths = filedialog.askopenfilenames(title="Selectează fișiere")
            if paths:
                for p in paths:
                    if os.path.isfile(p):
                        self.files.append(p)
                        self.files_list.insert(END, os.path.basename(p))
                self.status(f"Adăugate {len(paths)} fișiere.")
        except Exception:
            self.status("Nu s-a putut deschide dialogul de fișiere.")

    def on_clear_files(self):
        self.files.clear()
        self.files_list.delete(0, END)
        self.status("Lista de fișiere a fost curățată.")

    # ----- Devices -----
    def refresh_devices_list(self):
        with self.devices_lock:
            items = [f"{v['name']} | {ip}:{port}" for (ip, port), v in self.devices.items()]
        self.devices_list.delete(0, END)
        for it in items:
            self.devices_list.insert(END, it)

    # ----- Send -----
    def on_send(self):
        sel = self.devices_list.curselection()
        if not sel:
            self.status("Selectează un device din listă.")
            return
        item = self.devices_list.get(sel[0])
        try:
            right = item.split("|")[1].strip()
            host, port_s = right.split(":")
            port = int(port_s)
        except Exception:
            self.status("Intrare device invalidă.")
            return
        if not self.files:
            self.status("Lista de fișiere e goală.")
            return
        t = threading.Thread(target=send_files, args=(host, port, self.files.copy(), self.get_pin_seed, self.events_q), daemon=True)
        t.start()
        self.status(f"Pornit transfer către {host}:{port}.")

    # ----- Events & tick -----
    def status(self, msg: str):
        self.status_label.configure(text=msg)

    def ui_tick(self):
        self.refresh_devices_list()
        while True:
            try:
                ev, data = self.events_q.get_nowait()
            except queue.Empty:
                break
            if ev == "devices_updated":
                self.refresh_devices_list()
            elif ev == "send_started":
                name = data["name"]; size = data["size"]; dest = data["dest"]
                self.status(f"Trimit {name} ({size} bytes) către {dest}...")
                self.progress.set(0.0)
            elif ev == "send_progress":
                name = data["name"]; sent = data["sent"]; size = data["size"]
                pct = sent / size if size else 0
                self.progress.set(pct)
                self.status(f"{name}: {sent}/{size} bytes")
            elif ev == "send_done":
                name = data["name"]; size = data["size"]; dest = data["dest"]
                self.progress.set(1.0)
                self.status(f"Trimis {name} ({size} bytes) către {dest}.")
            elif ev == "send_failed":
                dest = data["dest"]
                self.status(f"Transfer către {dest} a eșuat.")
                self.progress.set(0.0)
            elif ev == "receive_started":
                name = data["name"]; size = data["size"]
                self.status(f"Primire {name} ({size} bytes)...")
                self.progress.set(0.0)
            elif ev == "receive_progress":
                name = data["name"]; rec = data["received"]; size = data["size"]
                pct = rec / size if size else 0
                self.progress.set(pct)
                self.status(f"{name}: {rec}/{size} bytes")
            elif ev == "receive_done":
                name = data["name"]; size = data["size"]
                self.progress.set(1.0)
                self.status(f"Primit {name} ({size} bytes). Saved în ./received")
            elif ev == "receive_failed":
                name = data["name"]
                self.progress.set(0.0)
                self.status(f"Primirea pentru {name} a eșuat.")
        self.after(UI_REFRESH_MS, self.ui_tick)

    def on_close(self):
        try:
            self.stop_event.set()
        except:
            pass
        self.after(200, self.destroy)

# ==========================
# Main
# ==========================
if __name__ == "__main__":
    app = FishareApp()
    app.mainloop()
