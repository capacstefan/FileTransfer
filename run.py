"""
LAN File Transfer — functional, robust version
- PIN generated on receiver (expires after PIN_TTL_SECONDS)
- salt is broadcast together with device info while PIN is valid
- sender reads salt from discovery info and enters PIN manually
- AES-GCM encryption with key derived from PIN+salt (PBKDF2)
- Files sent in 64 KiB chunks
- Progress bar + status messages
- timezone-aware datetimes (no utcnow())
"""

import os
import socket
import threading
import json
import time
import uuid
import struct
import base64
from datetime import datetime, timedelta, timezone
from pathlib import Path
from queue import Queue, Empty

import tkinter as tk
from tkinter import messagebox, filedialog

try:
    import customtkinter as ctk
except Exception as e:
    print("Please install customtkinter: pip install customtkinter")
    raise

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend
import secrets

# ---------------- Configuration ----------------
UDP_PORT = 50000
TCP_PORT = 50010
BCAST_INTERVAL = 1.0           # seconds between broadcasts
DEVICE_CLEANUP = 5.0           # seconds to consider device removed
CHUNK_SIZE = 64 * 1024         # 64 KiB
PIN_TTL_SECONDS = 120          # PIN validity
RECV_DIR = Path("received_files")
RECV_DIR.mkdir(exist_ok=True)

LOCAL_ID = str(uuid.uuid4())
HOSTNAME = socket.gethostname()

# ---------------- Helpers ----------------
def now_iso():
    return datetime.now(timezone.utc).isoformat()

def derive_key(pin_bytes: bytes, salt: bytes, length: int = 32) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        iterations=200_000,
        backend=default_backend()
    )
    return kdf.derive(pin_bytes)

def encrypt_payload(plaintext: bytes, key: bytes) -> bytes:
    aes = AESGCM(key)
    nonce = secrets.token_bytes(12)
    ct = aes.encrypt(nonce, plaintext, None)
    return nonce + ct

def decrypt_payload(payload: bytes, key: bytes) -> bytes:
    aes = AESGCM(key)
    nonce = payload[:12]
    ct = payload[12:]
    return aes.decrypt(nonce, ct, None)

def send_frame(sock: socket.socket, data: bytes):
    sock.sendall(struct.pack("!Q", len(data)) + data)

def recv_all(sock: socket.socket, n: int):
    buf = b''
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf

def recv_frame(sock: socket.socket):
    header = recv_all(sock, 8)
    if not header:
        return None
    length = struct.unpack("!Q", header)[0]
    if length == 0:
        return b''
    return recv_all(sock, length)

def unique_path(p: Path) -> Path:
    if not p.exists():
        return p
    stem = p.stem
    suffix = p.suffix
    i = 1
    while True:
        candidate = p.with_name(f"{stem}_{i}{suffix}")
        if not candidate.exists():
            return candidate
        i += 1

# ---------------- Discovery (advertise + listen) ----------------
class Discovery(threading.Thread):
    def __init__(self, device_queue: Queue, stop_event: threading.Event, receiver_ref=None):
        super().__init__(daemon=True)
        self.device_queue = device_queue
        self.stop_event = stop_event
        self.receiver_ref = receiver_ref  # optional, used to include salt while PIN active
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        self.listen_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.listen_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listen_sock.bind(("", UDP_PORT))
        self.devices = {}  # id -> (info_dict, last_seen_ts)
        self.lock = threading.Lock()

    def run(self):
        # start advertiser in separate thread
        threading.Thread(target=self._advertise_loop, daemon=True).start()
        while not self.stop_event.is_set():
            try:
                self.listen_sock.settimeout(1.0)
                data, addr = self.listen_sock.recvfrom(4096)
            except socket.timeout:
                data = None
            if data:
                try:
                    j = json.loads(data.decode('utf-8', errors='ignore'))
                    dev_id = j.get('id')
                    if dev_id and dev_id != LOCAL_ID:
                        j['addr'] = addr[0]
                        with self.lock:
                            self.devices[dev_id] = (j, time.time())
                        self.device_queue.put(('update', dev_id, j))
                except Exception:
                    pass
            self._cleanup_devices()
        try:
            self.listen_sock.close()
        except Exception:
            pass
        try:
            self.sock.close()
        except Exception:
            pass

    def _advertise_loop(self):
        while not self.stop_event.is_set():
            payload = {
                'id': LOCAL_ID,
                'name': HOSTNAME,
                'tcp_port': TCP_PORT,
                'ts': now_iso()
            }
            # include salt if receiver has a currently valid PIN
            try:
                if self.receiver_ref:
                    pin_state = self.receiver_ref.get_pin_state()
                    if pin_state:
                        _, salt, expiry = pin_state
                        # check expiry using timezone-aware
                        if expiry > datetime.now(timezone.utc):
                            payload['salt'] = base64.b64encode(salt).decode('ascii')
            except Exception:
                pass
            try:
                self.sock.sendto(json.dumps(payload).encode('utf-8'), ('<broadcast>', UDP_PORT))
            except Exception:
                # ignore send errors (network down etc.)
                pass
            time.sleep(BCAST_INTERVAL)

    def _cleanup_devices(self):
        with self.lock:
            dead = [d for d, (_, ts) in self.devices.items() if time.time() - ts > DEVICE_CLEANUP]
            for d in dead:
                del self.devices[d]
                self.device_queue.put(('remove', d, None))

    def get_devices_snapshot(self):
        with self.lock:
            return {k: v[0] for k, v in self.devices.items()}

# ---------------- FileReceiver (server) ----------------
class FileReceiver(threading.Thread):
    def __init__(self, incoming_queue: Queue, stop_event: threading.Event):
        super().__init__(daemon=True)
        self.incoming_queue = incoming_queue
        self.stop_event = stop_event
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("", TCP_PORT))
        self.sock.listen(4)
        # pin_state: (pin_str, salt_bytes, expiry_datetime_tzaware)
        self.pin_state = None
        self.pin_lock = threading.Lock()

    def run(self):
        while not self.stop_event.is_set():
            try:
                self.sock.settimeout(1.0)
                conn, addr = self.sock.accept()
            except socket.timeout:
                continue
            threading.Thread(target=self._handle_conn, args=(conn, addr), daemon=True).start()
        try:
            self.sock.close()
        except Exception:
            pass

    def generate_pin(self):
        pin = f"{secrets.randbelow(10**6):06d}"
        salt = secrets.token_bytes(16)
        expiry = datetime.now(timezone.utc) + timedelta(seconds=PIN_TTL_SECONDS)
        with self.pin_lock:
            self.pin_state = (pin, salt, expiry)
        return pin, salt, expiry

    def clear_pin(self):
        with self.pin_lock:
            self.pin_state = None

    def get_pin_state(self):
        with self.pin_lock:
            return self.pin_state

    def _handle_conn(self, conn: socket.socket, addr):
        try:
            meta_bytes = recv_frame(conn)
            if meta_bytes is None:
                conn.close()
                return
            pin_state = self.get_pin_state()
            # check pin exists and not expired
            if not pin_state or pin_state[2] <= datetime.now(timezone.utc):
                # tell sender the reason and close
                try:
                    conn.sendall(b'REJECT_NO_PIN')
                except Exception:
                    pass
                conn.close()
                return
            pin, salt, expiry = pin_state
            key = derive_key(pin.encode('utf-8'), salt)
            # try to decrypt metadata; if decryption fails -> wrong pin on sender side
            try:
                meta_plain = decrypt_payload(meta_bytes, key)
            except Exception:
                # wrong encryption key (likely wrong PIN provided by sender)
                try:
                    conn.sendall(b'REJECT_BAD_PIN')
                except Exception:
                    pass
                conn.close()
                return
            # parse metadata
            try:
                j = json.loads(meta_plain.decode('utf-8'))
                filename = os.path.basename(j.get('filename', 'received.bin'))
                filesize = int(j.get('filesize', 0))
            except Exception:
                conn.close()
                return
            tmp_path = RECV_DIR / (filename + '.part')
            with open(tmp_path, 'wb') as f:
                received = 0
                while received < filesize:
                    chunk_encrypted = recv_frame(conn)
                    if not chunk_encrypted:
                        break
                    try:
                        chunk = decrypt_payload(chunk_encrypted, key)
                    except Exception:
                        # decryption error mid-stream -> abort
                        try:
                            conn.sendall(b'REJECT_BAD_PIN')
                        except Exception:
                            pass
                        conn.close()
                        return
                    f.write(chunk)
                    received += len(chunk)
            final_path = unique_path(RECV_DIR / filename)
            tmp_path.rename(final_path)
            # notify UI
            self.incoming_queue.put(('received', str(final_path), filesize))
            try:
                conn.sendall(b'OK')
            except Exception:
                pass
            conn.close()
        except Exception as e:
            # log for debug, but keep server alive
            print("Receiver error:", e)
            try:
                conn.close()
            except Exception:
                pass

# ---------------- FileSender ----------------
class FileSender:
    def send_files(self, remote_addr: str, remote_port: int, files: list, pin: str, salt: bytes, progress_callback=None):
        """
        Returns (True, None) on success or (False, error_str) on failure.
        progress_callback expects a float between 0.0 and 1.0
        """
        try:
            key = derive_key(pin.encode('utf-8'), salt)
        except Exception as e:
            return False, f"Key derivation failed: {e}"

        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(10)
            s.connect((remote_addr, remote_port))
        except Exception as e:
            return False, f"Connect failed: {e}"

        total_size = sum(os.path.getsize(p) for p in files)
        sent_total = 0
        try:
            for path in files:
                size = os.path.getsize(path)
                meta = json.dumps({'filename': os.path.basename(path), 'filesize': size}).encode('utf-8')
                send_frame(s, encrypt_payload(meta, key))
                with open(path, 'rb') as f:
                    while True:
                        chunk = f.read(CHUNK_SIZE)
                        if not chunk:
                            break
                        send_frame(s, encrypt_payload(chunk, key))
                        sent_total += len(chunk)
                        if progress_callback:
                            try:
                                progress_callback(min(1.0, sent_total / total_size))
                            except Exception:
                                pass
            # wait for receiver ack (optional)
            try:
                s.settimeout(5.0)
                resp = s.recv(32)
                # some receivers send 'OK' or 'REJECT_*' messages
                if resp and resp.startswith(b'REJECT'):
                    return False, resp.decode('utf-8', errors='ignore')
            except Exception:
                # ignore ack timeout
                pass
            s.close()
            return True, None
        except Exception as e:
            try:
                s.close()
            except Exception:
                pass
            return False, f"Send failed: {e}"

# ---------------- GUI Application ----------------
class App(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("LAN File Transfer")
        self.geometry("860x540")
        ctk.set_appearance_mode("light")
        ctk.set_default_color_theme("blue")

        # networking
        self.stop_event = threading.Event()
        self.device_queue = Queue()
        self.incoming_queue = Queue()
        # create receiver first (so Discovery can include its salt if any)
        self.receiver = FileReceiver(self.incoming_queue, self.stop_event)
        self.discovery = Discovery(self.device_queue, self.stop_event, receiver_ref=self.receiver)
        self.sender = FileSender()

        self.devices = {}  # id -> info dict
        self.selected_device_id = None
        self.files_to_send = []

        # build UI
        self._build_ui()

        # start network threads
        self.receiver.start()
        self.discovery.start()

        # start polling loop
        self.after(200, self._poll_queues)

    def _build_ui(self):
        # LEFT: devices + PIN generation + PIN entry (for sender)
        left = ctk.CTkFrame(self, width=300, corner_radius=8)
        left.pack(side="left", fill="y", padx=12, pady=12)

        ctk.CTkLabel(left, text="Devices on LAN", font=("Helvetica", 14, "bold")).pack(anchor="nw", padx=8, pady=(6,4))
        self.listbox_frame = ctk.CTkFrame(left)
        self.listbox_frame.pack(fill="both", expand=True, padx=8, pady=4)
        self.listbox_tk = tk.Listbox(self.listbox_frame, height=12, font=("Segoe UI", 10))
        self.listbox_tk.pack(fill="both", expand=True, padx=4, pady=4)
        self.listbox_tk.bind("<<ListboxSelect>>", lambda e: self._on_device_select())

        self.lbl_selected = ctk.CTkLabel(left, text="Selected: —", anchor="w")
        self.lbl_selected.pack(fill="x", padx=8, pady=(4,6))

        # Receiver: generate pin
        pin_frame = ctk.CTkFrame(left)
        pin_frame.pack(fill="x", padx=8, pady=6)
        self.btn_gen_pin = ctk.CTkButton(pin_frame, text="Generate PIN (receiver)", command=self._generate_pin)
        self.btn_gen_pin.pack(side="left", padx=(0,6), expand=True)
        self.lbl_pin_timer = ctk.CTkLabel(pin_frame, text="PIN: —")
        self.lbl_pin_timer.pack(side="left")

        # Sender: entry to paste PIN shown on receiver (manual workflow)
        pin_entry_frame = ctk.CTkFrame(left)
        pin_entry_frame.pack(fill="x", padx=8, pady=(6,8))
        ctk.CTkLabel(pin_entry_frame, text="Enter receiver PIN:").pack(side="left", padx=(0,6))
        self.entry_pin = ctk.CTkEntry(pin_entry_frame, width=100, placeholder_text="123456")
        self.entry_pin.pack(side="left")

        # RIGHT: files, send controls, progress
        right = ctk.CTkFrame(self, corner_radius=8)
        right.pack(side="right", fill="both", expand=True, padx=12, pady=12)

        ctk.CTkLabel(right, text="Files to send", font=("Helvetica", 16, "bold")).pack(anchor="nw", padx=8, pady=(6,4))
        btn_bar = ctk.CTkFrame(right)
        btn_bar.pack(fill="x", padx=8, pady=(4,6))
        self.btn_add = ctk.CTkButton(btn_bar, text="Add files", command=self._add_files)
        self.btn_add.pack(side="left", padx=6)
        self.btn_remove = ctk.CTkButton(btn_bar, text="Remove", command=self._remove_file)
        self.btn_remove.pack(side="left", padx=6)
        self.btn_send = ctk.CTkButton(btn_bar, text="Send", command=self._send_files)
        self.btn_send.pack(side="right", padx=6)

        files_frame = ctk.CTkFrame(right)
        files_frame.pack(fill="both", expand=True, padx=8, pady=(4,6))
        self.files_listbox = tk.Listbox(files_frame, height=12, font=("Segoe UI", 10), selectmode=tk.MULTIPLE)
        self.files_listbox.pack(fill="both", expand=True, padx=4, pady=4)

        # progress + status
        self.progress = ctk.CTkProgressBar(right)
        self.progress.set(0.0)
        self.progress.pack(fill="x", padx=8, pady=(2,4))
        self.status = ctk.CTkLabel(right, text="Status: ready")
        self.status.pack(fill="x", padx=8, pady=(4,8))

    # UI helpers
    def _refresh_device_list(self):
        # repopulate listbox from self.devices
        self.listbox_tk.delete(0, tk.END)
        for dev_id, info in self.devices.items():
            name = info.get('name', 'unknown')
            addr = info.get('addr', '?.?.?.?')
            port = info.get('tcp_port', TCP_PORT)
            # mark if salt present (PIN active)
            salt_note = ' [PIN]' if info.get('salt') else ''
            self.listbox_tk.insert(tk.END, f"{name} {addr}:{port}{salt_note} — {dev_id}")

    def _on_device_select(self):
        sel = self.listbox_tk.curselection()
        if not sel:
            self.selected_device_id = None
            self.lbl_selected.configure(text="Selected: —")
            return
        text = self.listbox_tk.get(sel[0])
        # last part after ' — ' is id
        if ' — ' in text:
            dev_id = text.split(' — ')[-1]
            self.selected_device_id = dev_id
            info = self.devices.get(dev_id, {})
            addr = info.get('addr', '')
            port = info.get('tcp_port', TCP_PORT)
            self.lbl_selected.configure(text=f"Selected: {info.get('name','?')} @ {addr}:{port}")

    def _generate_pin(self):
        # generate pin on local receiver instance
        pin, salt, expiry = self.receiver.generate_pin()
        # update label and schedule timer updates via after
        def update_timer():
            ps = self.receiver.get_pin_state()
            if not ps:
                self.lbl_pin_timer.configure(text="PIN: —")
                return
            _, _, exp = ps
            remaining = int((exp - datetime.now(timezone.utc)).total_seconds())
            if remaining <= 0:
                # expired; receiver.clear_pin() should already have been called by timer thread if used,
                # but ensure label is updated
                self.receiver.clear_pin()
                self.lbl_pin_timer.configure(text="PIN: —")
                # Discovery will stop advertising salt automatically in next broadcast
                return
            self.lbl_pin_timer.configure(text=f"PIN: {pin} ({remaining}s)")
            # call again after 1s
            self.after(1000, update_timer)
        update_timer()
        # Note: Discovery thread uses receiver_ref to include salt while PIN is valid

    def _add_files(self):
        paths = filedialog.askopenfilenames(title="Select files to send")
        if not paths:
            return
        for p in paths:
            self.files_to_send.append(p)
            self.files_listbox.insert(tk.END, p)

    def _remove_file(self):
        sel = list(self.files_listbox.curselection())
        if not sel:
            return
        for idx in reversed(sel):
            self.files_listbox.delete(idx)
            del self.files_to_send[idx]

    def _send_files(self):
        # validate selection and PIN
        if not self.selected_device_id:
            messagebox.showwarning("No device", "Please select a device to send to.")
            return
        dev = self.devices.get(self.selected_device_id)
        if not dev:
            messagebox.showwarning("Device gone", "Selected device is not available anymore.")
            return
        if not self.files_to_send:
            messagebox.showwarning("No files", "Please add files to send.")
            return
        pin = self.entry_pin.get().strip()
        if not pin or len(pin) != 6 or not pin.isdigit():
            messagebox.showwarning("Invalid PIN", "Please enter a 6-digit PIN provided by the receiver.")
            return
        # get salt from the discovered device info (must be present while receiver's PIN valid)
        salt_b64 = dev.get('salt')
        if not salt_b64:
            # salt missing -> receiver did not broadcast salt (PIN not generated) or broadcast not received yet
            messagebox.showwarning("Missing salt", "Receiver did not advertise a salt. Make sure receiver pressed Generate PIN and wait a moment.")
            return
        try:
            salt = base64.b64decode(salt_b64)
        except Exception as e:
            messagebox.showerror("Salt error", f"Failed to decode salt from device info: {e}")
            return

        # start sending in background thread and update progress
        self.status.configure(text="Status: sending...")
        self.progress.set(0.0)
        files_copy = list(self.files_to_send)  # copy to avoid mutation during send

        def progress_cb(frac: float):
            # frac is 0.0..1.0
            try:
                self.progress.set(frac)
            except Exception:
                pass

        def send_thread():
            success, err = self.sender.send_files(dev['addr'], dev['tcp_port'], files_copy, pin, salt, progress_callback=progress_cb)
            if success:
                self.status.configure(text=f"Status: sent {len(files_copy)} file(s) successfully")
                # clear file list
                self.files_listbox.delete(0, tk.END)
                self.files_to_send.clear()
                self.progress.set(1.0)
            else:
                # map common REJECT_* responses
                if isinstance(err, bytes):
                    err_msg = err.decode('utf-8', errors='ignore')
                else:
                    err_msg = err or "unknown error"
                if 'REJECT_BAD_PIN' in str(err_msg) or 'REJECT_BAD_PIN' in str(err):
                    self.status.configure(text="Status: Error — wrong PIN (decryption failed on receiver)")
                elif 'REJECT_NO_PIN' in str(err_msg) or 'REJECT_NO_PIN' in str(err):
                    self.status.configure(text="Status: Error — receiver has no valid PIN (expired or not generated)")
                else:
                    self.status.configure(text=f"Status: Error — {err_msg}")
            # reset progress bar slightly after done
            time.sleep(0.6)
            # keep at final state for a bit then reset to 0
            time.sleep(0.4)
            self.progress.set(0.0)

        threading.Thread(target=send_thread, daemon=True).start()

    def _poll_queues(self):
        # devices updates
        try:
            while True:
                typ, dev_id, info = self.device_queue.get_nowait()
                if typ == 'update':
                    self.devices[dev_id] = info
                elif typ == 'remove':
                    if dev_id in self.devices:
                        del self.devices[dev_id]
                # update UI list
                self._refresh_device_list()
        except Empty:
            pass

        # incoming files
        try:
            while True:
                typ, path, size = self.incoming_queue.get_nowait()
                if typ == 'received':
                    messagebox.showinfo("File received", f"Saved: {path} ({size} bytes)")
        except Empty:
            pass

        # schedule next poll
        self.after(200, self._poll_queues)

# ----------------- Main -----------------
if __name__ == "__main__":
    app = App()
    app.protocol("WM_DELETE_WINDOW", lambda: (setattr(app, "stop_event", app.stop_event.set()) or app.destroy()))
    app.mainloop()
