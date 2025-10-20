"""
LAN File Transfer — CustomTkinter
Fully functional version with PIN entry, file send/receive, discovery, and feedback
"""

import os
import socket
import threading
import json
import time
import uuid
import struct
import secrets
from datetime import datetime, timedelta
from pathlib import Path
from queue import Queue, Empty

import tkinter as tk
from tkinter import messagebox, filedialog, simpledialog

try:
    import customtkinter as ctk
except Exception:
    print("Please install customtkinter: pip install customtkinter")
    raise

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend

# ----------------------------- Configuration -----------------------------
UDP_PORT = 50000
TCP_PORT = 50010
BCAST_INTERVAL = 1.0
DEVICE_CLEANUP = 5.0
CHUNK_SIZE = 64 * 1024
PIN_TTL_SECONDS = 120
RECV_DIR = Path("received_files")
RECV_DIR.mkdir(exist_ok=True)

def now_ts():
    return datetime.utcnow().isoformat() + 'Z'

LOCAL_ID = str(uuid.uuid4())
HOSTNAME = socket.gethostname()

# ----------------------------- Discovery -----------------------------
class Discovery(threading.Thread):
    def __init__(self, device_queue, stop_event, udp_port=UDP_PORT):
        super().__init__(daemon=True)
        self.udp_port = udp_port
        self.device_queue = device_queue
        self.stop_event = stop_event
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        self.listen_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.listen_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listen_sock.bind(("", self.udp_port))
        self.devices = {}
        self.lock = threading.Lock()

    def run(self):
        threading.Thread(target=self._advertise_loop, daemon=True).start()
        while not self.stop_event.is_set():
            try:
                self.listen_sock.settimeout(1.0)
                data, addr = self.listen_sock.recvfrom(4096)
            except socket.timeout:
                continue
            try:
                j = json.loads(data.decode('utf-8', errors='ignore'))
                dev_id = j.get('id')
                if dev_id and dev_id != LOCAL_ID:
                    j['addr'] = addr[0]
                    with self.lock:
                        self.devices[dev_id] = (j, time.time())
                        self.device_queue.put(('update', dev_id, j))
            except Exception:
                continue
            self._cleanup_devices()
        self.listen_sock.close()
        self.sock.close()

    def _advertise_loop(self):
        while not self.stop_event.is_set():
            payload = {
                'id': LOCAL_ID,
                'name': HOSTNAME,
                'tcp_port': TCP_PORT,
                'ts': now_ts()
            }
            bpayload = json.dumps(payload).encode('utf-8')
            try:
                self.sock.sendto(bpayload, ('<broadcast>', self.udp_port))
            except Exception:
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

# ----------------------------- FileReceiver -----------------------------
class FileReceiver(threading.Thread):
    def __init__(self, incoming_queue, stop_event, tcp_port=TCP_PORT):
        super().__init__(daemon=True)
        self.tcp_port = tcp_port
        self.incoming_queue = incoming_queue
        self.stop_event = stop_event
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("", self.tcp_port))
        self.sock.listen(4)
        self.pin_state = None
        self.pin_lock = threading.Lock()

    def run(self):
        while not self.stop_event.is_set():
            self.sock.settimeout(1.0)
            try:
                conn, addr = self.sock.accept()
            except socket.timeout:
                continue
            threading.Thread(target=self._handle_conn, args=(conn, addr), daemon=True).start()
        self.sock.close()

    def generate_pin(self):
        pin = f"{secrets.randbelow(10**6):06d}"
        salt = secrets.token_bytes(16)
        expiry = datetime.utcnow() + timedelta(seconds=PIN_TTL_SECONDS)
        with self.pin_lock:
            self.pin_state = (pin, salt, expiry)
        return pin, salt, expiry

    def clear_pin(self):
        with self.pin_lock:
            self.pin_state = None

    def get_pin_state(self):
        with self.pin_lock:
            return self.pin_state

    def _handle_conn(self, conn, addr):
        try:
            meta_bytes = recv_frame(conn)
            pin_state = self.get_pin_state()
            if not pin_state or pin_state[2] < datetime.utcnow():
                conn.sendall(b'REJECT_NO_PIN')
                conn.close()
                return
            pin, salt, expiry = pin_state
            key = derive_key(pin.encode('utf-8'), salt)
            meta = decrypt_payload(meta_bytes, key)
            j = json.loads(meta.decode('utf-8'))
            filename = os.path.basename(j.get('filename', 'received.bin'))
            filesize = int(j.get('filesize', 0))
            tmp_path = RECV_DIR / (filename + '.part')
            with open(tmp_path, 'wb') as f:
                received = 0
                while received < filesize:
                    chunk_encrypted = recv_frame(conn)
                    if not chunk_encrypted:
                        break
                    chunk = decrypt_payload(chunk_encrypted, key)
                    f.write(chunk)
                    received += len(chunk)
            final_path = unique_path(RECV_DIR / filename)
            tmp_path.rename(final_path)
            self.incoming_queue.put(('received', str(final_path), filesize))
            conn.close()
        except Exception as e:
            print('Error handling incoming transfer:', e)
            try:
                conn.close()
            except Exception:
                pass

# ----------------------------- FileSender -----------------------------
class FileSender:
    def send_files(self, remote_addr, remote_port, files, pin, salt):
        key = derive_key(pin.encode('utf-8'), salt)
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((remote_addr, remote_port))
            for path in files:
                size = os.path.getsize(path)
                meta = json.dumps({'filename': os.path.basename(path), 'filesize': size}).encode('utf-8')
                meta_enc = encrypt_payload(meta, key)
                send_frame(s, meta_enc)
                with open(path, 'rb') as f:
                    while True:
                        chunk = f.read(CHUNK_SIZE)
                        if not chunk:
                            break
                        enc = encrypt_payload(chunk, key)
                        send_frame(s, enc)
            s.close()
            return True, None
        except Exception as e:
            return False, str(e)

# ----------------------------- Crypto & framing -----------------------------
def derive_key(pin_bytes, salt, length=32):
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=length, salt=salt, iterations=200_000, backend=default_backend())
    return kdf.derive(pin_bytes)

def encrypt_payload(plaintext, key):
    aesgcm = AESGCM(key)
    nonce = secrets.token_bytes(12)
    ct = aesgcm.encrypt(nonce, plaintext, None)
    return nonce + ct

def decrypt_payload(payload, key):
    nonce, ct = payload[:12], payload[12:]
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ct, None)

def send_frame(sock, data_bytes):
    sock.sendall(struct.pack('!Q', len(data_bytes)) + data_bytes)

def recv_all(sock, n):
    buf = b''
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk: return None
        buf += chunk
    return buf

def recv_frame(sock):
    header = recv_all(sock, 8)
    if not header: return None
    length = struct.unpack('!Q', header)[0]
    if length == 0: return b''
    return recv_all(sock, length)

def unique_path(p: Path) -> Path:
    if not p.exists(): return p
    stem, suffix, i = p.stem, p.suffix, 1
    while True:
        candidate = p.with_name(f"{stem}_{i}{suffix}")
        if not candidate.exists(): return candidate
        i += 1

# ----------------------------- GUI -----------------------------
class App(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title('LAN File Transfer')
        self.geometry('820x520')
        ctk.set_appearance_mode('light')
        ctk.set_default_color_theme('blue')

        self.stop_event = threading.Event()
        self.device_queue = Queue()
        self.incoming_queue = Queue()
        self.discovery = Discovery(self.device_queue, self.stop_event)
        self.receiver = FileReceiver(self.incoming_queue, self.stop_event)
        self.sender = FileSender()

        self.devices = {}
        self.selected_device_id = None
        self.files_to_send = []

        self._build_ui()
        self.discovery.start()
        self.receiver.start()
        self.after(200, self._poll_queues)

    def _build_ui(self):
        # Left panel
        left = ctk.CTkFrame(self, width=260, corner_radius=8)
        left.pack(side='left', fill='y', padx=12, pady=12)

        ctk.CTkLabel(left, text='Devices on LAN', font=('Helvetica', 14, 'bold')).pack(padx=8, pady=(8,4))
        self.listbox_frame = ctk.CTkFrame(left)
        self.listbox_frame.pack(padx=8, pady=4, fill='both', expand=True)
        self.listbox_tk = tk.Listbox(self.listbox_frame, height=10, selectmode=tk.SINGLE, font=('Segoe UI', 11))
        self.listbox_tk.pack(fill='both', expand=True, padx=4, pady=4)
        self.listbox_tk.bind('<<ListboxSelect>>', lambda e: self._on_device_selected(
            self.listbox_tk.get(self.listbox_tk.curselection()[0]) if self.listbox_tk.curselection() else None))

        self.lbl_selected = ctk.CTkLabel(left, text='Selected: —', anchor='w')
        self.lbl_selected.pack(fill='x', padx=8, pady=(6,0))

        # PIN display for receiver
        pin_frame = ctk.CTkFrame(left)
        pin_frame.pack(padx=8, pady=8, fill='x')

        self.btn_gen_pin = ctk.CTkButton(pin_frame, text='Generate PIN', command=self._generate_pin)
        self.btn_gen_pin.pack(side='left', padx=4)

        self.entry_pin = ctk.CTkEntry(pin_frame, placeholder_text='Enter PIN to send')
        self.entry_pin.pack(side='left', padx=4)

        self.lbl_pin_timer = ctk.CTkLabel(pin_frame, text='PIN: —')
        self.lbl_pin_timer.pack(side='left', padx=4)

        # Right panel
        right = ctk.CTkFrame(self, corner_radius=8)
        right.pack(side='right', fill='both', expand=True, padx=12, pady=12)
        ctk.CTkLabel(right, text='Send Files', font=('Helvetica', 16, 'bold')).pack(anchor='nw', padx=8, pady=(8,4))

        btn_frame = ctk.CTkFrame(right)
        btn_frame.pack(fill='x', padx=8, pady=6)
        self.btn_add = ctk.CTkButton(btn_frame, text='Add files', command=self._add_files)
        self.btn_add.pack(side='left', padx=6)
        self.btn_remove = ctk.CTkButton(btn_frame, text='Remove selected file', command=self._remove_file)
        self.btn_remove.pack(side='left', padx=6)
        self.btn_send = ctk.CTkButton(btn_frame, text='Send', command=self._send_files)
        self.btn_send.pack(side='right', padx=6)

        self.files_frame = ctk.CTkFrame(right)
        self.files_frame.pack(padx=8, pady=4, fill='both', expand=True)
        self.files_listbox = tk.Listbox(self.files_frame, height=15, selectmode=tk.MULTIPLE, font=('Segoe UI', 11))
        self.files_listbox.pack(fill='both', expand=True, padx=4, pady=4)

        self.status = ctk.CTkLabel(right, text='Status: ready', anchor='w')
        self.status.pack(fill='x', padx=8, pady=(4,8))

    # ----------------- UI callbacks -----------------
    def _on_device_selected(self, value):
        if not value: return
        parts = value.split(' — ')
        if len(parts) >= 2:
            dev_id = parts[-1]
            self.selected_device_id = dev_id
            info = self.devices.get(dev_id, {})
            addr = info.get('addr')
            port = info.get('tcp_port')
            self.lbl_selected.configure(text=f"Selected: {info.get('name','?')} @ {addr}:{port}")

    def _generate_pin(self):
        pin, salt, expiry = self.receiver.generate_pin()
        self.lbl_pin.configure(text=f'PIN: {pin} (expires {expiry.strftime("%H:%M:%S UTC")})')
        def clear_later():
            time.sleep(PIN_TTL_SECONDS)
            self.receiver.clear_pin()
            self.lbl_pin.configure(text='PIN: —')
        threading.Thread(target=clear_later, daemon=True).start()

    def _add_files(self):
        paths = filedialog.askopenfilenames(title='Select files to send')
        if not paths: return
        for p in paths:
            self.files_to_send.append(p)
            self.files_listbox.insert('end', p)

    def _remove_file(self):
        sel = self.files_listbox.curselection()
        if not sel: return
        for idx in reversed(sel):
            self.files_listbox.delete(idx)
            del self.files_to_send[idx]

    def _send_files(self):
        if not self.selected_device_id:
            messagebox.showwarning('No device', 'Please select a device to send to.')
            return
        dev = self.devices.get(self.selected_device_id)
        if not dev:
            messagebox.showwarning('Device gone', 'Selected device is not available anymore.')
            return
        if not self.files_to_send:
            messagebox.showwarning('No files', 'Please add files to send.')
            return

        pin_input = self.entry_pin.get().strip()
        pin_state = self.receiver.get_pin_state()

        if not pin_state:
            self.status.configure(text="Status: PIN expired or not generated")
            return

        real_pin, salt, expiry = pin_state
        if pin_input != real_pin:
            self.status.configure(text="Status: Invalid PIN")
            return

        self.status.configure(text="Status: Sending…")
        threading.Thread(target=self._do_send_thread, args=(dev, self.files_to_send, pin_input, salt), daemon=True).start()

    def _do_send_thread(self, dev, files, pin, salt):
        success, err = self.sender.send_files(dev['addr'], dev['tcp_port'], files, pin, salt)
        if success:
            self.status.configure(text=f"Status: Sent {len(files)} file(s) successfully")
        else:
            self.status.configure(text=f"Status: Error - {err}")

    # ----------------- Polling -----------------
    def _poll_queues(self):
        # Devices
        try:
            while True:
                action, dev_id, info = self.device_queue.get_nowait()
                if action == 'update':
                    self.devices[dev_id] = info
                    display_name = f"{info.get('name','?')} — {dev_id}"
                    if display_name not in self.listbox_tk.get(0, tk.END):
                        self.listbox_tk.insert(tk.END, display_name)
                elif action == 'remove':
                    self.devices.pop(dev_id, None)
                    items = self.listbox_tk.get(0, tk.END)
                    for idx, val in enumerate(items):
                        if val.endswith(dev_id):
                            self.listbox_tk.delete(idx)
                            break
        except Empty:
            pass

        # Incoming files
        try:
            while True:
                action, filepath, filesize = self.incoming_queue.get_nowait()
                if action == 'received':
                    self.status.configure(text=f"Received: {filepath} ({filesize} bytes)")
        except Empty:
            pass

        self.after(200, self._poll_queues)

# ----------------------------- Main -----------------------------
if __name__ == '__main__':
    app = App()
    app.mainloop()
