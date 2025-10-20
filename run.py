"""
LAN File Transfer — CustomTkinter
Single-file Python app implementing a simple, secure LAN file transfer UI.

Features:
- GUI built with customtkinter (falls back to tkinter where needed).
- Device advertising + continuous scanning via UDP broadcast.
- Discovered devices shown in a Listbox; select device -> appears in "Selected Device" label.
- Add files (one or many) to send list. Files are organized per-file but in a simple list.
- Temporary PIN on the *receiver* side (valid 2:00 minutes) — PIN + salt -> PBKDF2 -> AES-GCM key.
- Files are sent in 64 KiB chunks, each chunk encrypted with AES-GCM (single session key).
- Received files written into a `received_files/` directory.

Dependencies:
- customtkinter: pip install customtkinter
- cryptography: pip install cryptography

Run: python LAN_File_Transfer_CustomTkinter.py

Notes:
- This is an example / prototype intended to be simple and robust; for production use
  review authentication, certificate pinning, network hardening, and better UX.

"""

import os
import sys
import socket
import threading
import json
import time
import uuid
import struct
import secrets
import hashlib
from datetime import datetime, timedelta
from pathlib import Path
from queue import Queue, Empty

# GUI
try:
    import customtkinter as ctk
except Exception:
    # fallback message: customtkinter is recommended
    import tkinter as tk
    from tkinter import messagebox, filedialog
    print("Please install customtkinter for the modern look: pip install customtkinter")
    raise

from tkinter import messagebox, filedialog

# Crypto
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend

# ----------------------------- Configuration -----------------------------
UDP_PORT = 50000                # used for advertising/discovery
TCP_PORT = 50010                # default port for incoming file transfers
BCAST_INTERVAL = 1.0            # seconds between advertisements
DEVICE_CLEANUP = 5.0            # seconds to consider a device dead if not seen
CHUNK_SIZE = 64 * 1024          # 64 KiB
PIN_TTL_SECONDS = 120           # PIN validity
RECV_DIR = Path("received_files")
RECV_DIR.mkdir(exist_ok=True)

# ----------------------------- Utilities -----------------------------

def now_ts():
    return datetime.utcnow().isoformat() + 'Z'

LOCAL_ID = str(uuid.uuid4())
HOSTNAME = socket.gethostname()

# ----------------------------- Networking: Discovery -----------------------------

class Discovery(threading.Thread):
    """Broadcasts our presence and listens for other broadcast messages."""
    def __init__(self, device_queue, stop_event, udp_port=UDP_PORT):
        super().__init__(daemon=True)
        self.udp_port = udp_port
        self.device_queue = device_queue
        self.stop_event = stop_event
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        # Listen socket
        self.listen_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.listen_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            self.listen_sock.bind(("", self.udp_port))
        except Exception as e:
            print("Failed to bind discovery UDP port:", e)
            raise
        # Devices: id -> (info dict, last_seen)
        self.devices = {}
        self.lock = threading.Lock()

    def run(self):
        # Launch advert sender thread
        threading.Thread(target=self._advertise_loop, daemon=True).start()
        # Listen loop
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
                            # push update to UI thread
                            self.device_queue.put(('update', dev_id, j))
                except Exception:
                    continue
            # Periodic cleanup
            self._cleanup_devices()
        self.listen_sock.close()
        self.sock.close()

    def _advertise_loop(self):
        payload = {
            'id': LOCAL_ID,
            'name': HOSTNAME,
            'tcp_port': TCP_PORT,
            'ts': now_ts()
        }
        bpayload = json.dumps(payload).encode('utf-8')
        while not self.stop_event.is_set():
            try:
                # Broadcast to local network
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

# ----------------------------- Networking: File Receiver -----------------------------

class FileReceiver(threading.Thread):
    """TCP server that receives encrypted file transfer sessions."""
    def __init__(self, incoming_queue, stop_event, tcp_port=TCP_PORT):
        super().__init__(daemon=True)
        self.tcp_port = tcp_port
        self.incoming_queue = incoming_queue
        self.stop_event = stop_event
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("", self.tcp_port))
        self.sock.listen(4)

        # PIN state: (pin_str, salt_bytes, expiry_datetime)
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
        pin = f"{secrets.randbelow(10**6):06d}"  # 6-digit
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
        """
        Protocol (simple framing):
        Sender connects to receiver TCP.
        First frame: 8-byte length N, then N bytes: encrypted JSON metadata (nonce + ciphertext).
        Then repeated frames: 8-byte length L, then L bytes of encrypted chunk (nonce + ciphertext).
        Metadata JSON fields: filename, filesize, salt (base64), header_nonce (we will not send salt as it's on receiver side; instead sender derives key from provided pin+salt), but to keep things clear sender will not send salt.

        On receiver side we will derive key using current pin_state (must exist and not expired) — this enforces sender to supply correct pin-derived key.
        But sender does not send the key; instead sender encrypts with key derived from PIN+salt; receiver uses stored salt and PIN to derive key and decrypt.

        For simplicity and safety, the receiver only accepts transfers if pin_state exists and not expired.
        """
        try:
            # Read metadata frame
            meta_bytes = recv_frame(conn)
            if not meta_bytes:
                conn.close()
                return
            # meta_bytes is encrypted payload; to decrypt, we must have pin_state
            pin_state = self.get_pin_state()
            if not pin_state or pin_state[2] < datetime.utcnow():
                # no valid pin; reject
                conn.sendall(b'REJECT_NO_PIN')
                conn.close()
                return
            pin, salt, expiry = pin_state
            key = derive_key(pin.encode('utf-8'), salt)
            meta = decrypt_payload(meta_bytes, key)
            # meta expected to be a JSON with filename, filesize
            j = json.loads(meta.decode('utf-8'))
            filename = os.path.basename(j.get('filename', 'received.bin'))
            filesize = int(j.get('filesize', 0))
            # prepare file
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
            # finalize
            final_path = RECV_DIR / filename
            # prevent overwriting by adding suffix
            final_path = unique_path(final_path)
            tmp_path.rename(final_path)
            # push event for UI
            self.incoming_queue.put(('received', str(final_path), filesize))
            conn.close()
        except Exception as e:
            print('Error handling incoming transfer:', e)
            try:
                conn.close()
            except Exception:
                pass

# ----------------------------- Networking: File Sender -----------------------------

class FileSender:
    """Sends files to a remote device using AES-GCM keyed by PIN+salt (PIN provided by receiver)."""
    def __init__(self):
        pass

    def send_files(self, remote_addr, remote_port, files, pin, salt):
        # derive key
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

# ----------------------------- Crypto helpers -----------------------------

def derive_key(pin_bytes, salt, length=32):
    # PBKDF2 with SHA256
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        iterations=200_000,
        backend=default_backend()
    )
    return kdf.derive(pin_bytes)


def encrypt_payload(plaintext, key):
    # Returns nonce + ciphertext
    aesgcm = AESGCM(key)
    nonce = secrets.token_bytes(12)
    ct = aesgcm.encrypt(nonce, plaintext, None)
    return nonce + ct


def decrypt_payload(payload, key):
    nonce = payload[:12]
    ct = payload[12:]
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ct, None)

# ----------------------------- Framing helpers -----------------------------

def send_frame(sock, data_bytes):
    # 8-byte length prefix
    header = struct.pack('!Q', len(data_bytes))
    sock.sendall(header + data_bytes)


def recv_all(sock, n):
    buf = b''
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf


def recv_frame(sock):
    header = recv_all(sock, 8)
    if not header:
        return None
    (length,) = struct.unpack('!Q', header)
    if length == 0:
        return b''
    return recv_all(sock, length)

# ----------------------------- Helpers -----------------------------

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

# ----------------------------- GUI App -----------------------------

class App(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title('LAN File Transfer')
        self.geometry('820x520')
        ctk.set_appearance_mode('light')
        ctk.set_default_color_theme('blue')

        # Networking threads
        self.stop_event = threading.Event()
        self.device_queue = Queue()
        self.incoming_queue = Queue()
        self.discovery = Discovery(self.device_queue, self.stop_event)
        self.receiver = FileReceiver(self.incoming_queue, self.stop_event)
        self.sender = FileSender()

        # UI state
        self.devices = {}  # id -> info
        self.selected_device_id = None
        self.files_to_send = []

        # Build UI
        self._build_ui()

        # Start networking
        self.discovery.start()
        self.receiver.start()

        # Start periodic UI poll
        self.after(200, self._poll_queues)

    def _build_ui(self):
        # Left: devices
        left = ctk.CTkFrame(self, width=260, corner_radius=8)
        left.pack(side='left', fill='y', padx=12, pady=12)

        ctk.CTkLabel(left, text='Devices on LAN', font=('Helvetica', 14, 'bold')).pack(padx=8, pady=(8,4))
        self.lb_devices = ctk.CTkTextbox(left, height=300, state='disabled')
        self.lb_devices.pack(padx=8, pady=4, fill='x')

        # We'll also have a listbox-like widget using tkinter Listbox for selection convenience
        self.tk_listbox = ctk.CTkFrame(left)
        self.tk_listbox.pack(padx=8, pady=4, fill='both', expand=True)
        self.listbox = ctk.CTkComboBox(left, values=[""], width=200)
        # but to keep it simple use a standard tkinter Listbox inside a frame
        self.listbox_tk = ctk.CTkListBox(left, width=220, height=180, command=self._on_device_selected)
        self.listbox_tk.pack(padx=8, pady=4)

        self.lbl_selected = ctk.CTkLabel(left, text='Selected: —', anchor='w')
        self.lbl_selected.pack(fill='x', padx=8, pady=(6,0))

        # Buttons for pin
        pin_frame = ctk.CTkFrame(left)
        pin_frame.pack(padx=8, pady=8, fill='x')
        self.btn_gen_pin = ctk.CTkButton(pin_frame, text='Generate PIN (allow incoming)', command=self._generate_pin)
        self.btn_gen_pin.pack(side='left', expand=True, padx=4)
        self.lbl_pin = ctk.CTkLabel(pin_frame, text='PIN: —')
        self.lbl_pin.pack(side='left', padx=4)

        # Right: file panel
        right = ctk.CTkFrame(self, corner_radius=8)
        right.pack(side='right', fill='both', expand=True, padx=12, pady=12)

        header = ctk.CTkLabel(right, text='Send Files', font=('Helvetica', 16, 'bold'))
        header.pack(anchor='nw', padx=8, pady=(8,4))

        btn_frame = ctk.CTkFrame(right)
        btn_frame.pack(fill='x', padx=8, pady=6)
        self.btn_add = ctk.CTkButton(btn_frame, text='Add files', command=self._add_files)
        self.btn_add.pack(side='left', padx=6)
        self.btn_remove = ctk.CTkButton(btn_frame, text='Remove selected file', command=self._remove_file)
        self.btn_remove.pack(side='left', padx=6)
        self.btn_send = ctk.CTkButton(btn_frame, text='Send', command=self._send_files)
        self.btn_send.pack(side='right', padx=6)

        # Files list
        self.files_listbox = ctk.CTkListBox(right, width=520, height=280)
        self.files_listbox.pack(padx=8, pady=8)

        # Status
        self.status = ctk.CTkLabel(right, text='Status: ready', anchor='w')
        self.status.pack(fill='x', padx=8, pady=(4,8))

    # ---------------- UI actions ----------------
    def _on_device_selected(self, value):
        # value is device id in our listbox items we stored as "{name} — {id}"
        # extract id
        # Simplify: the listbox contains entries of form "{name} ({addr}:{port}) — {id}"
        if not value:
            return
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
        # schedule clear
        def clear_later():
            time.sleep(PIN_TTL_SECONDS)
            self.receiver.clear_pin()
            self.lbl_pin.configure(text='PIN: —')
        threading.Thread(target=clear_later, daemon=True).start()

    def _add_files(self):
        paths = filedialog.askopenfilenames(title='Select files to send')
        if not paths:
            return
        for p in paths:
            self.files_to_send.append(p)
            self.files_listbox.insert('end', p)

    def _remove_file(self):
        sel = self.files_listbox.curselection()
        if not sel:
            return
        idx = sel[0]
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
        # Ask for PIN (the receiver must have generated and displayed it)
        pin = ctk.simpledialog.askstring('PIN required', 'Enter the temporary PIN shown on receiver (6 digits):')
        if not pin:
            return
        # Get salt: we need to obtain remote salt — in our design, the receiver keeps salt locally and does not send it.
        # To allow sender to derive the same key we must send salt to sender via discovery payload.
        # Update: keep salt published in discovery payload when generated. We'll check device discovery snapshot for salt.
        # If salt missing, cannot proceed.
        # In this prototype, we'll request salt by opening a small UDP query — but to keep it simple, assume discovery includes salt when receiver generated pin.
        remote = dev
        salt_b64 = remote.get('salt')
        if not salt_b64:
            messagebox.showerror('Missing salt', 'Receiver has not published a salt. Make sure the receiver pressed "Generate PIN" and wait a moment for broadcast to propagate.')
            return
        import base64
        salt = base64.b64decode(salt_b64)
        addr = remote.get('addr')
        port = int(remote.get('tcp_port', TCP_PORT))

        # run sender in thread
        def send_thread():
            self.status.configure(text='Status: sending...')
            ok, err = self.sender.send_files(addr, port, self.files_to_send, pin, salt)
            if ok:
                self.status.configure(text='Status: send complete')
            else:
                self.status.configure(text=f'Status: error: {err}')
        threading.Thread(target=send_thread, daemon=True).start()

    # ---------------- Polling for network events ----------------
    def _poll_queues(self):
        # Device updates
        updated = False
        try:
            while True:
                msg = self.device_queue.get_nowait()
                typ, dev_id, info = msg
                if typ == 'update':
                    # store info
                    # info may include 'salt' when pin generated
                    self.devices[dev_id] = info
                    updated = True
                elif typ == 'remove':
                    if dev_id in self.devices:
                        del self.devices[dev_id]
                        updated = True
        except Empty:
            pass
        if updated:
            self._refresh_device_list()
        # Incoming files
        try:
            while True:
                msg = self.incoming_queue.get_nowait()
                typ, arg, filesize = msg
                if typ == 'received':
                    messagebox.showinfo('File received', f'File saved to: {arg} ({filesize} bytes)')
        except Empty:
            pass
        # schedule next poll
        self.after(200, self._poll_queues)

    def _refresh_device_list(self):
        self.listbox_tk.delete(0, 'end')
        for dev_id, info in list(self.devices.items()):
            name = info.get('name', 'unknown')
            addr = info.get('addr')
            port = info.get('tcp_port')
            entry = f"{name} ({addr}:{port}) — {dev_id}"
            self.listbox_tk.insert('end', entry)

    def on_closing(self):
        if messagebox.askokcancel('Quit', 'Do you want to quit?'):
            self.stop_event.set()
            self.destroy()

# ----------------------------- Extended Discovery: include salt when PIN exists -----------------------------
# We will patch the Discovery class to include salt base64 in broadcast when receiver has a pin.
# For simplicity we will monkey-patch discovery to periodically check receiver.pin_state and include salt.

import base64

def attach_salt_to_broadcast(discovery: Discovery, receiver: FileReceiver):
    """Replace the discovery._advertise_loop with one that includes salt when PIN exists."""
    def _advertise_loop_with_salt():
        while not discovery.stop_event.is_set():
            payload = {
                'id': LOCAL_ID,
                'name': HOSTNAME,
                'tcp_port': TCP_PORT,
                'ts': now_ts()
            }
            pin_state = receiver.get_pin_state()
            if pin_state and pin_state[2] >= datetime.utcnow():
                # include salt as base64 so senders can derive key
                payload['salt'] = base64.b64encode(pin_state[1]).decode('ascii')
            bpayload = json.dumps(payload).encode('utf-8')
            try:
                discovery.sock.sendto(bpayload, ('<broadcast>', discovery.udp_port))
            except Exception:
                pass
            time.sleep(BCAST_INTERVAL)
    discovery._advertise_loop = _advertise_loop_with_salt

# ----------------------------- Main -----------------------------

def main():
    app = App()
    # attach salt-on-broadcast behavior
    attach_salt_to_broadcast(app.discovery, app.receiver)
    app.protocol('WM_DELETE_WINDOW', app.on_closing)
    app.mainloop()

if __name__ == '__main__':
    main()
