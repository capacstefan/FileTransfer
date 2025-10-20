import customtkinter as ctk
import tkinter as tk
from tkinter import filedialog, messagebox
import socket
import threading
import time
import os
import json
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import binascii
import random
import string

# --- CONSTANTE ȘI CONFIGURARE ---
APP_NAME = "LAN File Transfer"
BROADCAST_PORT = 12345
TRANSFER_PORT = 12346
BROADCAST_INTERVAL = 2  # Secunde
PIN_UPDATE_INTERVAL = 180  # 3 minute
CHUNK_SIZE = 64 * 1024  # 64 KB
SALT = b"salt_pentru_aes"
PIN_LENGTH = 6 

# Configurarea temei CTk
ctk.set_appearance_mode("Dark") # Setează o temă implicită consistentă
ctk.set_default_color_theme("blue")

# Culori statice pentru Listbox (simplificare)
LISTBOX_BG_DARK = "#292929"  # Fundal gri închis
LISTBOX_FG_LIGHT = "white"   # Text alb
LISTBOX_SELECT_COLOR = "#1f6aa5" # Culoarea de selecție CTk Blue standard

class FileTransferApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title(APP_NAME)
        self.geometry("800x600")
        
        # Variabile de stare
        self.local_ip = self.get_local_ip()
        self.devices = {}
        self.files_to_send = []
        self.current_pin = self.generate_pin()
        self.pin_countdown = PIN_UPDATE_INTERVAL

        # Setări Socket
        self.broadcast_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.broadcast_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        self.broadcast_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.broadcast_socket.bind(('', BROADCAST_PORT))
        
        self.transfer_server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.transfer_server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        try:
            self.transfer_server_socket.bind(('', TRANSFER_PORT))
        except OSError as e:
            messagebox.showerror("Eroare Critică", f"Nu se poate lega la portul de transfer {TRANSFER_PORT}. Eroare: {e}")
            self.quit()
            return

        # Pornirea thread-urilor
        self.is_running = True
        threading.Thread(target=self.broadcast_advertisement, daemon=True).start()
        threading.Thread(target=self.listen_for_devices, daemon=True).start()
        threading.Thread(target=self.start_transfer_server, daemon=True).start()
        
        # UI Setup și Timer
        self.setup_ui()
        self.after(1000, self.pin_updater)

    # --- Utilități PIN ---
    def get_local_ip(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(('10.255.255.255', 1))
            IP = s.getsockname()[0]
        except Exception:
            IP = '127.0.0.1'
        finally:
            s.close()
        return IP

    def generate_pin(self):
        return ''.join(random.choices(string.digits, k=PIN_LENGTH))

    def pin_updater(self):
        if not self.is_running:
            return
            
        self.pin_countdown -= 1
        
        if self.pin_countdown <= 0:
            self.current_pin = self.generate_pin()
            self.pin_countdown = PIN_UPDATE_INTERVAL
        
        self.update_pin_label()
        
        self.after(1000, self.pin_updater)

    def update_pin_label(self):
        minutes = self.pin_countdown // 60
        seconds = self.pin_countdown % 60
        timer_text = f"{minutes:02d}:{seconds:02d}"
        
        self.pin_timer_label.configure(text=f"PIN: {self.current_pin} | Resetare în: {timer_text}")
        self.pin_timer_label.update()
    
    def derive_key(self, pin: str) -> bytes:
        data = (pin + SALT.decode()).encode('utf-8')
        key = hashlib.sha256(data).digest()
        return key
        
    # --- Interfață Grafică (UI) Simplificată ---
    def setup_ui(self):
        self.grid_columnconfigure((0, 1), weight=1)
        self.grid_rowconfigure((0, 1, 2), weight=1)

        # 1. Frame-ul de Informații Locale (Partea de Sus)
        local_info_frame = ctk.CTkFrame(self)
        local_info_frame.grid(row=0, column=0, columnspan=2, padx=20, pady=(20, 10), sticky="nsew")
        local_info_frame.grid_columnconfigure((0, 1), weight=1)
        
        ctk.CTkLabel(local_info_frame, text="Informații Locale", font=ctk.CTkFont(size=18, weight="bold")).grid(row=0, column=0, columnspan=2, pady=(10, 5))
        ctk.CTkLabel(local_info_frame, text=f"IP Local: {self.local_ip}", font=ctk.CTkFont(size=14, weight="bold")).grid(row=1, column=0, padx=10, pady=5, sticky="w")
        
        self.pin_timer_label = ctk.CTkLabel(local_info_frame, text="", text_color="#10B981", font=ctk.CTkFont(size=14, weight="bold"))
        self.pin_timer_label.grid(row=1, column=1, padx=10, pady=5, sticky="e")
        self.update_pin_label()

        # 2. Frame-ul de Dispozitive (Stânga)
        device_frame = ctk.CTkFrame(self)
        device_frame.grid(row=1, column=0, padx=(20, 10), pady=10, sticky="nsew")
        device_frame.grid_rowconfigure(1, weight=1)
        device_frame.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(device_frame, text="Dispozitive Detectate 📡", font=ctk.CTkFont(size=16, weight="bold")).grid(row=0, column=0, padx=10, pady=(10, 5))
        
        # Simplificare: Folosim culori statice pentru tk.Listbox
        self.device_listbox_frame = tk.Frame(device_frame)
        self.device_listbox_frame.grid(row=1, column=0, padx=10, pady=(0, 10), sticky="nsew")
        
        self.device_listbox = tk.Listbox(self.device_listbox_frame, 
            selectmode=tk.SINGLE, 
            font=('Arial', 12), 
            borderwidth=0, 
            highlightthickness=0, 
            bg=LISTBOX_BG_DARK,             # Fundal static închis
            fg=LISTBOX_FG_LIGHT,            # Text static deschis
            selectbackground=LISTBOX_SELECT_COLOR, # Culoarea de selecție
            selectforeground=LISTBOX_FG_LIGHT,
            relief="flat" # Elimină marginile 3D
        )
        self.device_listbox.pack(fill="both", expand=True)

        ctk.CTkButton(device_frame, text="Trimite Fisiere", command=self.send_files_dialog, font=ctk.CTkFont(size=14, weight="bold"), height=40).grid(row=2, column=0, padx=10, pady=(0, 10), sticky="ew")

        # 3. Frame-ul de Fisiere (Dreapta)
        file_frame = ctk.CTkFrame(self)
        file_frame.grid(row=1, column=1, padx=(10, 20), pady=10, sticky="nsew")
        file_frame.grid_rowconfigure(1, weight=1)
        file_frame.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(file_frame, text="Fisiere pentru Transfer 📁", font=ctk.CTkFont(size=16, weight="bold")).grid(row=0, column=0, padx=10, pady=(10, 5))
        
        self.file_listbox_frame = tk.Frame(file_frame)
        self.file_listbox_frame.grid(row=1, column=0, padx=10, pady=(0, 10), sticky="nsew")
        
        self.file_listbox = tk.Listbox(self.file_listbox_frame, 
            selectmode=tk.MULTIPLE, 
            font=('Arial', 12), 
            borderwidth=0, 
            highlightthickness=0, 
            bg=LISTBOX_BG_DARK, 
            fg=LISTBOX_FG_LIGHT,
            selectbackground=LISTBOX_SELECT_COLOR,
            selectforeground=LISTBOX_FG_LIGHT,
            relief="flat"
        )
        self.file_listbox.pack(fill="both", expand=True)
        
        file_button_frame = ctk.CTkFrame(file_frame, fg_color="transparent")
        file_button_frame.grid(row=2, column=0, padx=10, pady=(0, 10), sticky="ew")
        file_button_frame.grid_columnconfigure((0, 1), weight=1)
        
        ctk.CTkButton(file_button_frame, text="Adaugă Fisiere", command=self.add_files, font=ctk.CTkFont(size=14), height=40).grid(row=0, column=0, padx=(0, 5), sticky="ew")
        ctk.CTkButton(file_button_frame, text="Șterge Selectate", command=self.remove_selected_files, font=ctk.CTkFont(size=14), height=40).grid(row=0, column=1, padx=(5, 0), sticky="ew")
        
        # 4. Progress Bar (Partea de Jos)
        self.progress_bar = ctk.CTkProgressBar(self, orientation="horizontal", mode="determinate", height=20, fg_color="gray", progress_color="green")
        self.progress_bar.grid(row=2, column=0, columnspan=2, padx=20, pady=(10, 20), sticky="ew")
        self.progress_bar.set(0)
        
        self.progress_label = ctk.CTkLabel(self, text="Gata de transfer.", font=ctk.CTkFont(size=12))
        self.progress_label.grid(row=3, column=0, columnspan=2, padx=20, pady=(0, 10), sticky="ew")
        
        self.update_device_listbox()

    # --- Funcții de Interfață (Fără modificări) ---
    def add_files(self):
        file_paths = filedialog.askopenfilenames()
        if file_paths:
            for path in file_paths:
                file_name = os.path.basename(path)
                file_size = os.path.getsize(path)
                self.files_to_send.append((path, file_name, file_size))
                self.file_listbox.insert(tk.END, f"{file_name} ({self.format_size(file_size)})")

    def remove_selected_files(self):
        selected_indices = self.file_listbox.curselection()
        for index in reversed(selected_indices):
            self.file_listbox.delete(index)
            del self.files_to_send[index]

    def format_size(self, size_bytes):
        if size_bytes >= 1024**3:
            return f"{size_bytes / 1024**3:.2f} GB"
        elif size_bytes >= 1024**2:
            return f"{size_bytes / 1024**2:.2f} MB"
        elif size_bytes >= 1024:
            return f"{size_bytes / 1024:.2f} KB"
        else:
            return f"{size_bytes} Bytes"

    def update_device_listbox(self):
        selected_index = None
        try:
            selected_index = self.device_listbox.curselection()[0]
        except IndexError:
            pass
            
        self.device_listbox.delete(0, tk.END)
        for ip, hostname in self.devices.items():
            if ip != self.local_ip:
                self.device_listbox.insert(tk.END, f"{hostname} ({ip})")

        if selected_index is not None and selected_index < self.device_listbox.size():
            self.device_listbox.selection_set(selected_index)
            
        self.after(1000, self.update_device_listbox)

    # --- Dialog de Trimitere (PIN - Numeric și Vizibil) ---
    def send_files_dialog(self):
        if not self.files_to_send:
            messagebox.showwarning("Atenție", "Vă rugăm să adăugați fișiere de trimis.")
            return

        try:
            selected_index = self.device_listbox.curselection()[0]
        except IndexError:
            messagebox.showwarning("Atenție", "Vă rugăm să selectați un dispozitiv din listă.")
            return

        selected_device_text = self.device_listbox.get(selected_index)
        target_ip = selected_device_text.split('(')[-1].strip(')')
        
        dialog = ctk.CTkToplevel(self)
        dialog.title("Introducere PIN")
        dialog.geometry("300x150")
        dialog.transient(self)
        dialog.grab_set()

        ctk.CTkLabel(dialog, text=f"Introduceți PIN-ul de pe {target_ip}", font=ctk.CTkFont(size=14, weight="bold")).pack(pady=10)
        
        # PIN-ul NU are '*' (show="") și acceptă doar cifre
        pin_entry = ctk.CTkEntry(dialog, width=200, font=ctk.CTkFont(size=14), show="") 
        pin_entry.pack(pady=5)
        
        def validate_pin(char):
            return char.isdigit() or char == ""

        vcmd = dialog.register(validate_pin)
        pin_entry.configure(validate="key", validatecommand=(vcmd, '%S'))
        
        def start_transfer_callback():
            pin = pin_entry.get()
            if len(pin) != PIN_LENGTH or not pin.isdigit():
                messagebox.showerror("Eroare PIN", f"PIN-ul trebuie să aibă exact {PIN_LENGTH} cifre.")
                return
            
            dialog.destroy()
            threading.Thread(target=self.initiate_transfer, args=(target_ip, pin), daemon=True).start()
        
        ctk.CTkButton(dialog, text="Start Transfer", command=start_transfer_callback, font=ctk.CTkFont(size=14)).pack(pady=10)
        
    # --- Protocol de Rețea (Fără modificări) ---
    def broadcast_advertisement(self):
        hostname = socket.gethostname()
        message = json.dumps({"ip": self.local_ip, "hostname": hostname}).encode('utf-8')
        while self.is_running:
            try:
                self.broadcast_socket.sendto(message, ('<broadcast>', BROADCAST_PORT))
            except Exception:
                pass
            time.sleep(BROADCAST_INTERVAL)

    def listen_for_devices(self):
        while self.is_running:
            try:
                data, addr = self.broadcast_socket.recvfrom(1024)
                message = json.loads(data.decode('utf-8'))
                
                device_ip = message.get("ip")
                device_hostname = message.get("hostname")

                if device_ip and device_ip != self.local_ip:
                    self.devices[device_ip] = device_hostname
            except socket.timeout:
                continue
            except Exception:
                continue

    # --- Protocol de Transfer (Fără modificări) ---
    def initiate_transfer(self, target_ip, pin):
        self.progress_label.configure(text=f"Conectare la {target_ip}...")
        self.progress_bar.set(0)
        
        try:
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client_socket.connect((target_ip, TRANSFER_PORT))
            
            client_socket.sendall(pin.encode('utf-8'))
            response = client_socket.recv(1024).decode('utf-8')
            
            if response == "PIN_OK":
                key = self.derive_key(pin)
                
                metadata = []
                for path, name, size in self.files_to_send:
                    metadata.append({"name": name, "size": size})
                
                metadata_json = json.dumps(metadata).encode('utf-8')
                metadata_header = len(metadata_json).to_bytes(4, byteorder='big')
                
                client_socket.sendall(metadata_header)
                client_socket.sendall(metadata_json)
                
                self.progress_label.configure(text=f"Începe transferul de {len(self.files_to_send)} fișiere...")
                
                for path, name, size in self.files_to_send:
                    self.send_file(client_socket, path, name, size, key)
                    
                self.progress_label.configure(text="✅ Transfer complet. Gata de transfer.")
                self.progress_bar.set(1)
                
            else:
                self.progress_label.configure(text="❌ Transfer eșuat. PIN incorect sau eroare server.")
                messagebox.showerror("Eroare", "PIN-ul introdus este incorect. Transfer anulat.")
                
            client_socket.close()

        except ConnectionRefusedError:
            self.progress_label.configure(text="❌ Transfer eșuat. Conexiune refuzată.")
            messagebox.showerror("Eroare", f"Conexiune refuzată la {target_ip}. Aplicația nu rulează sau firewall-ul blochează.")
        except Exception as e:
            self.progress_label.configure(text=f"❌ Transfer eșuat. Eroare: {e}")
            messagebox.showerror("Eroare", f"Eroare neașteptată la trimitere: {e}")
            
        self.progress_bar.set(0)

    def send_file(self, sock, file_path, file_name, file_size, key):
        self.progress_label.configure(text=f"Transfer: {file_name}...")
        
        cipher = AES.new(key, AES.MODE_CBC)
        iv = cipher.iv
        sock.sendall(iv)
        
        bytes_sent = 0
        
        with open(file_path, 'rb') as f:
            while True:
                chunk = f.read(CHUNK_SIZE)
                if not chunk:
                    break
                
                padded_chunk = pad(chunk, AES.block_size)
                encrypted_chunk = cipher.encrypt(padded_chunk)
                
                chunk_len_header = len(encrypted_chunk).to_bytes(4, byteorder='big')
                sock.sendall(chunk_len_header)
                sock.sendall(encrypted_chunk)
                
                bytes_sent += len(chunk)
                
                progress = bytes_sent / file_size
                self.progress_bar.set(progress)
                self.progress_label.configure(text=f"Transfer: {file_name} - {self.format_size(bytes_sent)}/{self.format_size(file_size)}")

            sock.sendall((0).to_bytes(4, byteorder='big'))

    # --- Protocol de Transfer (Receiver Side - Fără modificări) ---
    def start_transfer_server(self):
        self.transfer_server_socket.listen(5)
        while self.is_running:
            try:
                conn, addr = self.transfer_server_socket.accept()
                threading.Thread(target=self.handle_transfer_request, args=(conn, addr), daemon=True).start()
            except Exception:
                continue

    def handle_transfer_request(self, conn, addr):
        sender_ip = addr[0]
        
        try:
            pin = conn.recv(1024).decode('utf-8')
            
            if pin != self.current_pin:
                conn.sendall("PIN_INCORRECT".encode('utf-8'))
                conn.close()
                return

            conn.sendall("PIN_OK".encode('utf-8'))
            key = self.derive_key(pin)
            
            metadata_header = conn.recv(4)
            if not metadata_header: raise Exception("Eroare la primirea header-ului de metadate.")
            metadata_len = int.from_bytes(metadata_header, byteorder='big')
            
            metadata_json = self.recv_all(conn, metadata_len).decode('utf-8')
            metadata = json.loads(metadata_json)
            
            save_dir = os.path.join(os.getcwd(), "Received_Files")
            os.makedirs(save_dir, exist_ok=True)
            
            self.progress_label.configure(text=f"Primește de la {sender_ip}...")
            
            for file_info in metadata:
                self.receive_file(conn, file_info['name'], file_info['size'], save_dir, key)
            
            self.progress_label.configure(text="✅ Toate fișierele primite. Gata de transfer.")
            self.progress_bar.set(1)

        except Exception as e:
            self.progress_label.configure(text=f"❌ Primire eșuată de la {sender_ip}. Eroare: {e}")
        finally:
            conn.close()
            self.progress_bar.set(0)

    def receive_file(self, conn, file_name, file_size, save_dir, key):
        self.progress_label.configure(text=f"Primește: {file_name}...")
        save_path = os.path.join(save_dir, file_name)
        
        iv = self.recv_all(conn, 16)
        if len(iv) != 16: raise Exception("Eroare la primirea IV-ului.")
        cipher = AES.new(key, AES.MODE_CBC, iv=iv)
        
        bytes_received = 0
        
        with open(save_path, 'wb') as f:
            while True:
                chunk_len_header = self.recv_all(conn, 4)
                if not chunk_len_header:
                    raise Exception("Conexiune închisă neașteptat.")
                    
                encrypted_chunk_len = int.from_bytes(chunk_len_header, byteorder='big')
                
                if encrypted_chunk_len == 0:
                    break
                
                encrypted_chunk = self.recv_all(conn, encrypted_chunk_len)
                if not encrypted_chunk:
                    raise Exception("Conexiune închisă neașteptat în timpul primirii chunk-ului.")
                    
                decrypted_padded_chunk = cipher.decrypt(encrypted_chunk)
                decrypted_chunk = unpad(decrypted_padded_chunk, AES.block_size)

                f.write(decrypted_chunk)
                bytes_received += len(decrypted_chunk)
                
                progress = bytes_received / file_size
                self.progress_bar.set(progress)
                self.progress_label.configure(text=f"Primește: {file_name} - {self.format_size(bytes_received)}/{self.format_size(file_size)}")
        
        if bytes_received != file_size:
            print(f"Atenție: Dimensiunea primită ({bytes_received}) nu corespunde cu dimensiunea așteptată ({file_size}) pentru {file_name}")

    def recv_all(self, sock, n):
        data = bytearray()
        while len(data) < n:
            packet = sock.recv(n - len(data))
            if not packet:
                return None
            data.extend(packet)
        return data

    # --- Curățare ---
    def on_closing(self):
        self.is_running = False
        try:
            self.broadcast_socket.close()
            # Deblocare server socket
            temp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            temp_sock.connect(('127.0.0.1', TRANSFER_PORT))
            temp_sock.close()
            self.transfer_server_socket.close()
        except:
            pass
        self.destroy()

if __name__ == "__main__":
    app = FileTransferApp()
    app.protocol("WM_DELETE_WINDOW", app.on_closing) 
    app.mainloop()