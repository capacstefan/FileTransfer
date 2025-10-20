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

# --- CONSTANTE ȘI CONFIGURARE ---
APP_NAME = "LAN File Transfer"
BROADCAST_PORT = 12345
TRANSFER_PORT = 12346
BROADCAST_INTERVAL = 2  # Secunde între mesaje de advertising
PIN_UPDATE_INTERVAL = 180  # 3 minute
CHUNK_SIZE = 64 * 1024  # 64 KB
SALT = b"salt_pentru_aes"  # Salt fix pentru derivarea cheii

# Configurare customtkinter
ctk.set_appearance_mode("System")  # Modul implicit
ctk.set_default_color_theme("blue")

class FileTransferApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title(APP_NAME)
        self.geometry("800x600")
        
        # Variabile de stare
        self.local_ip = self.get_local_ip()
        self.devices = {}  # {IP: Nume_Host}
        self.files_to_send = []  # [(cale_fisier, nume_fisier, dimensiune)]
        self.current_pin = self.generate_pin()

        # Thread-uri și Sockets
        self.broadcast_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.broadcast_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        self.broadcast_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.broadcast_socket.bind(('', BROADCAST_PORT))
        
        self.transfer_server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.transfer_server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        # Neapărat să încercăm să bind-uim socketul de transfer
        try:
            self.transfer_server_socket.bind(('', TRANSFER_PORT))
        except OSError as e:
            messagebox.showerror("Eroare Critică", f"Nu se poate lega la portul de transfer {TRANSFER_PORT}. Verificați dacă altă aplicație folosește acest port. Eroare: {e}")
            self.quit()
            return

        # Pornirea thread-urilor
        self.is_running = True
        threading.Thread(target=self.broadcast_advertisement, daemon=True).start()
        threading.Thread(target=self.listen_for_devices, daemon=True).start()
        threading.Thread(target=self.start_transfer_server, daemon=True).start()
        threading.Thread(target=self.pin_updater, daemon=True).start()
        
        # UI Setup
        self.setup_ui()

    # --- Utilități de Rețea și PIN ---
    def get_local_ip(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            # Nu contează adresa la care ne conectăm, vrem doar să aflăm IP-ul local
            s.connect(('10.255.255.255', 1))
            IP = s.getsockname()[0]
        except Exception:
            IP = '127.0.0.1'
        finally:
            s.close()
        return IP

    def generate_pin(self):
        # Generează un PIN simplu din 6 cifre
        return str(binascii.hexlify(os.urandom(3)).decode())[:6].upper()

    def pin_updater(self):
        while self.is_running:
            time.sleep(PIN_UPDATE_INTERVAL)
            if self.is_running:
                self.current_pin = self.generate_pin()
                self.update_pin_label()

    def update_pin_label(self):
        self.pin_label.configure(text=f"PIN (Se schimbă la 3 min): {self.current_pin}")
        self.pin_label.update()
    
    def derive_key(self, pin: str) -> bytes:
        """Derivă cheia AES pe 256 de biți din PIN și SALT."""
        data = (pin + SALT.decode()).encode('utf-8')
        key = hashlib.sha256(data).digest()
        return key
        
    # --- Interfață Grafică (UI) ---
    def setup_ui(self):
        # Configurarea grid-ului principal
        self.grid_columnconfigure((0, 1), weight=1)
        self.grid_rowconfigure((0, 1, 2), weight=1)

        # Frame-ul de Informații Locale (Partea de Sus)
        local_info_frame = ctk.CTkFrame(self)
        local_info_frame.grid(row=0, column=0, columnspan=2, padx=20, pady=(20, 10), sticky="nsew")
        local_info_frame.grid_columnconfigure((0, 1), weight=1)
        
        ctk.CTkLabel(local_info_frame, text="Informații Locale", font=ctk.CTkFont(size=18, weight="bold")).grid(row=0, column=0, columnspan=2, pady=(10, 5))
        ctk.CTkLabel(local_info_frame, text=f"IP Local: {self.local_ip}", font=ctk.CTkFont(size=14, weight="bold")).grid(row=1, column=0, padx=10, pady=5, sticky="w")
        
        self.pin_label = ctk.CTkLabel(local_info_frame, text=f"PIN (Se schimbă la 3 min): {self.current_pin}", text_color="green", font=ctk.CTkFont(size=14, weight="bold"))
        self.pin_label.grid(row=1, column=1, padx=10, pady=5, sticky="e")

        # Frame-ul de Dispozitive (Stânga)
        device_frame = ctk.CTkFrame(self)
        device_frame.grid(row=1, column=0, padx=(20, 10), pady=10, sticky="nsew")
        device_frame.grid_rowconfigure(1, weight=1)
        device_frame.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(device_frame, text="Dispozitive Detectate 📡", font=ctk.CTkFont(size=16, weight="bold")).grid(row=0, column=0, padx=10, pady=(10, 5))
        
        # Folosim tk.Listbox deoarece CTk nu are (sau o simulare ar fi prea complexă)
        self.device_listbox_frame = tk.Frame(device_frame, bg=device_frame.cget("fg_color")[1]) # Fundalul frame-ului pentru Listbox
        self.device_listbox_frame.grid(row=1, column=0, padx=10, pady=(0, 10), sticky="nsew")
        
        self.device_listbox = tk.Listbox(self.device_listbox_frame, selectmode=tk.SINGLE, font=('Arial', 12), borderwidth=0, highlightthickness=0)
        self.device_listbox.pack(fill="both", expand=True)

        ctk.CTkButton(device_frame, text="Trimite Fisiere", command=self.send_files_dialog, font=ctk.CTkFont(size=14, weight="bold"), height=40).grid(row=2, column=0, padx=10, pady=(0, 10), sticky="ew")

        # Frame-ul de Fisiere (Dreapta)
        file_frame = ctk.CTkFrame(self)
        file_frame.grid(row=1, column=1, padx=(10, 20), pady=10, sticky="nsew")
        file_frame.grid_rowconfigure(1, weight=1)
        file_frame.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(file_frame, text="Fisiere pentru Transfer 📁", font=ctk.CTkFont(size=16, weight="bold")).grid(row=0, column=0, padx=10, pady=(10, 5))
        
        self.file_listbox_frame = tk.Frame(file_frame, bg=file_frame.cget("fg_color")[1])
        self.file_listbox_frame.grid(row=1, column=0, padx=10, pady=(0, 10), sticky="nsew")
        
        self.file_listbox = tk.Listbox(self.file_listbox_frame, selectmode=tk.MULTIPLE, font=('Arial', 12), borderwidth=0, highlightthickness=0)
        self.file_listbox.pack(fill="both", expand=True)
        
        # Frame de butoane pentru fișiere
        file_button_frame = ctk.CTkFrame(file_frame, fg_color="transparent")
        file_button_frame.grid(row=2, column=0, padx=10, pady=(0, 10), sticky="ew")
        file_button_frame.grid_columnconfigure((0, 1), weight=1)
        
        ctk.CTkButton(file_button_frame, text="Adaugă Fisiere", command=self.add_files, font=ctk.CTkFont(size=14), height=40).grid(row=0, column=0, padx=(0, 5), sticky="ew")
        ctk.CTkButton(file_button_frame, text="Șterge Selectate", command=self.remove_selected_files, font=ctk.CTkFont(size=14), height=40).grid(row=0, column=1, padx=(5, 0), sticky="ew")
        
        # Progress Bar (Partea de Jos)
        self.progress_bar = ctk.CTkProgressBar(self, orientation="horizontal", mode="determinate", height=20, fg_color="gray", progress_color="green")
        self.progress_bar.grid(row=2, column=0, columnspan=2, padx=20, pady=(10, 20), sticky="ew")
        self.progress_bar.set(0)
        
        self.progress_label = ctk.CTkLabel(self, text="Gata de transfer.", font=ctk.CTkFont(size=12))
        self.progress_label.grid(row=3, column=0, columnspan=2, padx=20, pady=(0, 10), sticky="ew")
        
        self.update_device_listbox() # Initializare

    # --- Funcții de Interfață ---
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
        # Ștergem de la coadă la cap pentru a nu afecta indexarea
        for index in reversed(selected_indices):
            self.file_listbox.delete(index)
            del self.files_to_send[index]

    def format_size(self, size_bytes):
        """Formatează dimensiunea fișierului într-un format lizibil (KB, MB, GB)."""
        if size_bytes >= 1024**3:
            return f"{size_bytes / 1024**3:.2f} GB"
        elif size_bytes >= 1024**2:
            return f"{size_bytes / 1024**2:.2f} MB"
        elif size_bytes >= 1024:
            return f"{size_bytes / 1024:.2f} KB"
        else:
            return f"{size_bytes} Bytes"

    def update_device_listbox(self):
        """Actualizează Listbox-ul cu dispozitivele detectate în timp real."""
        selected_index = None
        try:
            selected_index = self.device_listbox.curselection()[0]
        except IndexError:
            pass # Nu e selectat nimic
            
        self.device_listbox.delete(0, tk.END)
        for ip, hostname in self.devices.items():
            if ip != self.local_ip: # Nu ne afișăm pe noi înșine
                self.device_listbox.insert(tk.END, f"{hostname} ({ip})")

        # Reselectăm elementul dacă a fost selectat înainte
        if selected_index is not None and selected_index < self.device_listbox.size():
            self.device_listbox.selection_set(selected_index)
            
        # Programăm următoarea actualizare
        self.after(1000, self.update_device_listbox) 

    # --- Dialog de Trimitere (Solicitare PIN) ---
    def send_files_dialog(self):
        if not self.files_to_send:
            messagebox.showwarning("Atenție", "Vă rugăm să adăugați fișiere de trimis.")
            return

        try:
            selected_index = self.device_listbox.curselection()[0]
        except IndexError:
            messagebox.showwarning("Atenție", "Vă rugăm să selectați un dispozitiv din listă.")
            return

        # Obținem IP-ul dispozitivului selectat
        selected_device_text = self.device_listbox.get(selected_index)
        target_ip = selected_device_text.split('(')[-1].strip(')')
        
        # Crearea ferestrei de dialog pentru PIN (Toplevel)
        dialog = ctk.CTkToplevel(self)
        dialog.title("Introducere PIN")
        dialog.geometry("300x150")
        dialog.transient(self) # Fereastra rămâne deasupra
        dialog.grab_set() # Blochează interacțiunea cu fereastra principală

        ctk.CTkLabel(dialog, text=f"PIN-ul de pe {target_ip}", font=ctk.CTkFont(size=14, weight="bold")).pack(pady=10)
        pin_entry = ctk.CTkEntry(dialog, show="*", width=200, font=ctk.CTkFont(size=14))
        pin_entry.pack(pady=5)

        def start_transfer_callback():
            pin = pin_entry.get()
            if not pin:
                messagebox.showerror("Eroare PIN", "Vă rugăm să introduceți PIN-ul.")
                return
            
            dialog.destroy()
            threading.Thread(target=self.initiate_transfer, args=(target_ip, pin), daemon=True).start()
        
        ctk.CTkButton(dialog, text="Start Transfer", command=start_transfer_callback, font=ctk.CTkFont(size=14)).pack(pady=10)
        
    # --- Protocol de Rețea (Advertising și Descoperire) ---
    def broadcast_advertisement(self):
        hostname = socket.gethostname()
        message = json.dumps({"ip": self.local_ip, "hostname": hostname}).encode('utf-8')
        while self.is_running:
            try:
                # Trimite la adresa de broadcast
                self.broadcast_socket.sendto(message, ('<broadcast>', BROADCAST_PORT))
            except Exception as e:
                # print(f"Eroare la broadcasting: {e}") # Debugging
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
                    # Adaugă sau actualizează dispozitivul
                    self.devices[device_ip] = device_hostname
                    # Păstrează doar dispozitivele recent văzute (opțional: curățare pe bază de timestamp)
            except socket.timeout:
                continue
            except Exception as e:
                # print(f"Eroare la primirea broadcast: {e}") # Debugging
                continue

    # --- Protocol de Transfer (Sender Side) ---
    def initiate_transfer(self, target_ip, pin):
        """Inițiază conexiunea și trimiterea fișierelor către receiver."""
        self.progress_label.configure(text=f"Conectare la {target_ip}...")
        self.progress_bar.set(0)
        
        try:
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client_socket.connect((target_ip, TRANSFER_PORT))
            
            # 1. Trimiterea PIN-ului pentru verificare
            client_socket.sendall(pin.encode('utf-8'))
            
            # 2. Primirea răspunsului de la server
            response = client_socket.recv(1024).decode('utf-8')
            
            if response == "PIN_OK":
                key = self.derive_key(pin)
                
                # Pregătirea metadatelor tuturor fișierelor
                metadata = []
                total_size = 0
                for path, name, size in self.files_to_send:
                    metadata.append({"name": name, "size": size})
                    total_size += size
                
                # 3. Trimiterea metadatelor (număr de fișiere, nume, dimensiuni)
                metadata_json = json.dumps(metadata).encode('utf-8')
                metadata_header = len(metadata_json).to_bytes(4, byteorder='big') # Lungimea metadatelor
                
                client_socket.sendall(metadata_header)
                client_socket.sendall(metadata_json)
                
                # 4. Începe transferul fișierelor
                self.progress_label.configure(text=f"Începe transferul de {len(self.files_to_send)} fișiere...")
                
                for path, name, size in self.files_to_send:
                    self.send_file(client_socket, path, name, size, key, total_size)
                    
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
            
        self.progress_bar.set(0) # Resetare la final

    def send_file(self, sock, file_path, file_name, file_size, key, total_transfer_size):
        """Trimite un singur fișier, împărțit în chunk-uri criptate."""
        self.progress_label.configure(text=f"Transfer: {file_name}...")
        
        cipher = AES.new(key, AES.MODE_CBC)
        iv = cipher.iv # Vectorul de inițializare
        
        # 1. Trimiterea IV-ului (16 bytes)
        sock.sendall(iv) 
        
        bytes_sent = 0
        
        with open(file_path, 'rb') as f:
            while True:
                chunk = f.read(CHUNK_SIZE)
                if not chunk:
                    break
                
                # Criptare: padding + criptare
                padded_chunk = pad(chunk, AES.block_size)
                encrypted_chunk = cipher.encrypt(padded_chunk)
                
                # Trimite lungimea chunk-ului criptat (4 bytes) + chunk-ul în sine
                chunk_len_header = len(encrypted_chunk).to_bytes(4, byteorder='big')
                sock.sendall(chunk_len_header)
                sock.sendall(encrypted_chunk)
                
                bytes_sent += len(chunk)
                
                # Actualizare ProgressBar (folosind doar dimensiunea fișierului curent, pentru simplitate vizuală)
                # O implementare mai robustă ar trebui să țină cont de progresul total
                progress = bytes_sent / file_size
                self.progress_bar.set(progress)
                self.progress_label.configure(text=f"Transfer: {file_name} - {self.format_size(bytes_sent)}/{self.format_size(file_size)}")

            # Semnal de sfârșit de fișier (header de lungime zero)
            sock.sendall((0).to_bytes(4, byteorder='big'))

    # --- Protocol de Transfer (Receiver Side) ---
    def start_transfer_server(self):
        """Ascultă pe portul de transfer pentru conexiuni noi."""
        self.transfer_server_socket.listen(5)
        while self.is_running:
            try:
                conn, addr = self.transfer_server_socket.accept()
                threading.Thread(target=self.handle_transfer_request, args=(conn, addr), daemon=True).start()
            except Exception as e:
                # print(f"Eroare la acceptarea conexiunii: {e}") # Debugging
                continue

    def handle_transfer_request(self, conn, addr):
        """Gestionează o singură cerere de transfer de la un sender."""
        sender_ip = addr[0]
        
        try:
            # 1. Primirea și verificarea PIN-ului
            pin = conn.recv(1024).decode('utf-8')
            
            if pin != self.current_pin:
                conn.sendall("PIN_INCORRECT".encode('utf-8'))
                conn.close()
                return

            conn.sendall("PIN_OK".encode('utf-8'))
            key = self.derive_key(pin)
            
            # 2. Primirea metadatelor
            metadata_header = conn.recv(4)
            if not metadata_header: raise Exception("Eroare la primirea header-ului de metadate.")
            metadata_len = int.from_bytes(metadata_header, byteorder='big')
            
            metadata_json = conn.recv(metadata_len).decode('utf-8')
            metadata = json.loads(metadata_json)
            
            # 3. Pregătire director de salvare
            save_dir = os.path.join(os.getcwd(), "Received_Files")
            os.makedirs(save_dir, exist_ok=True)
            
            # 4. Primirea fișierelor
            self.progress_label.configure(text=f"Primește de la {sender_ip}...")
            
            for file_info in metadata:
                self.receive_file(conn, file_info['name'], file_info['size'], save_dir, key)
            
            self.progress_label.configure(text="✅ Toate fișierele primite. Gata de transfer.")
            self.progress_bar.set(1)

        except Exception as e:
            self.progress_label.configure(text=f"❌ Primire eșuată de la {sender_ip}. Eroare: {e}")
        finally:
            conn.close()
            self.progress_bar.set(0) # Resetare

    def receive_file(self, conn, file_name, file_size, save_dir, key):
        """Primește un singur fișier criptat, pe chunk-uri."""
        self.progress_label.configure(text=f"Primește: {file_name}...")
        save_path = os.path.join(save_dir, file_name)
        
        # 1. Primirea IV-ului (16 bytes)
        iv = conn.recv(16)
        if len(iv) != 16: raise Exception("Eroare la primirea IV-ului.")
        cipher = AES.new(key, AES.MODE_CBC, iv=iv)
        
        bytes_received = 0
        
        with open(save_path, 'wb') as f:
            while True:
                # 2. Primirea header-ului de lungime (4 bytes)
                chunk_len_header = self.recv_all(conn, 4)
                if not chunk_len_header:
                    raise Exception("Conexiune închisă neașteptat.")
                    
                encrypted_chunk_len = int.from_bytes(chunk_len_header, byteorder='big')
                
                if encrypted_chunk_len == 0:
                    break # Semnal de sfârșit de fișier
                
                # 3. Primirea chunk-ului criptat
                encrypted_chunk = self.recv_all(conn, encrypted_chunk_len)
                if not encrypted_chunk:
                    raise Exception("Conexiune închisă neașteptat în timpul primirii chunk-ului.")
                    
                # Decriptare
                decrypted_padded_chunk = cipher.decrypt(encrypted_chunk)
                decrypted_chunk = unpad(decrypted_padded_chunk, AES.block_size)

                f.write(decrypted_chunk)
                bytes_received += len(decrypted_chunk)
                
                # Actualizare ProgressBar
                progress = bytes_received / file_size
                self.progress_bar.set(progress)
                self.progress_label.configure(text=f"Primește: {file_name} - {self.format_size(bytes_received)}/{self.format_size(file_size)}")
        
        # Verificare finală a dimensiunii
        if bytes_received != file_size:
            print(f"Atenție: Dimensiunea primită ({bytes_received}) nu corespunde cu dimensiunea așteptată ({file_size}) pentru {file_name}")

    def recv_all(self, sock, n):
        """Funcție helper pentru a ne asigura că primim exact n bytes."""
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
            # O modalitate de a debloca socketul de ascultare (transfer_server_socket)
            temp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            temp_sock.connect(('127.0.0.1', TRANSFER_PORT))
            temp_sock.close()
            self.transfer_server_socket.close()
        except:
            pass
        self.destroy()

if __name__ == "__main__":
    app = FileTransferApp()
    # Asigură-te că funcția de curățare este apelată la închiderea ferestrei
    app.protocol("WM_DELETE_WINDOW", app.on_closing) 
    app.mainloop()