import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import socket
import threading
import os
import struct
import json
import queue
import hashlib
import sys

# Use 'Cryptodome' which is what you have installed (from pycryptodomex)
from Cryptodome.Cipher import AES
from Cryptodome.Protocol.KDF import PBKDF2
from Cryptodome.Hash import SHA256
from Cryptodome.Random import get_random_bytes

# --- Constants ---
HOST = '0.0.0.0' # Listen on all interfaces
FILE_PORT = 12345
DISCOVERY_PORT = 12346
BROADCAST_ADDR = '<broadcast>' # Special address for broadcasting

# Encryption settings
KEY_SIZE = 32 # 256-bit AES
NONCE_SIZE = 16 # GCM Nonce
TAG_SIZE = 16 # GCM Tag
SALT_SIZE = 16
PBKDF2_ITERATIONS = 100000
CHUNK_SIZE = 65536 # 64KB chunks

# Discovery messages
MSG_PRESENCE = b'P2P_FILE_SHARE_HELLO'
MSG_ACK = b'P2P_FILE_SHARE_ACK'

class FileTransferApp:
    def __init__(self, master):
        self.master = master
        self.master.title("Secure LAN File Transfer")
        self.master.geometry("600x650")

        # Style
        self.style = ttk.Style()
        self.style.theme_use('clam')
        
        # Configure styles
        self.style.configure('.', background='#2E2E2E', foreground='#E0E0E0', font=('Arial', 10))
        self.style.configure('TFrame', background='#2E2E2E')
        self.style.configure('TLabel', background='#2E2E2E', foreground='#E0E0E0')
        self.style.configure('TButton', background='#4A4A4A', foreground='#E0E0E0', borderwidth=1)
        self.style.map('TButton', background=[('active', '#5A5A5A')])
        self.style.configure('TNotebook', background='#2E2E2E', borderwidth=0)
        self.style.configure('TNotebook.Tab', background='#3C3C3C', foreground='#E0E0E0', padding=[10, 5])
        self.style.map('TNotebook.Tab', background=[('selected', '#4A4A4A'), ('active', '#5A5A5A')])
        self.style.configure('TEntry', fieldbackground='#4A4A4A', foreground='#E0E0E0', borderwidth=1)
        self.style.configure('TScrolledText', background='#4A4A4A', foreground='#E0E0E0')
        self.style.configure('TListbox', background='#4A4A4A', foreground='#E0E0E0')
        
        self.master.configure(background='#2E2E2E')
        
        # --- State Variables ---
        self.selected_filepath = ""
        self.listen_thread = None
        self.discovery_server_thread = None
        self.discovery_client_thread = None
        self.stop_listening = threading.Event()
        self.stop_discovery_server = threading.Event()
        self.stop_discovery_thread = threading.Event()
        self.discovered_peers = set()

        # --- Log Queue ---
        self.log_queue = queue.Queue()
        
        # --- Main UI ---
        self.notebook = ttk.Notebook(master)
        
        self.send_tab = ttk.Frame(self.notebook, padding=10)
        self.receive_tab = ttk.Frame(self.notebook, padding=10)
        
        self.notebook.add(self.send_tab, text='Send File')
        self.notebook.add(self.receive_tab, text='Receive File')
        self.notebook.pack(expand=True, fill='both')

        self.create_send_tab()
        self.create_receive_tab()
        
        self.master.after(100, self.process_log_queue)
        self.master.protocol("WM_DELETE_WINDOW", self.on_closing)

    def create_send_tab(self):
        # --- Peer Discovery ---
        discover_frame = ttk.Frame(self.send_tab)
        discover_frame.pack(fill='x', pady=(0, 10))
        
        self.discover_button = ttk.Button(discover_frame, text="Discover Peers", command=self.start_discovery_thread)
        self.discover_button.pack(side='left', fill='x', expand=True, ipady=5)

        self.peer_list_label = ttk.Label(self.send_tab, text="Discovered Peers:")
        self.peer_list_label.pack(fill='x', pady=(5,0))
        
        self.peer_listbox = tk.Listbox(self.send_tab, height=5, bg='#4A4A4A', fg='#E0E0E0', highlightthickness=0, borderwidth=1, relief='solid')
        self.peer_listbox.pack(fill='x', pady=5)
        self.peer_listbox.bind('<<ListboxSelect>>', self.on_peer_select)
        
        # --- Target ---
        target_frame = ttk.Frame(self.send_tab)
        target_frame.pack(fill='x', pady=5)
        
        target_label = ttk.Label(target_frame, text="Target IP:")
        target_label.pack(side='left', padx=(0, 10))
        
        self.target_ip_entry = ttk.Entry(target_frame)
        self.target_ip_entry.pack(side='left', fill='x', expand=True)

        # --- File Selection ---
        file_frame = ttk.Frame(self.send_tab)
        file_frame.pack(fill='x', pady=10)
        
        self.select_file_button = ttk.Button(file_frame, text="Select File", command=self.select_file)
        self.select_file_button.pack(side='left', ipady=5)
        
        self.selected_file_label = ttk.Label(file_frame, text="No file selected.", foreground="gray", wraplength=350)
        self.selected_file_label.pack(side='left', fill='x', expand=True, padx=10)

        # --- Password ---
        password_frame = ttk.Frame(self.send_tab)
        password_frame.pack(fill='x', pady=5)

        password_label = ttk.Label(password_frame, text="Encryption Password:")
        password_label.pack(side='left', padx=(0, 10))
        
        self.send_password_entry = ttk.Entry(password_frame, show="*")
        self.send_password_entry.pack(side='left', fill='x', expand=True)

        # --- Send Button ---
        self.send_button = ttk.Button(self.send_tab, text="Send File", state="disabled", command=self.start_send_thread)
        self.send_button.pack(fill='x', ipady=10, pady=10)
        
        # --- Status Log ---
        log_label = ttk.Label(self.send_tab, text="Send Status:")
        log_label.pack(fill='x', pady=(5,0))
        
        self.send_status_log = scrolledtext.ScrolledText(self.send_tab, height=8, width=70, state='disabled', bg='#4A4A4A', fg='#E0E0E0')
        self.send_status_log.pack(fill='both', expand=True, pady=5)

    def create_receive_tab(self):
        # --- IP Info ---
        ip_frame = ttk.Frame(self.receive_tab)
        ip_frame.pack(fill='x', pady=5)
        
        ip_label = ttk.Label(ip_frame, text="Your Local IP Address:")
        ip_label.pack(side='left')
        
        local_ip = self.get_local_ip()
        self.ip_display = ttk.Entry(ip_frame, state='readonly')
        self.ip_display.insert(0, local_ip)
        self.ip_display.pack(side='left', fill='x', expand=True, padx=10)
        
        # --- Password ---
        password_frame = ttk.Frame(self.receive_tab)
        password_frame.pack(fill='x', pady=10)

        password_label = ttk.Label(password_frame, text="Decryption Password:")
        password_label.pack(side='left', padx=(0, 10))
        
        self.receive_password_entry = ttk.Entry(password_frame, show="*")
        self.receive_password_entry.pack(side='left', fill='x', expand=True)
        
        # --- Listen Button ---
        self.listen_button = ttk.Button(self.receive_tab, text="Start Listening", command=self.toggle_listening)
        self.listen_button.pack(fill='x', ipady=10, pady=10)
        
        # --- Status Log ---
        log_label = ttk.Label(self.receive_tab, text="Receive Status:")
        log_label.pack(fill='x', pady=(5,0))
        
        self.receive_status_log = scrolledtext.ScrolledText(self.receive_tab, height=12, width=70, state='disabled', bg='#4A4A4A', fg='#E0E0E0')
        self.receive_status_log.pack(fill='both', expand=True, pady=5)

    def log_message(self, log_widget, message):
        """Thread-safe way to log messages to a Tkinter widget."""
        def update_log():
            log_widget.config(state='normal')
            log_widget.insert(tk.END, message + "\n")
            log_widget.see(tk.END)
            log_widget.config(state='disabled')
        
        if self.master.winfo_exists(): # Check if window is still open
            log_widget.after(0, update_log)

    def process_log_queue(self):
        """Processes messages from the log queue to update the UI."""
        try:
            while not self.log_queue.empty():
                log_widget, message = self.log_queue.get_nowait()
                log_widget.config(state='normal')
                log_widget.insert(tk.END, message + "\n")
                log_widget.see(tk.END)
                log_widget.config(state='disabled')
        except queue.Empty:
            pass
        finally:
            if self.master.winfo_exists():
                self.master.after(100, self.process_log_queue)

    def get_local_ip(self):
        """Finds the local IP address of the machine."""
        s = None
        try:
            # Connect to a public server (doesn't send data)
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80)) # Google's DNS
            ip = s.getsockname()[0]
        except Exception as e:
            self.log_queue.put((self.receive_status_log, f"Warning: Could not auto-detect IP: {e}"))
            ip = "127.0.0.1" # Fallback to loopback
        finally:
            if s:
                s.close()
        return ip

    def on_peer_select(self, event):
        """Called when a user clicks an IP in the peer list."""
        try:
            selected_indices = self.peer_listbox.curselection()
            if not selected_indices:
                return
            selected_ip = self.peer_listbox.get(selected_indices[0])
            self.target_ip_entry.delete(0, tk.END)
            self.target_ip_entry.insert(0, selected_ip)
        except Exception as e:
            self.log_queue.put((self.send_status_log, f"Error selecting peer: {e}"))

    def select_file(self):
        self.selected_filepath = filedialog.askopenfilename()
        if self.selected_filepath:
            filename = os.path.basename(self.selected_filepath)
            self.selected_file_label.config(text=filename, foreground="#E0E0E0")
            self.send_button.config(state="normal")
        else:
            self.selected_file_label.config(text="No file selected.", foreground="gray")
            self.send_button.config(state="disabled")

    def derive_key(self, password, salt):
        """Derives a 256-bit AES key from a password and salt using PBKDF2."""
        # We must use the SHA256 module from Cryptodome, not hashlib
        return PBKDF2(password, salt, dkLen=KEY_SIZE, count=PBKDF2_ITERATIONS, hmac_hash_module=SHA256)

    # --- Send Logic ---

    def start_discovery_thread(self):
        """Starts the peer discovery client thread."""
        self.log_queue.put((self.send_status_log, "Discovering peers..."))
        self.discover_button.config(state="disabled")
        self.discovered_peers.clear()
        self.peer_listbox.delete(0, tk.END)
        self.stop_discovery_thread.clear()
        
        self.discovery_client_thread = threading.Thread(target=self.discover_peers_logic, daemon=True)
        self.discovery_client_thread.start()
        
        # Re-enable the button after a timeout
        self.master.after(5000, lambda: self.discover_button.config(state="normal"))

    def discover_peers_logic(self):
        """Sends a broadcast and listens for replies."""
        my_ip = self.get_local_ip()
        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            sock.settimeout(3.0) # Listen for replies for 3 seconds
            
            sock.sendto(MSG_PRESENCE, (BROADCAST_ADDR, DISCOVERY_PORT))
            
            while not self.stop_discovery_thread.is_set():
                try:
                    data, addr = sock.recvfrom(1024)
                    if data == MSG_ACK:
                        peer_ip = addr[0]
                        # This check was removed to allow self-discovery for testing
                        # if peer_ip != my_ip: 
                        self.log_queue.put((self.send_status_log, f"Discovered peer: {peer_ip}"))
                        self.master.after(0, self.add_peer_to_list, peer_ip)

                except socket.timeout:
                    # This is expected, means the discovery period is over
                    break
                except Exception as e:
                    if self.stop_discovery_thread.is_set():
                        break
                    self.log_queue.put((self.send_status_log, f"Discovery error: {e}"))
            
        except Exception as e:
            self.log_queue.put((self.send_status_log, f"Discovery failed: {e}"))
        finally:
            if sock:
                sock.close()
            self.log_queue.put((self.send_status_log, "Discovery finished."))

    def add_peer_to_list(self, ip):
        """Thread-safe way to add a peer to the listbox."""
        if ip not in self.discovered_peers:
            self.discovered_peers.add(ip)
            self.peer_listbox.insert(tk.END, ip)

    def start_send_thread(self):
        """Starts the file sending logic in a new thread."""
        self.send_button.config(state="disabled")
        send_thread = threading.Thread(target=self.send_file_logic, daemon=True)
        send_thread.start()

    def send_file_logic(self):
        """The core logic for sending a file."""
        target_ip = self.target_ip_entry.get()
        password = self.send_password_entry.get()
        filepath = self.selected_filepath

        if not target_ip or not password or not filepath:
            self.log_queue.put((self.send_status_log, "Error: IP, password, and file must be set."))
            self.master.after(0, lambda: self.send_button.config(state="normal"))
            return

        filename = os.path.basename(filepath)
        filesize = os.path.getsize(filepath)
        
        log = lambda msg: self.log_queue.put((self.send_status_log, msg))
        
        sock = None
        f = None
        try:
            log(f"Starting to send {filename}...")
            
            # 1. Derive key
            log("1. Deriving encryption key...")
            salt = get_random_bytes(SALT_SIZE)
            key = self.derive_key(password, salt)
            
            # 2. Create cipher
            cipher = AES.new(key, AES.MODE_GCM)
            
            # 3. Create metadata
            metadata = {
                'filename': filename,
                'filesize': filesize,
                'salt': salt.hex(),
                'nonce': cipher.nonce.hex()
            }
            metadata_json = json.dumps(metadata)
            metadata_bytes = metadata_json.encode('utf-8')
            
            # 4. Connect to receiver
            log(f"2. Connecting to {target_ip}:{FILE_PORT}...")
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((target_ip, FILE_PORT))
            
            # 5. Send metadata length and metadata
            log("3. Sending file metadata...")
            sock.sendall(struct.pack('>I', len(metadata_bytes)))
            sock.sendall(metadata_bytes)

            # 6. Send encrypted file in chunks
            log("4. Encrypting and sending file...")
            f = open(filepath, 'rb')
            bytes_sent = 0
            while True:
                chunk = f.read(CHUNK_SIZE)
                if not chunk:
                    break # End of file
                
                encrypted_chunk = cipher.encrypt(chunk)
                sock.sendall(encrypted_chunk)
                
                bytes_sent += len(chunk)
                log(f"   Sent {bytes_sent * 100 / filesize:.2f}%")

            # 7. Finalize encryption and send tag
            log("5. Sending authentication tag...")
            tag = cipher.digest()
            sock.sendall(tag)
            
            log(f"Successfully sent {filename}!")

        except Exception as e:
            log(f"An error occurred: {e}")
        finally:
            if f:
                f.close()
            if sock:
                sock.close()
            self.master.after(0, lambda: self.send_button.config(state="normal"))

    # --- Receive Logic ---

    def toggle_listening(self):
        """Starts or stops the listening and discovery server threads."""
        if self.listen_thread and self.listen_thread.is_alive():
            # We are currently listening, so stop
            self.log_queue.put((self.receive_status_log, "Stopping listener..."))
            self.stop_listening.set()
            self.stop_discovery_server.set()
            self.listen_button.config(text="Start Listening")
            
            # We need to connect to the server socket to unblock the accept() call
            try:
                # Use a dummy socket to connect to ourselves
                dummy_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                dummy_sock.connect(('127.0.0.1', FILE_PORT))
                dummy_sock.close()
            except ConnectionRefusedError:
                pass # Server already down, that's fine
            
        else:
            # We are not listening, so start
            self.stop_listening.clear()
            self.stop_discovery_server.clear()
            
            self.listen_thread = threading.Thread(target=self.listen_for_files, daemon=True)
            self.listen_thread.start()
            
            self.discovery_server_thread = threading.Thread(target=self.run_discovery_server, daemon=True)
            self.discovery_server_thread.start()
            
            self.listen_button.config(text="Stop Listening")
            self.log_queue.put((self.receive_status_log, f"Listening on port {FILE_PORT}..."))
            self.log_queue.put((self.receive_status_log, f"Discovery server on port {DISCOVERY_PORT}..."))

    def run_discovery_server(self):
        """Listens for UDP broadcasts and replies to them."""
        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.bind((HOST, DISCOVERY_PORT))
            
            while not self.stop_discovery_server.is_set():
                try:
                    data, addr = sock.recvfrom(1024)
                    if data == MSG_PRESENCE:
                        # Got a ping, send an ack back
                        sock.sendto(MSG_ACK, addr)
                except Exception as e:
                    if not self.stop_discovery_server.is_set():
                        self.log_queue.put((self.receive_status_log, f"Discovery server error: {e}"))
                        
        except Exception as e:
            if not self.stop_discovery_server.is_set():
                self.log_queue.put((self.receive_status_log, f"Discovery server failed to start: {e}"))
        finally:
            if sock:
                sock.close()

    def listen_for_files(self):
        """The main TCP server loop for receiving files."""
        server_sock = None
        try:
            server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server_sock.bind((HOST, FILE_PORT))
            server_sock.listen(5)

            while not self.stop_listening.is_set():
                try:
                    conn, addr = server_sock.accept()
                    if self.stop_listening.is_set():
                        if conn:
                            conn.close()
                        break
                    
                    # Handle the connection in a new thread
                    handler_thread = threading.Thread(target=self.handle_connection, args=(conn, addr), daemon=True)
                    handler_thread.start()
                except Exception as e:
                    if self.stop_listening.is_set():
                        break # This is an expected error during shutdown
                    self.log_queue.put((self.receive_status_log, f"Error accepting connection: {e}"))
        
        except Exception as e:
            if not self.stop_listening.is_set():
                self.log_queue.put((self.receive_status_log, f"Listener socket error: {e}"))
        finally:
            if server_sock:
                server_sock.close()
            self.log_queue.put((self.receive_status_log, "Listener stopped."))

    def handle_connection(self, conn, addr):
        """Handles a single incoming file transfer connection."""
        log = lambda msg: self.log_queue.put((self.receive_status_log, msg))
        log(f"Accepted connection from {addr[0]}:{addr[1]}")
        
        password = self.receive_password_entry.get()
        if not password:
            log(f"[{addr[0]}] Error: No password set. Connection refused.")
            conn.close()
            return

        f = None
        try:
            # 1. Receive metadata length
            metadata_len_bytes = conn.recv(4)
            if not metadata_len_bytes:
                log(f"[{addr[0]}] Client disconnected before sending data.")
                return
            
            metadata_len = struct.unpack('>I', metadata_len_bytes)[0]
            
            # 2. Receive metadata
            log(f"[{addr[0]}] Receiving metadata...")
            metadata_bytes = conn.recv(metadata_len)
            metadata = json.loads(metadata_bytes.decode('utf-8'))
            
            filename = metadata['filename']
            filesize = metadata['filesize']
            salt = bytes.fromhex(metadata['salt'])
            nonce = bytes.fromhex(metadata['nonce'])
            
            log(f"[{addr[0]}] Incoming file: {filename} ({filesize} bytes)")

            # 3. Ask user where to save
            save_path = self.master.after(0, self.ask_save_path, filename)
            # This is a bit tricky. We need to wait for the main thread to run the dialog.
            # A more robust way uses events, but this is simpler for now.
            # Let's poll for the result.
            save_path_result = [None] # Use a list so it's mutable from inner func
            def get_save_path():
                save_path_result[0] = filedialog.asksaveasfilename(initialfile=filename)
            
            self.master.after(0, get_save_path)
            
            while save_path_result[0] is None: # Wait for dialog
                if self.stop_listening.is_set():
                    raise Exception("Shutdown requested.")
                pass

            save_path = save_path_result[0]
            if not save_path:
                log(f"[{addr[0]}] Save cancelled by user.")
                raise Exception("Save cancelled.")

            # 4. Derive key and create cipher
            log(f"[{addr[0]}] Deriving key...")
            key = self.derive_key(password, salt)
            cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)

            # 5. Receive file, decrypt, and write
            log(f"[{addr[0]}] Receiving and decrypting file...")
            f = open(save_path, 'wb')
            bytes_received = 0
            
            while bytes_received < filesize:
                # We read in encrypted chunk size, but must account for final, smaller chunk
                bytes_to_read = min(CHUNK_SIZE, filesize - bytes_received)
                
                encrypted_chunk = conn.recv(bytes_to_read)
                if not encrypted_chunk:
                    raise Exception("Connection lost unexpectedly.")
                    
                decrypted_chunk = cipher.decrypt(encrypted_chunk)
                f.write(decrypted_chunk)
                bytes_received += len(decrypted_chunk) # Use decrypted length
                log(f"   Received {bytes_received * 100 / filesize:.2f}%")

            # 6. Receive and verify tag
            log(f"[{addr[0]}] Authenticating file...")
            tag = conn.recv(TAG_SIZE)
            cipher.verify(tag) # This will raise ValueError if auth fails
            
            log(f"[{addr[0]}] Success! File saved to {save_path}")

        except (ValueError, TypeError):
            log(f"[{addr[0]}] DECRYPTION FAILED! Incorrect password or corrupted file.")
            if f:
                f.close()
                os.remove(save_path) # Delete the corrupted file
        except Exception as e:
            log(f"[{addr[0]}] Error: {e}")
            if "Save cancelled" not in str(e) and f:
                f.close()
                if os.path.exists(save_path):
                    os.remove(save_path) # Delete partial/corrupted file
        finally:
            if f and not f.closed:
                f.close()
            conn.close()
            log(f"[{addr[0]}] Connection closed.")

    def ask_save_path(self, filename):
        """Placeholder - the real logic is injected into the main thread."""
        pass 

    def on_closing(self):
        """Handle window close event."""
        self.stop_listening.set()
        self.stop_discovery_server.set()
        self.stop_discovery_thread.set()
        
        # Unblock the listener
        try:
            dummy_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            dummy_sock.connect(('127.0.0.1', FILE_PORT))
            dummy_sock.close()
        except ConnectionRefusedError:
            pass # Server already down
            
        self.master.quit()
        self.master.destroy()

if __name__ == "__main__":
    # Handle high-DPI scaling
    if sys.platform.startswith("win"):
        try:
            from ctypes import windll
            windll.shcore.SetProcessDpiAwareness(1)
        except:
            pass # Ignore if it fails

    root = tk.Tk()
    app = FileTransferApp(root)
    root.mainloop()