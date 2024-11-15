import socket
import threading
import logging
import base64
import os
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext, Entry, Button
import cryptography
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

key = Fernet.generate_key()
print(key.decode())

class SecureFileTransfer:
    def __init__(self, cipher_suite):
        self.cipher_suite = cipher_suite
        self.logger = logging.getLogger(__name__)

    def send_file(self, filename, socket):
        try:
            if not os.path.exists(filename):
                self.logger.error(f"File not found: {filename}")
                return False
            file_size = os.path.getsize(filename)
            file_info = f"FILE|{filename}|{file_size}"
            encrypted_file_info = self.cipher_suite.encrypt(file_info.encode())
            socket.send(encrypted_file_info)
            self.logger.info(f"Sending file: {filename}, size: {file_size} bytes")
            
            with open(filename, 'rb') as file:
                bytes_sent = 0
                while bytes_sent < file_size:
                    chunk = file.read(1024)
                    if not chunk:
                        break
                    encrypted_chunk = self.cipher_suite.encrypt(chunk)
                    socket.send(encrypted_chunk)
                    bytes_sent += len(chunk)
                    self.logger.debug(f"Sent {bytes_sent}/{file_size} bytes")
            self.logger.info(f"File {filename} sent successfully")
            return True
        except Exception as e:
            self.logger.error(f"Error sending file {filename}: {str(e)}", exc_info=True)
            return False

class Client:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.logger = logging.getLogger(__name__)
        self.socket = None
        self.cipher_suite = None
        self.file_transfer = None
        self.shared_key = None
        self.gui = None
        self.receive_thread = None
        self.logger.debug("Client instance initialized")

    def connect(self):
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((self.host, self.port))
            self.logger.info(f"Connected to {self.host}:{self.port}")
            return True
        except Exception as e:
            self.logger.error(f"Connection error: {str(e)}", exc_info=True)
            return False

    def setup(self):
        self.logger.debug("Starting setup process")
        if self.authenticate():
            self.logger.info("Authentication successful")
            self.exchange_keys()
            self.logger.info("Key exchange completed")
            self.file_transfer = SecureFileTransfer(self.cipher_suite)
            self.start_receive_thread()
            self.logger.info("Setup completed successfully")
            return True
        self.logger.warning("Setup failed")
        return False

    def authenticate(self):
        self.logger.debug("Starting authentication process")
        auth_response = self.socket.recv(1024)
        if auth_response != b"AUTH":
            self.logger.error("Unexpected auth response")
            return False

        auth_type = input("Enter 'register' or 'login': ").upper()
        self.socket.sendall(auth_type.encode())

        username = input("Enter username: ")
        password = input("Enter password: ")

        self.socket.sendall(username.encode())
        self.socket.sendall(password.encode())

        result = self.socket.recv(1024)
        if result in [b"REGISTERED", b"AUTHENTICATED"]:
            self.logger.info(f"Authentication successful: {result.decode()}")
            return True
        else:
            self.logger.warning(f"Authentication failed: {result.decode()}")
            return False
        
    def exchange_keys(self):
        server_key = self.socket.recv(1024)
        client_key = os.urandom(32)
        self.socket.sendall(client_key)
        shared_key = self.derive_shared_key(server_key, client_key)
        fernet_key = base64.urlsafe_b64encode(shared_key)
        self.cipher_suite = Fernet(fernet_key)
        self.logger.debug(f"Fernet key derived: {fernet_key.decode()}")
        
    def start_receive_thread(self):
        self.receive_thread = threading.Thread(target=self.receive_messages, daemon=True)
        self.receive_thread.start()

    def derive_shared_key(self, server_key, client_key):
        combined_key = server_key + client_key
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b'secure_messenger_salt',
            iterations=100000,
            backend=default_backend()
        )
        return kdf.derive(combined_key)

    def send_message(self, message):
        try:
            encrypted_message = self.cipher_suite.encrypt(message.encode())
            self.socket.sendall(encrypted_message)
            self.logger.debug(f"Sent encrypted message: {encrypted_message}")
            self.logger.info(f"Sent message: {message}")
        except Exception as e:
            self.logger.error(f"Error sending message: {str(e)}", exc_info=True)

    def receive_messages(self):
        while True:
            try:
                encrypted_message = self.socket.recv(1024)
                if not encrypted_message:
                    break
                if self.cipher_suite is None:
                    self.logger.error("Cipher suite not initialized")
                    continue
                self.logger.debug(f"Received encrypted message: {encrypted_message}")
                message = self.cipher_suite.decrypt(encrypted_message).decode()
                self.logger.info(f"Received message: {message}")
                if self.gui:
                    self.gui.update_chat(f"Received: {message}")
            except Exception as e:
                self.logger.error(f"Error receiving message: {str(e)}", exc_info=True)
                break

    def set_gui(self, gui):
        self.gui = gui

class ClientGUI:
    def __init__(self, client):
        self.client = client
        self.root = tk.Tk()
        self.root.title("Secure Messenger")
        self.create_widgets()
        self.client.set_gui(self)
        self.logger = logging.getLogger(__name__)
        self.logger.debug("GUI initialized")

    def create_widgets(self):
        self.chat_area = scrolledtext.ScrolledText(self.root, state='disabled')
        self.chat_area.pack(padx=5, pady=5)

        self.msg_entry = Entry(self.root, width=50)
        self.msg_entry.pack(side=tk.LEFT, padx=5, pady=5)

        self.send_button = Button(self.root, text="Send", command=self.send_message)
        self.send_button.pack(side=tk.LEFT, padx=5, pady=5)

        self.file_button = tk.Button(self.root, text="Send File", command=self.send_file)
        self.file_button.pack(side=tk.LEFT, padx=5, pady=5)

    print("Widgets created")

    def send_message(self):
        message = self.msg_entry.get()
        if message:
            self.client.send_message(message)
            self.update_chat(f"You: {message}")
            self.msg_entry.delete(0, tk.END)

    def send_file(self):
        filename = filedialog.askopenfilename()
        if filename:
            if self.client.file_transfer.send_file(filename, self.client.socket):
                self.update_chat(f"You sent file: {filename}")
            else:
                messagebox.showerror("Error", "Failed to send file")

    def update_chat(self, message):
        self.chat_area.config(state='normal')
        self.chat_area.insert(tk.END, message + '\n')
        self.chat_area.config(state='disabled')
        self.chat_area.see(tk.END)

    def run(self):
        print("Starting GUI mainloop")
        self.root.mainloop()

def main():
    logging.info("Starting main function")
    client = Client('127.0.0.1', 8080)
    logging.info("Client instance created")
    if client.connect():
        logging.info("Connected to server")
        if client.setup():
            logging.info("Client setup completed successfully")
            try:
                gui = ClientGUI(client)
                logging.info("GUI instance created")
                gui.run()
                logging.info("GUI run method called")
            except Exception as e:
                logging.error(f"Error initializing GUI: {str(e)}", exc_info=True)
        else:
            logging.error("Client setup failed. Exiting.")
    else:
        logging.error("Failed to connect to the server. Exiting.")

if __name__ == "__main__":
    main()