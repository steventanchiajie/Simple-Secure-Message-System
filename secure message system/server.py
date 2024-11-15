import base64
import json
import socket
import threading
import logging
import os
import hashlib
import cryptography
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

key = Fernet.generate_key()
print(key.decode())

class UserAuth:
    def __init__(self):
        self.users_file = 'users.json'
        self.users = self.load_users()
        
    def load_users(self):
        if os.path.exists(self.users_file):
            with open(self.users_file, 'r') as f:
                return json.load(f)
        return {}

    def save_users(self):
        with open(self.users_file, 'w') as f:
            json.dump(self.users, f)
        
    def register_user(self, username, password):
        if username in self.users:
            return False
        salt = os.urandom(32)
        hashed_password = self._hash_password(password, salt)
        self.users[username] = {
            'salt': base64.b64encode(salt).decode('utf-8'),
            'hashed_password': base64.b64encode(hashed_password).decode('utf-8')
        }
        self.save_users()
        return True

    def authenticate_user(self, username, password):
        if username not in self.users:
            return False
        salt = base64.b64decode(self.users[username]['salt'].encode('utf-8'))
        stored_hash = base64.b64decode(self.users[username]['hashed_password'].encode('utf-8'))
        return self._hash_password(password, salt) == stored_hash

    def _hash_password(self, password, salt):
        return hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)


class SecureFileTransfer:
    def __init__(self, cipher_suite):
        self.cipher_suite = cipher_suite
        self.logger = logging.getLogger(__name__)

    def receive_file(self, socket):
        try:
            encrypted_file_info = socket.recv(1024)
            file_info = self.cipher_suite.decrypt(encrypted_file_info).decode()
            _, filename, file_size = file_info.split('|')
            file_size = int(file_size)
            self.logger.info(f"Receiving file: {filename}, size: {file_size} bytes")
            
            with open(filename, 'wb') as file:
                bytes_received = 0
                while bytes_received < file_size:
                    encrypted_chunk = socket.recv(min(1024, file_size - bytes_received))
                    chunk = self.cipher_suite.decrypt(encrypted_chunk)
                    file.write(chunk)
                    bytes_received += len(chunk)
                    self.logger.debug(f"Received {bytes_received}/{file_size} bytes")
            self.logger.info(f"File {filename} received successfully")
            return filename
        except Exception as e:
            self.logger.error(f"Error receiving file: {str(e)}", exc_info=True)
            return None

class Server:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.user_auth = UserAuth()
        self.logger = logging.getLogger(__name__)
        self.clients = {}
        self.clients_lock = threading.Lock()

    def start(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind((self.host, self.port))
            s.listen(1)
            self.logger.info(f"Server listening on {self.host}:{self.port}")
            while True:
                conn, addr = s.accept()
                self.logger.info(f"Connected by {addr}")
                client_thread = threading.Thread(target=self.handle_client, args=(conn, addr))
                client_thread.start()

    def handle_client(self, conn, addr):
        try:
            auth_success, cipher_suite = self.authenticate_client(conn)
            if not auth_success:
                return

            self.logger.info(f"Key exchange completed with {addr}")
            file_transfer = SecureFileTransfer(cipher_suite)

            with self.clients_lock:
                self.clients[addr] = {"conn": conn, "cipher": cipher_suite}

            while True:
                encrypted_message = conn.recv(1024)
                if not encrypted_message:
                    break
                self.logger.debug(f"Received encrypted message from {addr}: {encrypted_message}")
                message = cipher_suite.decrypt(encrypted_message).decode()
                self.logger.info(f"Decrypted message from {addr}: {message}")

                if message.startswith("FILE|"):
                    filename = file_transfer.receive_file(conn)
                    if filename:
                        self.broadcast_message(f"File received: {filename}", addr)
                else:
                    self.broadcast_message(message, addr)

        except Exception as e:
            self.logger.error(f"Error handling client {addr}: {str(e)}", exc_info=True)
        finally:
            with self.clients_lock:
                if addr in self.clients:
                    del self.clients[addr]
            conn.close()

    def authenticate_client(self, conn):
        conn.sendall(b"AUTH")
        auth_type = conn.recv(1024).decode()
        
        if auth_type == "REGISTER":
            username = conn.recv(1024).decode()
            password = conn.recv(1024).decode()
            if self.user_auth.register_user(username, password):
                conn.sendall(b"REGISTERED")
                cipher_suite = self.exchange_keys(conn)
                return True, cipher_suite
            else:
                conn.sendall(b"REGISTRATION_FAILED")
                return False, None
        elif auth_type == "LOGIN":
            username = conn.recv(1024).decode()
            password = conn.recv(1024).decode()
            if self.user_auth.authenticate_user(username, password):
                conn.sendall(b"AUTHENTICATED")
                cipher_suite = self.exchange_keys(conn)
                return True, cipher_suite
            else:
                conn.sendall(b"AUTH_FAILED")
                return False, None
        else:
            return False, None
        
    def exchange_keys(self, conn):
        server_key = os.urandom(32)
        conn.sendall(server_key)
        client_key = conn.recv(1024)
        shared_key = self.derive_shared_key(server_key, client_key)
        fernet_key = base64.urlsafe_b64encode(shared_key)
        self.logger.debug(f"Fernet key derived: {fernet_key.decode()}")
        return Fernet(fernet_key)

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

    def broadcast_message(self, message, sender_addr):
        with self.clients_lock:
            for addr, client_info in self.clients.items():
                if addr != sender_addr:
                    try:
                        encrypted_message = client_info["cipher"].encrypt(message.encode())
                        client_info["conn"].sendall(encrypted_message)
                    except Exception as e:
                        self.logger.error(f"Error broadcasting to {addr}: {str(e)}")

if __name__ == "__main__":
    server = Server('127.0.0.1', 8080)
    server.start()