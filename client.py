import socket
import secrets
import hashlib
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os

# Конфігурація клієнта
SERVER_HOST = '127.0.0.1'
SERVER_PORT = 1222

# Завантажити публічний ключ сервера
def load_public_key(serialized_public_key):
    return serialization.load_pem_public_key(serialized_public_key)

# Зашифрувати премастер секрет за допомогою публічного ключа сервера
def encrypt_premaster_secret(public_key, premaster_secret):
    return public_key.encrypt(premaster_secret.encode(), padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))

# Вивести сесіонний ключ
def derive_session_key(client_hello, server_hello, premaster_secret):
    combined = client_hello + server_hello + premaster_secret
    return hashlib.sha256(combined.encode()).digest()

# Симетричне шифрування та дешифрування
def encrypt_message(session_key, message):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(session_key), modes.CFB(iv))
    encryptor = cipher.encryptor()
    return iv + encryptor.update(message.encode()) + encryptor.finalize()

def decrypt_message(session_key, encrypted_message):
    iv = encrypted_message[:16]
    cipher = Cipher(algorithms.AES(session_key), modes.CFB(iv))
    decryptor = cipher.decryptor()
    return decryptor.update(encrypted_message[16:]) + decryptor.finalize()

def main():
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((SERVER_HOST, SERVER_PORT))
    print("Connected to the server.")

    # Надіслати client_hello
    client_hello = secrets.token_hex(16)
    client_socket.sendall(client_hello.encode())
    print(f"Sent client_hello: {client_hello}")

    # Отримати server_hello та публічний ключ
    server_hello = client_socket.recv(1024).decode()
    serialized_public_key = client_socket.recv(4096)
    public_key = load_public_key(serialized_public_key)
    print(f"Received server_hello: {server_hello}")

    # Згенерувати та надіслати зашифрований премастер секрет
    premaster_secret = secrets.token_hex(16)
    encrypted_premaster_secret = encrypt_premaster_secret(public_key, premaster_secret)
    client_socket.sendall(encrypted_premaster_secret)
    print("Sent encrypted premaster secret.")

    # Вивести сесіонний ключ
    session_key = derive_session_key(client_hello, server_hello, premaster_secret)
    print("Session key derived.")

    # Отримати та надіслати повідомлення про готовність
    encrypted_ready = client_socket.recv(4096)
    server_ready = decrypt_message(session_key, encrypted_ready).decode()
    print(f"Received server ready: {server_ready}")

    if server_ready == "server_ready":
        print("Server is ready.")
    else:
        print("Server is not ready.")
        client_socket.close()
        return

    client_ready_message = "client_ready"
    encrypted_client_ready = encrypt_message(session_key, client_ready_message)
    client_socket.sendall(encrypted_client_ready)
    print("Sent client_ready message.")

    # Безпечне спілкування
    while True:
        message = input("Client: ")
        encrypted_message = encrypt_message(session_key, message)
        client_socket.sendall(encrypted_message)

        encrypted_response = client_socket.recv(4096)
        response = decrypt_message(session_key, encrypted_response).decode()
        print(f"Server: {response}")

if __name__ == "__main__":
    main()
