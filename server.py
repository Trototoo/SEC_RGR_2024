import socket
import secrets
import hashlib
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os

# Конфігурація сервера
SERVER_HOST = '127.0.0.1'
SERVER_PORT = 1222

# Згенерувати RSA ключі сервера
def generate_rsa_key_pair():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    return private_key, public_key

# Серіалізувати публічний ключ для відправки клієнту
def serialize_public_key(public_key):
    return public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)

# Розшифрувати премастер-секрет, надісланий клієнтом
def decrypt_premaster_secret(private_key, encrypted_secret):
    return private_key.decrypt(encrypted_secret, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))

# Вивести сесіонний ключ із використанням випадкових рядків та премастер-секрету
def derive_session_key(client_hello, server_hello, premaster_secret):
    combined = client_hello + server_hello + premaster_secret
    return hashlib.sha256(combined.encode()).digest()

# Симетричне шифрування та дешифрування за допомогою AES
def encrypt_message(session_key, message):
    iv = os.urandom(16)  # Generate a random IV
    cipher = Cipher(algorithms.AES(session_key), modes.CFB(iv))
    encryptor = cipher.encryptor()
    return iv + encryptor.update(message.encode()) + encryptor.finalize()

def decrypt_message(session_key, encrypted_message):
    iv = encrypted_message[:16]
    cipher = Cipher(algorithms.AES(session_key), modes.CFB(iv))
    decryptor = cipher.decryptor()
    return decryptor.update(encrypted_message[16:]) + decryptor.finalize()

def main():
    # RSA-генерація ключів
    private_key, public_key = generate_rsa_key_pair()
    serialized_public_key = serialize_public_key(public_key)
    
    # Налаштувати серверний сокет
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((SERVER_HOST, SERVER_PORT))
    server_socket.listen(1)
    print("Server is listening...")

    conn, addr = server_socket.accept()
    print(f"Connection established with {addr}")

    # Сервер отримує client_hello
    client_hello = conn.recv(1024).decode()
    print(f"Received client_hello: {client_hello}")

    # Сервер відправляє server_hello та публічний ключ
    server_hello = secrets.token_hex(16)
    conn.sendall(server_hello.encode())
    conn.sendall(serialized_public_key)
    print(f"Sent server_hello: {server_hello} and public key")

    # Сервер отримує зашифрований премастер-секрет
    encrypted_premaster_secret = conn.recv(4096)
    premaster_secret = decrypt_premaster_secret(private_key, encrypted_premaster_secret)
    print("Decrypted premaster secret")

    # Вивести сесіонний ключ
    session_key = derive_session_key(client_hello, server_hello, premaster_secret.decode())
    print("Session key derived")

    # Сервер відправляє зашифроване повідомлення про готовність
    ready_message = "server_ready"
    encrypted_ready = encrypt_message(session_key, ready_message)
    conn.sendall(encrypted_ready)
    print("Sent server_ready message encrypted")

    # Сервер отримує зашифроване повідомлення про готовність клієнта
    client_ready_encrypted = conn.recv(4096)
    client_ready = decrypt_message(session_key, client_ready_encrypted).decode()
    if client_ready == "client_ready":
        print("Handshake complete. Secure communication established.")
    else:
        print("Handshake failed.")
        conn.close()
        server_socket.close()
        return

    # Безпечне спілкування
    while True:
        encrypted_message = conn.recv(4096)
        if not encrypted_message:
            break
        decrypted_message = decrypt_message(session_key, encrypted_message).decode()
        print(f"Client: {decrypted_message}")
        
        response = input("Server: ")
        encrypted_response = encrypt_message(session_key, response)
        conn.sendall(encrypted_response)

    conn.close()
    server_socket.close()

if __name__ == "__main__":
    main()
