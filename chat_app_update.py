import socket
import threading
import struct
import os
import hashlib
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Util.Padding import pad, unpad
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes

# AES encryption and decryption
aes_key = get_random_bytes(16)  # AES-128 key
iv = get_random_bytes(16)       # Initialization Vector

# Hash a password
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# Add a new user
def add_user(username, password):
    if os.path.isfile(f"{username}_users.txt"):
        print("Error: Username already exists.")
        return
    with open(f"{username}_users.txt", "w") as user_file:
        user_file.write(hash_password(password) + "\n")
    print("User added successfully.")

# Authenticate a user
def authenticate_user(username, password):
    if os.path.isfile(f"{username}_users.txt"):
        with open(f"{username}_users.txt", "r") as user_file:
            stored_password = user_file.readline().strip()
        return stored_password == hash_password(password)
    return False

# Encrypt message using AES (CBC mode)
def aes_encrypt(message, aes_key, iv):
    try:
        padded_message = pad(message.encode('utf-8'), AES.block_size)
        cipher = AES.new(aes_key, AES.MODE_CBC, iv)
        return cipher.encrypt(padded_message)
    except Exception as e:
        print(f"Encryption error: {e}")
        return None

# Decrypt message using AES (CBC mode)
def aes_decrypt(ciphertext, aes_key, iv):
    try:
        cipher = AES.new(aes_key, AES.MODE_CBC, iv)
        padded_message = cipher.decrypt(ciphertext)
        return unpad(padded_message, AES.block_size).decode('utf-8')
    except ValueError as e:
        print(f"Decryption error: {e}")
        return None

# Send a length-prefixed message
def send_length_prefixed(sock, message):
    message_length = len(message)
    sock.sendall(struct.pack('!I', message_length) + message)

# Receive a length-prefixed message
def receive_length_prefixed(sock):
    raw_msglen = sock.recv(4)
    if not raw_msglen:
        return None
    msglen = struct.unpack('!I', raw_msglen)[0]
    return sock.recv(msglen)

