import socket
import threading
import struct
import os
import hashlib
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Util.Padding import pad, unpad
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes

# Server code

class ClientInfo:
    def __init__(self, socket, aes_key, iv):
        self.socket = socket
        self.aes_key = aes_key
        self.iv = iv

# Decrypt message using AES (CBC mode)
def aes_decrypt(ciphertext, aes_key, iv):
    try:
        cipher = AES.new(aes_key, AES.MODE_CBC, iv)
        padded_message = cipher.decrypt(ciphertext)
        return unpad(padded_message, AES.block_size).decode('utf-8')
    except ValueError as e:
        print(f"Decryption error (padding): {e}")
        return None

# Encrypt message using AES (CBC mode)
def aes_encrypt(message, aes_key, iv):
    try:
        padded_message = pad(message.encode('utf-8'), AES.block_size)
        cipher = AES.new(aes_key, AES.MODE_CBC, iv)
        return cipher.encrypt(padded_message)
    except Exception as e:
        print(f"Encryption error: {e}")
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

# Handle communication with a client
def interact_with_client(client_socket, client_address, clients):
    print(f"Client connected from {client_address}")

    # Receive the client's RSA public key
    public_key_length = struct.unpack('!I', client_socket.recv(4))[0]
    client_public_key = client_socket.recv(public_key_length)
    rsa_public_key = RSA.import_key(client_public_key)

    # Generate AES key and IV for communication with the client
    aes_key = get_random_bytes(16)
    iv = get_random_bytes(16)

    # Encrypt AES key with client's RSA public key
    cipher_rsa = PKCS1_OAEP.new(rsa_public_key)
    encrypted_aes_key = cipher_rsa.encrypt(aes_key)

    # Send encrypted AES key and IV to the client
    send_length_prefixed(client_socket, encrypted_aes_key)
    send_length_prefixed(client_socket, iv)

    # Store client info
    client_info = ClientInfo(client_socket, aes_key, iv)
    clients[client_socket] = client_info

    # Handle client messages
    while True:
        try:
            encrypted_message = receive_length_prefixed(client_socket)
            if not encrypted_message:
                print(f"Client {client_address} disconnected.")
                break

            # Print the encrypted message instead of decrypting
            print(f"Encrypted message from {client_address}: {encrypted_message.hex()}")

            # Decrypt the message from the client
            decrypted_message = aes_decrypt(encrypted_message, aes_key, iv)
            if decrypted_message:
                # Broadcast the message to all other clients
                for other_client, info in clients.items():
                    if other_client != client_socket:
                        re_encrypted_message = aes_encrypt(decrypted_message, info.aes_key, info.iv)
                        send_length_prefixed(info.socket, re_encrypted_message)
        except ConnectionResetError:
            print(f"Client {client_address} forcibly disconnected.")
            break

    # Remove the client from the list
    del clients[client_socket]
    client_socket.close()

def main():
    print("Server is starting...")

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_address = ("127.0.0.1", 12345)

    try:
        server_socket.bind(server_address)
        server_socket.listen()
        print(f"Server is listening on {server_address[0]}:{server_address[1]}")
    except socket.error as e:
        print(f"Server setup error: {e}")
        server_socket.close()
        return

    clients = {}

    try:
        while True:
            client_socket, client_address = server_socket.accept()
            print(f"New connection from {client_address}")
            client_thread = threading.Thread(target=interact_with_client, args=(client_socket, client_address, clients))
            client_thread.daemon = True
            client_thread.start()
    except KeyboardInterrupt:
        print("\nShutting down server.")
    finally:
        for client_socket in clients.keys():
            client_socket.close()
        server_socket.close()

if __name__ == "__main__":
    main()
