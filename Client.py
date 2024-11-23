import socket
import threading
import os
import hashlib
from Crypto.Cipher import DES, PKCS1_OAEP
from Crypto.Util.Padding import pad, unpad
from Crypto.PublicKey import RSA

# Global variables
DES_KEY = None
private_key = RSA.generate(2048)
public_key = private_key.publickey()
logged_in_user = None


# Hash a password
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()


# Check if a user exists
def user_exists(username):
    return os.path.isfile(f"{username}_users.txt")


# Add a new user
def add_user(username, password):
    if user_exists(username):
        print("Error: Username already exists.")
        return
    hashed_password = hash_password(password)
    with open(f"{username}_users.txt", "w") as user_file:
        user_file.write(hashed_password + "\n")
    print("User added successfully.")


# Authenticate a user
def authenticate_user(username, password):
    if user_exists(username):
        with open(f"{username}_users.txt", "r") as user_file:
            stored_password = user_file.readline().strip()
        if stored_password == hash_password(password):
            return True
    return False


# Save an encrypted message to chat history
def save_message(username, encrypted_message):
    with open(f"{username}_messages.txt", "ab") as history_file:
        history_file.write(encrypted_message + b"\n")


# View chat history
def view_chat_history(username):
    try:
        with open(f"{username}_messages.txt", "rb") as history_file:
            for line in history_file:
                try:
                    decrypted_message = des_decrypt(line.strip(), DES_KEY)
                    print(decrypted_message)
                except ValueError:
                    print("Corrupted message in chat history.")
    except FileNotFoundError:
        print("No chat history found.")


# DES encryption
def des_encrypt(message, des_key):
    cipher = DES.new(des_key, DES.MODE_ECB)
    padded_message = pad(message.encode(), DES.block_size)
    return cipher.encrypt(padded_message)


# DES decryption
def des_decrypt(encrypted_message, des_key):
    cipher = DES.new(des_key, DES.MODE_ECB)
    return unpad(cipher.decrypt(encrypted_message), DES.block_size).decode()


# Handle sending messages
def send_msg(sock, username):
    name = input("Enter your chat name: ")
    while True:
        message = input()
        if message.lower() == "exit":
            print("Exiting chat.")
            break
        encrypted_message = des_encrypt(f"{name}: {message}", DES_KEY)
        sock.sendall(encrypted_message)
        save_message(username, encrypted_message)
    sock.close()


# Handle receiving messages
def receive_msg(sock):
    while True:
        try:
            encrypted_data = sock.recv(4096)
            if not encrypted_data:
                print("Disconnected from the server.")
                break
            decrypted_message = des_decrypt(encrypted_data, DES_KEY)
            print(f"Decrypted message: {decrypted_message}")
        except ValueError:
            print("Decryption failed. Check DES key and message format.")
        except (ConnectionResetError, BrokenPipeError):
            print("Server connection lost unexpectedly.")
            break
    sock.close()


def main():
    while True:
        print("Choose an option:")
        print("1. Signup")
        print("2. Login")
        print("3. Exit")
        choice = input().strip()

        if choice == "1":
            username = input("Enter a username: ").strip()
            password = input("Enter a password: ").strip()
            add_user(username, password)

        elif choice == "2":
            username = input("Enter your username: ").strip()
            password = input("Enter your password: ").strip()
            if authenticate_user(username, password):
                global logged_in_user
                logged_in_user = username

                server_address = "127.0.0.1"
                port = 12345

                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
                    try:
                        client_socket.connect((server_address, port))
                        print("Successfully connected to the server.")

                        # Send public key to server
                        client_socket.sendall(public_key.export_key())

                        # Receive DES key
                        encrypted_des_key = client_socket.recv(4096)
                        global DES_KEY
                        DES_KEY = PKCS1_OAEP.new(private_key).decrypt(encrypted_des_key)
                        print(f"DES key successfully received: {DES_KEY.hex()}")

                        while True:
                            print("Choose an option:")
                            print("1. View Chat History")
                            print("2. Enter Chat")
                            print("3. Logout")
                            inner_choice = input().strip()

                            if inner_choice == "1":
                                view_chat_history(username)
                            elif inner_choice == "2":
                                sender_thread = threading.Thread(target=send_msg, args=(client_socket, username))
                                receiver_thread = threading.Thread(target=receive_msg, args=(client_socket,))

                                sender_thread.start()
                                receiver_thread.start()

                                sender_thread.join()
                                receiver_thread.join()
                                break
                            elif inner_choice == "3":
                                print("Logging out.")
                                break
                            else:
                                print("Invalid choice. Please try again.")
                    except ConnectionRefusedError:
                        print("Unable to connect to server.")
            else:
                print("Invalid username or password.")

        elif choice == "3":
            print("Exiting program.")
            break

        else:
            print("Invalid choice. Please try again.")


if __name__ == "__main__":
    main()
