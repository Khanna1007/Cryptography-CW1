import tkinter as tk
from tkinter import simpledialog, messagebox, scrolledtext
import threading
from chat_app_update import add_user, authenticate_user # Assuming chat_app_update.py contains the core functions

# GUI class
class ChatAppGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Secure Chat Application")
        self.root.geometry("600x600")
        self.username = None
        self.password = None
        self.client_socket = None
        self.aes_key = None
        self.iv = None

        # Login frame
        self.login_frame = tk.Frame(self.root)
        self.login_frame.pack()

        tk.Label(self.login_frame, text="Username:").pack(pady=5)
        self.username_entry = tk.Entry(self.login_frame)
        self.username_entry.pack(pady=5)

        tk.Label(self.login_frame, text="Password:").pack(pady=5)
        self.password_entry = tk.Entry(self.login_frame, show="*")
        self.password_entry.pack(pady=5)

        tk.Button(self.login_frame, text="Signup", command=self.signup).pack(pady=5)
        tk.Button(self.login_frame, text="Login", command=self.login).pack(pady=5)

        # Chat frame
        self.chat_frame = tk.Frame(self.root)
        self.chat_display = scrolledtext.ScrolledText(self.chat_frame, wrap=tk.WORD, height=20, width=50)
        self.chat_display.pack(padx=10, pady=10)
        self.chat_display.config(state=tk.DISABLED)

        self.chat_input = tk.Entry(self.chat_frame, width=40)
        self.chat_input.pack(side=tk.LEFT, padx=10, pady=10)
        self.chat_input.bind("<Return>", self.send_message_event)

        self.send_button = tk.Button(self.chat_frame, text="Send", command=self.send_message)
        self.send_button.pack(side=tk.RIGHT, padx=10, pady=10)

        # Chat control buttons
        self.view_history_button = tk.Button(self.chat_frame, text="View Chat History", command=self.view_chat_history)
        self.view_history_button.pack(side=tk.LEFT, padx=5, pady=5)

        self.exit_chat_button = tk.Button(self.chat_frame, text="Exit Chat", command=self.exit_chat)
        self.exit_chat_button.pack(side=tk.RIGHT, padx=5, pady=5)

        # Menu frame
        self.menu_frame = tk.Frame(self.root)
        tk.Button(self.menu_frame, text="View Chat History", command=self.view_chat_history).pack(pady=5)
        tk.Button(self.menu_frame, text="Enter Chat", command=self.enter_chat).pack(pady=5)
        tk.Button(self.menu_frame, text="Logout", command=self.logout).pack(pady=5)

    def signup(self):
        username = self.username_entry.get().strip()
        password = self.password_entry.get().strip()
        if username and password:
            add_user(username, password)
            # Create an empty chat history file for the new user
            with open(f"{username}_messages.txt", "w") as chat_file:
                chat_file.write("")
            messagebox.showinfo("Signup Successful", "User added successfully.")
        else:
            messagebox.showerror("Signup Error", "Please provide a username and password.")

    def login(self):
        self.username = self.username_entry.get().strip()
        self.password = self.password_entry.get().strip()
        if authenticate_user(self.username, self.password):
            # Ensure the chat history file exists
            if not os.path.isfile(f"{self.username}_messages.txt"):
                with open(f"{self.username}_messages.txt", "w") as chat_file:
                    chat_file.write("")
            messagebox.showinfo("Login Successful", f"Welcome {self.username}!")
            self.login_frame.pack_forget()
            self.menu_frame.pack()
        else:
            messagebox.showerror("Login Error", "Invalid username or password.")

    def view_chat_history(self):
        try:
            with open(f"{self.username}_messages.txt", "r") as chat_file:
                chat_history = chat_file.read()
                history_window = tk.Toplevel(self.root)
                history_window.title("Chat History")
                history_window.geometry("500x400")
                history_display = scrolledtext.ScrolledText(history_window, wrap=tk.WORD)
                history_display.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)
                history_display.insert(tk.END, chat_history)
                history_display.config(state=tk.DISABLED)
        except FileNotFoundError:
            messagebox.showinfo("Chat History", "No chat history found.")

    def enter_chat(self):
        self.menu_frame.pack_forget()
        self.chat_frame.pack()
        self.initialize_chat()

    def initialize_chat(self):
        # Create a socket connection to server, establish AES key, etc.
        server_address = "127.0.0.1"
        port = 12345

        import socket
        from Crypto.PublicKey import RSA
        from Crypto.Cipher import PKCS1_OAEP
        from chat_app_update import send_length_prefixed, receive_length_prefixed

        # Generate RSA key pair
        rsa_key = RSA.generate(2048)
        public_key = rsa_key.publickey().export_key()
        private_key = rsa_key.export_key()

        try:
            self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.client_socket.connect((server_address, port))

            # Send public key to server
            send_length_prefixed(self.client_socket, public_key)

            # Receive encrypted AES key and IV from server
            encrypted_aes_key = receive_length_prefixed(self.client_socket)
            iv = receive_length_prefixed(self.client_socket)

            # Decrypt AES key with client's private key
            cipher_rsa = PKCS1_OAEP.new(RSA.import_key(private_key))
            self.aes_key = cipher_rsa.decrypt(encrypted_aes_key)
            self.iv = iv

            # Start a thread to listen to incoming messages
            receiver_thread = threading.Thread(target=self.receive_messages, daemon=True)
            receiver_thread.start()
        except ConnectionRefusedError:
            messagebox.showerror("Connection Error", "Unable to connect to the server.")

    def receive_messages(self):
        from chat_app_update import receive_length_prefixed, aes_decrypt
        while True:
            data = receive_length_prefixed(self.client_socket)
            if not data:
                break
            decrypted_message = aes_decrypt(data, self.aes_key, self.iv)
            if decrypted_message:
                self.update_chat_display(decrypted_message)
                # Save the received message to chat history file
                with open(f"{self.username}_messages.txt", "a") as chat_file:
                    chat_file.write(decrypted_message + "\n")

    def update_chat_display(self, message):
        self.chat_display.config(state=tk.NORMAL)
        self.chat_display.insert(tk.END, message + "\n")
        self.chat_display.config(state=tk.DISABLED)
        self.chat_display.yview(tk.END)

    def send_message(self):
        from chat_app_update import aes_encrypt, send_length_prefixed
        message = self.chat_input.get().strip()
        if message:
            full_message = f"{self.username}: {message}"
            encrypted_message = aes_encrypt(full_message, self.aes_key, self.iv)
            if encrypted_message:
                send_length_prefixed(self.client_socket, encrypted_message)
                self.update_chat_display(f"{self.username}: {message}")
                # Save the sent message to chat history file
                with open(f"{self.username}_messages.txt", "a") as chat_file:
                    chat_file.write(f"{self.username}: {message}\n")
            self.chat_input.delete(0, tk.END)

    def send_message_event(self, event):
        self.send_message()

    def exit_chat(self):
        if self.client_socket:
            self.client_socket.close()
        self.chat_frame.pack_forget()
        self.menu_frame.pack()

    def logout(self):
        if self.client_socket:
            self.client_socket.close()
        self.menu_frame.pack_forget()
        self.chat_frame.pack_forget()
        self.login_frame.pack()

# Run the GUI
if __name__ == "__main__":
    import os
    root = tk.Tk()
    app = ChatAppGUI(root)
    root.mainloop()
