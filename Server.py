import socket
import threading
from Crypto.Cipher import DES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes


class Node:
    def __init__(self, client_socket):
        self.client_socket = client_socket
        self.next = None


# Function to handle communication with a client
def interact_with_client(client_socket, client_address, head_ref):
    print(f"Client connected from {client_address}")

    try:
        # Receive RSA public key
        public_key_data = client_socket.recv(4096)
        client_public_key = RSA.import_key(public_key_data)

        # Generate and send DES key
        des_key = get_random_bytes(8)  # DES key must be 8 bytes
        encrypted_des_key = PKCS1_OAEP.new(client_public_key).encrypt(des_key)
        client_socket.sendall(encrypted_des_key)
        print(f"DES key sent to client {client_address}: {des_key.hex()}")

        # Add client to linked list
        new_node = Node(client_socket)
        new_node.next = head_ref[0]
        head_ref[0] = new_node

        # Handle encrypted client messages
        while True:
            try:
                # Receive encrypted message from the client
                encrypted_message = client_socket.recv(4096)
                if not encrypted_message:
                    print(f"Client {client_address} disconnected.")
                    break

                print(f"Encrypted message received from client {client_address}: {encrypted_message.hex()}")

                # Broadcast the encrypted message to all other clients
                current = head_ref[0]
                while current:
                    if current.client_socket != client_socket:
                        try:
                            current.client_socket.sendall(encrypted_message)
                        except BrokenPipeError:
                            pass  # Handle cases where the client is disconnected
                    current = current.next
            except ConnectionResetError:
                print(f"Client {client_address} forcibly disconnected.")
                break
    except Exception as e:
        print(f"Error with client {client_address}: {e}")

    # Remove client from linked list
    prev = None
    current = head_ref[0]
    while current:
        if current.client_socket == client_socket:
            if prev:
                prev.next = current.next
            else:
                head_ref[0] = current.next
            break
        prev = current
        current = current.next

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

    head_ref = [None]

    try:
        while True:
            client_socket, client_address = server_socket.accept()
            print(f"New connection from {client_address}")

            client_thread = threading.Thread(target=interact_with_client, args=(client_socket, client_address, head_ref))
            client_thread.daemon = True
            client_thread.start()
    except KeyboardInterrupt:
        print("\nShutting down server.")
    finally:
        current = head_ref[0]
        while current:
            current.client_socket.close()
            current = current.next

        server_socket.close()


if __name__ == "__main__":
    main()
