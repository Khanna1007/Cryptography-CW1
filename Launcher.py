import subprocess
import threading
import time
import sys

def start_server():
    # Assuming your server code is in `server.py`
    subprocess.Popen([sys.executable, "server.py"])

def start_gui():
    # Assuming your GUI code is in `chat_app_gui.py`
    subprocess.Popen([sys.executable, "chat_app_gui.py"])

if __name__ == "__main__":
    # Start the server in a separate thread
    server_thread = threading.Thread(target=start_server)
    server_thread.start()

    # Allow server some time to initialize
    time.sleep(2)

    # Start the GUI
    start_gui()

    # Optional: Wait for the server thread to finish if necessary
    server_thread.join()
