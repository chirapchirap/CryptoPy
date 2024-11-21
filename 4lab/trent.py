import sys
import socket
import random
import threading
from PyQt5.QtWidgets import QApplication, QMainWindow, QTextEdit, QPushButton, QVBoxLayout, QWidget
from PyQt5.QtCore import QThread, pyqtSignal
from datetime import datetime

# Utility functions for logging and encryption


def log_message(log_widget, message):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_widget.append(f"[{timestamp}] {message}")


def generate_large_prime():
    # Simple large prime generation (for demonstration purposes only)
    return random.choice([101, 103, 107, 109, 113, 127, 131, 137, 139, 149])


def mod_exp(base, exp, mod):
    """Perform modular exponentiation."""
    return pow(base, exp, mod)

# Trent's Main Server Class


class TrentServer(QThread):
    log_signal = pyqtSignal(str)

    def __init__(self):
        super().__init__()
        self.server_socket = None
        self.shared_keys = {}

    def run(self):
        # Start the server and handle Diffie-Hellman and Needham-Schroeder
        self.start_server()

    def start_server(self):
        self.log_signal.emit("Starting Trent's server...")
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.bind(("127.0.0.1", 65432))
        self.server_socket.listen(5)
        self.log_signal.emit("Server listening on 127.0.0.1:65432")

        while True:
            client_socket, address = self.server_socket.accept()
            self.log_signal.emit(f"Connection established with {address}")
            threading.Thread(target=self.handle_client,
                             args=(client_socket,)).start()

    def handle_client(self, client_socket):
        try:
            # Perform Diffie-Hellman Key Exchange
            n = generate_large_prime()
            g = random.randint(2, n - 1)

            private_key = random.randint(2, n - 2)
            public_key = mod_exp(g, private_key, n)

            client_socket.send(f"{n},{g},{public_key}".encode())
            self.log_signal.emit(f"Sent n={n}, g={g}, public_key={
                                 public_key} to client.")

            client_response = client_socket.recv(1024).decode()
            client_public_key = int(client_response)

            shared_key = mod_exp(client_public_key, private_key, n)
            self.log_signal.emit(f"Computed shared key: {shared_key}")

            # Receive Needham-Schroeder message
            data = client_socket.recv(1024).decode()
            self.log_signal.emit(f"Received: {data}")

            # Process and respond to Needham-Schroeder message
            client_socket.close()
        except Exception as e:
            self.log_signal.emit(f"Error: {e}")
            client_socket.close()

# Trent's GUI Application


class TrentApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Trent Application")
        self.setGeometry(100, 100, 600, 400)

        self.log_widget = QTextEdit(self)
        self.log_widget.setReadOnly(True)

        self.start_button = QPushButton("Start Server", self)
        self.start_button.clicked.connect(self.start_server)

        layout = QVBoxLayout()
        layout.addWidget(self.log_widget)
        layout.addWidget(self.start_button)

        container = QWidget()
        container.setLayout(layout)
        self.setCentralWidget(container)

        self.server_thread = TrentServer()
        self.server_thread.log_signal.connect(
            lambda msg: log_message(self.log_widget, msg))

    def start_server(self):
        log_message(self.log_widget, "Initializing Trent's server...")
        self.server_thread.start()


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = TrentApp()
    window.show()
    sys.exit(app.exec_())
