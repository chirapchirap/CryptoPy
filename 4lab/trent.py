import sys
import threading
import socket
import random
import time
from datetime import datetime
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QTextEdit, QVBoxLayout, QWidget, QLabel, QPushButton
)
from PyQt5.QtCore import Qt


# Encryption/Decryption with One-Time Pad
def otp_encrypt_decrypt(message, key):
    return ''.join(chr(ord(c) ^ ord(k)) for c, k in zip(message, key))


class TrentApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.init_ui()
        self.server_socket = None
        self.client_socket = None
        self.shared_key_a = None
        self.shared_key_b = None
        self.logs = []

    def init_ui(self):
        self.setWindowTitle("Trent's Application")
        self.setGeometry(100, 100, 600, 400)

        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)
        self.layout = QVBoxLayout(self.central_widget)

        self.label = QLabel("Trent's Cryptographic Server", self)
        self.label.setAlignment(Qt.AlignCenter)
        self.layout.addWidget(self.label)

        self.log_area = QTextEdit(self)
        self.log_area.setReadOnly(True)
        self.layout.addWidget(self.log_area)

        self.start_button = QPushButton("Start Server", self)
        self.start_button.clicked.connect(self.start_server_thread)
        self.layout.addWidget(self.start_button)

    def log_message(self, message):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"[{timestamp}] {message}"
        self.logs.append(log_entry)
        self.log_area.append(log_entry)

    def start_server_thread(self):
        threading.Thread(target=self.start_server, daemon=True).start()

    def start_server(self):
        try:
            # Generate shared keys for Alice (K_A) and Bob (K_B)
            self.shared_key_a = ''.join(random.choices(
                'abcdefghijklmnopqrstuvwxyz', k=16))
            self.shared_key_b = ''.join(random.choices(
                'abcdefghijklmnopqrstuvwxyz', k=16))
            self.log_message(f"Generated shared key for Alice (K_A): {
                             self.shared_key_a}")
            self.log_message(f"Generated shared key for Bob (K_B): {
                             self.shared_key_b}")

            # Set up server socket
            self.server_socket = socket.socket(
                socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.bind(('0.0.0.0', 12345))
            self.server_socket.listen(1)
            self.log_message("Server is listening on port 12345...")

            self.client_socket, addr = self.server_socket.accept()
            self.log_message(f"Connection established with Alice: {addr}")

            # Receive message from Alice (A, B, R_A)
            data = self.client_socket.recv(1024).decode()
            self.log_message(f"Received from Alice: {data}")
            alice_name, bob_name, r_a = data.split(',')

            # Generate session key (K)
            session_key = ''.join(random.choices(
                'abcdefghijklmnopqrstuvwxyz', k=16))
            self.log_message(f"Generated session key (K): {session_key}")

            # Prepare message for Bob
            bob_message = otp_encrypt_decrypt(
                f"{session_key},{alice_name}", self.shared_key_b)

            # Encrypt full message for Alice
            alice_message = otp_encrypt_decrypt(
                f"{r_a},{bob_name},{session_key},{
                    bob_message}", self.shared_key_a
            )

            # Send encrypted message to Alice
            self.client_socket.send(alice_message.encode())
            self.log_message(
                f"Sent encrypted message to Alice: {alice_message}")

            # Close connection
            self.client_socket.close()
            self.server_socket.close()
            self.log_message("Server stopped.")

        except Exception as e:
            self.log_message(f"Error: {str(e)}")
            if self.client_socket:
                self.client_socket.close()
            if self.server_socket:
                self.server_socket.close()


def main():
    app = QApplication(sys.argv)
    trent_app = TrentApp()
    trent_app.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
