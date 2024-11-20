import sys
import socket
import random
import time
from PyQt5.QtWidgets import QApplication, QMainWindow, QTextEdit, QPushButton, QLineEdit, QVBoxLayout, QWidget
from PyQt5.QtCore import QTimer

# One-time pad encryption/decryption function


def one_time_pad_encrypt(message, key):
    return ''.join(chr(ord(m) ^ ord(k)) for m, k in zip(message, key))


def one_time_pad_decrypt(ciphertext, key):
    # Encryption and decryption are the same in one-time pad
    return one_time_pad_encrypt(ciphertext, key)


class BobApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.initUI()
        self.K_B = ''.join(chr(random.randint(0, 255)) for _ in range(16))
        self.session_key = None
        self.log(f"Generated shared secret key K_B: {self.K_B}")

    def initUI(self):
        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)

        layout = QVBoxLayout()
        self.name_input = QLineEdit(self)
        self.name_input.setPlaceholderText("Enter Bob's name")
        layout.addWidget(self.name_input)

        self.port_input = QLineEdit(self)
        self.port_input.setPlaceholderText("Enter Bob's port")
        layout.addWidget(self.port_input)

        self.logs = QTextEdit(self)
        self.logs.setReadOnly(True)
        layout.addWidget(self.logs)

        self.start_button = QPushButton('Start Bob', self)
        self.start_button.clicked.connect(self.start_bob)
        layout.addWidget(self.start_button)

        self.central_widget.setLayout(layout)

        self.setWindowTitle('Bob Application')
        self.setGeometry(100, 100, 400, 300)

    def log(self, message):
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
        self.logs.append(f"{timestamp} - {message}")

    def start_bob(self):
        self.name = self.name_input.text()
        self.port = int(self.port_input.text())
        self.log(f"Starting Bob with name: {self.name}, port: {self.port}")

        # Set up server socket
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.bind(('localhost', self.port))
        self.server_socket.listen(5)
        self.log(f"Bob is listening for connections on port {self.port}")

        self.bob_thread = QTimer()
        self.bob_thread.timeout.connect(self.handle_connections)
        self.bob_thread.start(1000)

    def handle_connections(self):
        try:
            client_socket, addr = self.server_socket.accept()
            self.log(f"Connection from {addr}")
            self.handle_client(client_socket)
        except BlockingIOError:
            pass  # No new connection, continue

    def handle_client(self, client_socket):
        data = client_socket.recv(1024).decode()
        if data:
            self.log(f"Received from Alice: {data}")

            # Decrypt message from Alice
            decrypted_message = one_time_pad_decrypt(data, self.K_B)
            self.log(f"Decrypted message: {decrypted_message}")

            parts = decrypted_message.split(',')
            K, A = parts
            self.log(f"Extracted K: {K}, A: {A}")

            # Verify session key K
            self.session_key = K
            self.log(f"Session key K is valid.")

            # Generate random number R_B
            R_B = random.randint(1, 10000)
            self.log(f"Generated random number R_B: {R_B}")

            # Encrypt R_B with session key K
            encrypted_R_B = one_time_pad_encrypt(str(R_B), self.session_key)
            self.log(f"Sending encrypted R_B to Alice: {encrypted_R_B}")
            client_socket.send(encrypted_R_B.encode())

            # Receive encrypted R_B - 1 from Alice
            encrypted_R_B_minus_1 = client_socket.recv(1024).decode()
            self.log(
                f"Received encrypted R_B - 1 from Alice: {encrypted_R_B_minus_1}")

            # Decrypt R_B - 1
            R_B_minus_1 = one_time_pad_decrypt(
                encrypted_R_B_minus_1, self.session_key)
            self.log(f"Decrypted R_B - 1: {R_B_minus_1}")

            # Verify R_B - 1
            if int(R_B_minus_1) == R_B - 1:
                self.log("R_B - 1 is valid, session established.")
            else:
                self.log("R_B - 1 is invalid, aborting.")
                client_socket.close()
                return

            # Start message exchange with Alice
            self.start_message_exchange(client_socket)

    def start_message_exchange(self, client_socket):
        self.log("Starting message exchange with Alice...")
        self.message_thread = QTimer()
        self.message_thread.timeout.connect(
            lambda: self.handle_messages(client_socket))
        self.message_thread.start(1000)

    def handle_messages(self, client_socket):
        try:
            data = client_socket.recv(1024).decode()
            if data:
                decrypted_message = one_time_pad_decrypt(
                    data, self.session_key)
                self.log(f"Received from Alice: {decrypted_message}")

                # Echo the message back
                encrypted_message = one_time_pad_encrypt(
                    decrypted_message, self.session_key)
                client_socket.send(encrypted_message.encode())
                self.log(f"Sent to Alice: {decrypted_message}")
        except BlockingIOError:
            pass  # No new message, continue


if __name__ == '__main__':
    app = QApplication(sys.argv)
    bob_app = BobApp()
    bob_app.show()
    sys.exit(app.exec_())
