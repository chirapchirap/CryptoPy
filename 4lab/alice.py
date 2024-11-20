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


class AliceApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.initUI()
        self.K_A = ''.join(chr(random.randint(0, 255)) for _ in range(16))
        self.session_key = None
        self.log(f"Generated shared secret key K_A: {self.K_A}")

    def initUI(self):
        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)

        layout = QVBoxLayout()
        self.name_input = QLineEdit(self)
        self.name_input.setPlaceholderText("Enter Alice's name")
        layout.addWidget(self.name_input)

        self.bob_name_input = QLineEdit(self)
        self.bob_name_input.setPlaceholderText("Enter Bob's name")
        layout.addWidget(self.bob_name_input)

        self.bob_port_input = QLineEdit(self)
        self.bob_port_input.setPlaceholderText("Enter Bob's port")
        layout.addWidget(self.bob_port_input)

        self.logs = QTextEdit(self)
        self.logs.setReadOnly(True)
        layout.addWidget(self.logs)

        self.start_button = QPushButton('Start Alice', self)
        self.start_button.clicked.connect(self.start_alice)
        layout.addWidget(self.start_button)

        self.central_widget.setLayout(layout)

        self.setWindowTitle('Alice Application')
        self.setGeometry(100, 100, 400, 300)

    def log(self, message):
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
        self.logs.append(f"{timestamp} - {message}")

    def start_alice(self):
        self.name = self.name_input.text()
        self.bob_name = self.bob_name_input.text()
        self.bob_port = int(self.bob_port_input.text())
        self.log(f"Starting Alice with name: {self.name}, Bob's name: {
                 self.bob_name}, Bob's port: {self.bob_port}")

        # Generate random number R_A
        self.R_A = random.randint(1, 10000)
        self.log(f"Generated random number R_A: {self.R_A}")

        # Connect to Trent
        self.connect_to_trent()

    def connect_to_trent(self):
        self.log("Connecting to Trent...")
        self.trent_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.trent_socket.connect(('localhost', 12345))

        # Send message to Trent
        message = f"{self.name},{self.bob_name},{self.R_A}"
        self.log(f"Sending to Trent: {message}")
        self.trent_socket.send(message.encode())

        # Receive encrypted message from Trent
        encrypted_message = self.trent_socket.recv(1024).decode()
        self.log(f"Received from Trent: {encrypted_message}")

        # Decrypt message
        decrypted_message = one_time_pad_decrypt(encrypted_message, self.K_A)
        self.log(f"Decrypted message: {decrypted_message}")

        parts = decrypted_message.split(',')
        R_A_received, B, K, encrypted_message_for_bob = parts
        self.log(f"Extracted R_A: {R_A_received}, B: {B}, K: {K}")

        # Verify R_A
        if int(R_A_received) == self.R_A:
            self.log("R_A matches, session key K is valid.")
            self.session_key = K
        else:
            self.log("R_A does not match, aborting.")
            self.trent_socket.close()
            return

        # Send encrypted message to Bob
        self.connect_to_bob(encrypted_message_for_bob)

    def connect_to_bob(self, encrypted_message_for_bob):
        self.log("Connecting to Bob...")
        self.bob_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.bob_socket.connect(('localhost', self.bob_port))

        self.log(f"Sending encrypted message to Bob: {
                 encrypted_message_for_bob}")
        self.bob_socket.send(encrypted_message_for_bob.encode())

        # Receive encrypted R_B from Bob
        encrypted_R_B = self.bob_socket.recv(1024).decode()
        self.log(f"Received encrypted R_B from Bob: {encrypted_R_B}")

        # Decrypt R_B
        R_B = one_time_pad_decrypt(encrypted_R_B, self.session_key)
        self.log(f"Decrypted R_B: {R_B}")

        # Send R_B - 1 to Bob
        R_B_minus_1 = str(int(R_B) - 1)
        encrypted_R_B_minus_1 = one_time_pad_encrypt(
            R_B_minus_1, self.session_key)
        self.log(f"Sending encrypted R_B - 1 to Bob: {encrypted_R_B_minus_1}")
        self.bob_socket.send(encrypted_R_B_minus_1.encode())

        # Start message exchange with Bob
        self.start_message_exchange()

    def start_message_exchange(self):
        self.log("Starting message exchange with Bob...")
        self.message_thread = QTimer()
        self.message_thread.timeout.connect(self.handle_messages)
        self.message_thread.start(1000)

    def handle_messages(self):
        try:
            data = self.bob_socket.recv(1024).decode()
            if data:
                decrypted_message = one_time_pad_decrypt(
                    data, self.session_key)
                self.log(f"Received from Bob: {decrypted_message}")

                # Echo the message back
                encrypted_message = one_time_pad_encrypt(
                    decrypted_message, self.session_key)
                self.bob_socket.send(encrypted_message.encode())
                self.log(f"Sent to Bob: {decrypted_message}")
        except BlockingIOError:
            pass  # No new message, continue


if __name__ == '__main__':
    app = QApplication(sys.argv)
    alice_app = AliceApp()
    alice_app.show()
    sys.exit(app.exec_())
