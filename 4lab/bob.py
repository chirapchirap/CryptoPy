import socket
import threading
import time
import base64
from PyQt5.QtWidgets import QApplication, QWidget, QVBoxLayout, QPushButton, QTextEdit, QLineEdit
from PyQt5.QtCore import QTimer
from PyQt5.QtGui import QFont
from Crypto.Random import get_random_bytes

K_B = b'abcdefabcdefabcd'


class BobApp(QWidget):
    def __init__(self):
        super().__init__()

        self.setWindowTitle("Bob")
        self.setGeometry(300, 300, 400, 400)
        self.layout = QVBoxLayout()

        self.text_edit = QTextEdit(self)
        self.text_edit.setFont(QFont('Courier', 10))
        self.text_edit.setReadOnly(True)
        self.layout.addWidget(self.text_edit)

        self.message_input = QLineEdit(self)
        self.layout.addWidget(self.message_input)

        self.send_button = QPushButton('Send Message to Alice', self)
        self.send_button.clicked.connect(self.send_message_to_alice)
        self.layout.addWidget(self.send_button)

        self.setLayout(self.layout)

        self.server_socket = None
        self.client_socket = None
        self.session_key = None
        self.alice_socket = None

    def log_message(self, message):
        timestamp = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())
        self.text_edit.append(f"[{timestamp}] {message}")

    def otp_encrypt(self, key, data):
        key = key.ljust(len(data), b'\0')
        return bytes([b ^ k for b, k in zip(data.encode('utf-8'), key)])

    def otp_decrypt(self, key, data):
        return self.otp_encrypt(key, data)

    def start_listening(self):
        self.log_message("Bob is now listening for messages from Alice.")
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.bind(('localhost', 12347))
        self.server_socket.listen(1)

        threading.Thread(target=self.accept_connection, daemon=True).start()

    def accept_connection(self):
        self.client_socket, address = self.server_socket.accept()
        self.log_message(f"Connected to Alice at {address}")
        self.handle_alice_response()

    def handle_alice_response(self):
        data = self.client_socket.recv(1024).decode('utf-8')
        self.log_message(f"Received from Alice: {data}")

        decrypted_msg = self.otp_decrypt(K_B, data)
        self.log_message(f"Decrypted: {decrypted_msg}")
        K, A = decrypted_msg.split(',')

        self.session_key = K
        self.send_random_number(K)

    def send_random_number(self, K):
        R_B = get_random_bytes(16).hex()
        encrypted_msg = self.otp_encrypt(K.encode('utf-8'), R_B)
        self.log_message(f"Sending encrypted random number to Alice: {R_B}")

        self.alice_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.alice_socket.connect(('localhost', 12346))
        self.alice_socket.send(base64.b64encode(
            encrypted_msg).decode('utf-8').encode('utf-8'))
        self.alice_socket.close()

    def send_message_to_alice(self):
        message = self.message_input.text()
        if self.session_key:
            encrypted_message = self.otp_encrypt(
                self.session_key.encode('utf-8'), message)
            self.alice_socket = socket.socket(
                socket.AF_INET, socket.SOCK_STREAM)
            self.alice_socket.connect(('localhost', 12346))
            self.alice_socket.send(base64.b64encode(
                encrypted_message).decode('utf-8').encode('utf-8'))
            self.log_message(f"Sent encrypted message to Alice: {message}")
            self.alice_socket.close()


def run_bob():
    app = QApplication([])
    window = BobApp()
    window.show()
    window.start_listening()
    app.exec_()


if __name__ == '__main__':
    run_bob()
