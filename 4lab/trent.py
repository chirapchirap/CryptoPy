import socket
import threading
import time
import base64
from PyQt5.QtWidgets import QApplication, QWidget, QVBoxLayout, QPushButton, QTextEdit
from PyQt5.QtCore import QTimer
from PyQt5.QtGui import QFont
from Crypto.Random import get_random_bytes

K_A = b'1234567890123456'
K_B = b'abcdefabcdefabcd'


class TrentApp(QWidget):
    def __init__(self):
        super().__init__()

        self.setWindowTitle("Trent")
        self.setGeometry(300, 300, 400, 300)
        self.layout = QVBoxLayout()
        self.text_edit = QTextEdit(self)
        self.text_edit.setFont(QFont('Courier', 10))
        self.text_edit.setReadOnly(True)
        self.layout.addWidget(self.text_edit)

        self.start_button = QPushButton('Start Listening', self)
        self.start_button.clicked.connect(self.start_listening)
        self.layout.addWidget(self.start_button)

        self.setLayout(self.layout)
        self.server_socket = None
        self.client_socket = None

    def log_message(self, message):
        timestamp = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())
        self.text_edit.append(f"[{timestamp}] {message}")

    def otp_encrypt(self, key, data):
        key = key.ljust(len(data), b'\0')
        return bytes([b ^ k for b, k in zip(data.encode('utf-8'), key)])

    def otp_decrypt(self, key, data):
        return self.otp_encrypt(key, data)

    def start_listening(self):
        self.log_message("Трент слушает подключения.")
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.bind(('localhost', 12345))
        self.server_socket.listen(1)

        threading.Thread(target=self.accept_connection, daemon=True).start()

    def accept_connection(self):
        self.client_socket, address = self.server_socket.accept()
        self.log_message(f"Подключен {address}")
        self.handle_client_request()

    def handle_client_request(self):
        data = self.client_socket.recv(1024).decode('utf-8')
        self.log_message(f"Получено от Алисы: {data}")

        if data:
            A, B, R_A = data.split(',')
            R_A = int(R_A)

            # Генерация случайного сеансового ключа
            K = get_random_bytes(16).hex()

            # Шифруем сообщение для Боба
            encrypted_msg_1 = self.otp_encrypt(K_B, f"{K},{A}")
            encrypted_msg_1_base64 = base64.b64encode(
                encrypted_msg_1).decode('utf-8')

            # Шифруем сообщение для Алисы
            encrypted_msg_2 = self.otp_encrypt(
                K_A, f"{R_A},{B},{K},{encrypted_msg_1_base64}")

            self.client_socket.send(base64.b64encode(
                encrypted_msg_2).decode('utf-8').encode('utf-8'))
            self.log_message(f"Отправлено сообщение Алисе: {R_A},{
                             B},{K},{encrypted_msg_1_base64}.")

            # Закрываем соединение с Алисой
            self.client_socket.close()
            self.server_socket.close()
            self.log_message(f"Трент отключен.")

        else:
            self.log_message("Ошибка получения данных от Алисы.")


def run_trent():
    app = QApplication([])
    window = TrentApp()
    window.show()
    app.exec_()


if __name__ == '__main__':
    run_trent()
