import socket
import threading
import time
import random
import base64
from PyQt5.QtWidgets import QApplication, QWidget, QVBoxLayout, QPushButton, QTextEdit, QLineEdit
from PyQt5.QtCore import QTimer, pyqtSignal
from PyQt5.QtGui import QFont
from Crypto.Random import get_random_bytes

K_B = b'1010101000101010'


class BobApp(QWidget):
    log_signal = pyqtSignal(str)  # Signal to update the UI with messages

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

        self.send_button = QPushButton('Отправить сообщение Алисе', self)
        self.send_button.clicked.connect(self.start_listening)
        self.layout.addWidget(self.send_button)

        self.setLayout(self.layout)

        self.server_socket = None
        self.client_socket = None
        self.session_key = None
        self.alice_socket = None

        # Connect the signal to the log_message method
        self.log_signal.connect(self.log_message)

    def log_message(self, message):
        timestamp = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())
        self.text_edit.append(f"[{timestamp}] {message}")

    def otp_encrypt(self, key, data):
        key = key.ljust(len(data), b'\0')
        return bytes([b ^ k for b, k in zip(data.encode('utf-8'), key)])

    def otp_decrypt(self, key, data):
        return self.otp_encrypt(key, data)

    def start_listening(self):
        self.log_message("Боб слушает подключение от Алисы.")
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.bind(('localhost', 12347))
        self.server_socket.listen(1)

        threading.Thread(target=self.accept_connection, daemon=True).start()

    def accept_connection(self):
        self.client_socket, address = self.server_socket.accept()
        self.log_message(f"Подключено к Алисе: {address}")
        self.handle_alice_response()

    def send_to_alice(self, K, message, encrypt=True):
        # self.log_signal.emit("Начинаю отправку сообщения Алисе.")
        try:
            if encrypt:
                # Шифруем сообщение
                encrypted_message = self.otp_encrypt(
                    K.encode('utf-8'), message)
                message_to_send = base64.b64encode(
                    encrypted_message).decode('utf-8')
                # self.log_signal.emit(f"Сообщение {message} зашифровано перед отправкой: {
                #     message_to_send}.")
            else:
                # Отправляем сообщение без шифрования
                message_to_send = message
                # self.log_signal.emit(f"Сообщение {message} готово к отправке.")

            # Отправляем сообщение
            self.client_socket.send(message_to_send.encode('utf-8'))
            # self.log_signal.emit("Сообщение успешно отправлено Алисе.")

            # Ждем ответ от Алисы
            self.log_signal.emit("Ожидание ответа от Алисы...")
            while True:
                encrypted_response = self.client_socket.recv(1024)
                if encrypted_response:
                    # self.log_signal.emit(f"Получено зашифрованное сообщение от Алисы: {
                    #     encrypted_response.decode('utf-8')}")
                    return encrypted_response
                else:
                    self.log_signal.emit(
                        "Сообщение от Алисы пустое или соединение закрыто.")
                    time.sleep(5)
        except Exception as e:
            self.log_signal.emit(f"Ошибка при отправке сообщения Алисе: {e}")

    def decrypt_response(self, enc_response, key):
        try:
            # Расшифровка сообщения
            decoded_response = base64.b64decode(
                enc_response).decode('utf-8')
            decrypted_message = self.otp_decrypt(
                key.encode('utf-8'), decoded_response)
            return decrypted_message.decode('utf-8')
        except Exception as e:
            self.log_signal.emit(f"Ошибка при расшифровании сообщения: {e}")
            return None

    def get_trent_message(self):
        # Ждем ответ от Алисы
        self.log_signal.emit("Ожидание ответа от Алисы...")
        while True:
            encrypted_response = self.client_socket.recv(1024)
            if encrypted_response:
                self.log_signal.emit(f"Получено зашифрованное сообщение от Алисы: {
                    encrypted_response.decode('utf-8')}")
                return encrypted_response
            else:
                self.log_signal.emit(
                    "Сообщение от Алисы пустое или соединение закрыто.")
                time.sleep(5)

    def handle_alice_response(self):
        # Шаг 4.1: Получение E_K_B(K, A), зашифрованного Трентом, от Алисы.
        try:
            encrypted_response = self.get_trent_message()
            self.log_signal.emit(
                f"Получено сообщение, которое Трент зашифровал для Боба и отправил Алисе: {encrypted_response}")
            decrypted_response = self.decrypt_response(
                encrypted_response, K_B.decode('utf-8'))
            K, A = decrypted_response.split(',')
            self.log_signal.emit(
                f"Расшифрованно сообщение, которое Трент зашифровал для Боба и отправил Алисе: K: {K}, A: {A}")
        except Exception as e:
            raise e

        # Шаг 4.2-6: Генерация R_B и отправка Алисе.
        try:
            R_B = str(random.randint(1, 100))
            # Отправляем зашифрованное значение R_B Алисе
            encrypted_response = self.send_to_alice(K, R_B, encrypt=True)
            self.log_signal.emit(f"Отправлено Алисе R_B: {R_B}")
            self.log_signal.emit(f"Получено от Алисы R_B-1: {
                                 encrypted_response}")
            decrypted_response = self.decrypt_response(encrypted_response, K)
            self.log_signal.emit(f"Расшифрованно R_B-1: {
                                 decrypted_response}")
        except Exception as e:
            self.log_signal.emit(
                f"Ошибка при отправке сообщения Алисе и получении ответа от Боба: {e}")

        # Шаг 6: Обмен сообщениями.
        try:
            msg = "Привет, Алиса. Как дела?"
            encrypted_response = self.send_to_alice(K, msg, encrypt=True)
            self.log_signal.emit(f"Вы: {msg}")
            self.log_signal.emit(f"Алиса (шифрованное сообщение): {
                                 encrypted_response}")
            decrypted_response = self.decrypt_response(encrypted_response, K)
            self.log_signal.emit(f"Алиса (расшифрованное сообщение): {
                                 decrypted_response}")
        except Exception as e:
            self.log_signal.emit(
                f"Ошибка при отправке сообщения Алисе и получении ответа от Алисы: {e}")

        try:
            msg = "Если честно, не очень."
            encrypted_response = self.send_to_alice(K, msg, encrypt=True)
            self.log_signal.emit(f"Вы: {msg}")

            # Шифруем сообщение
            encrypted_message = self.otp_encrypt(
                K.encode('utf-8'), msg)
            message_to_send = base64.b64encode(
                encrypted_message).decode('utf-8')
            self.log_signal.emit(f"Сообщение {msg} зашифровано перед отправкой: {
                message_to_send}.")
            # Отправляем сообщение
            self.client_socket.send(message_to_send.encode('utf-8'))
            self.log_signal.emit("Сообщение успешно отправлено Алисе.")

            self.log_signal.emit(f"Алиса (шифрованное сообщение): {
                                 encrypted_response}")
            decrypted_response = self.decrypt_response(encrypted_response, K)
            self.log_signal.emit(f"Алиса (расшифрованное сообщение): {
                                 decrypted_response}")
        except Exception as e:
            self.log_signal.emit(
                f"Ошибка при отправке сообщения Алисе и получении ответа от Алисы: {e}")


def run_bob():
    app = QApplication([])
    window = BobApp()
    window.show()
    app.exec_()


if __name__ == '__main__':
    run_bob()
