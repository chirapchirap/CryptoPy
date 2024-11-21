import socket
import threading
import time
import base64
from PyQt5.QtWidgets import QApplication, QWidget, QVBoxLayout, QPushButton, QTextEdit, QLineEdit
from PyQt5.QtCore import QThread, pyqtSignal
from PyQt5.QtGui import QFont
import random
K_A = b'1234567890123456'


class AliceApp(QWidget):
    log_signal = pyqtSignal(str)  # Signal to update the UI with messages

    def __init__(self):
        super().__init__()

        self.setWindowTitle("Alice")
        self.setGeometry(300, 300, 400, 400)
        self.layout = QVBoxLayout()

        self.text_edit = QTextEdit(self)
        self.text_edit.setFont(QFont('Courier', 10))
        self.text_edit.setReadOnly(True)
        self.layout.addWidget(self.text_edit)

        self.message_input = QLineEdit(self)
        self.layout.addWidget(self.message_input)

        self.send_button_to_trent = QPushButton(
            'Отправить сообщение Тренту', self)
        self.send_button_to_trent.clicked.connect(self.send_message_to_trent)
        self.layout.addWidget(self.send_button_to_trent)

        self.send_button_to_bob = QPushButton('Отправить сообщение Бобу', self)
        self.send_button_to_bob.clicked.connect(self.send_message_to_bob)
        self.layout.addWidget(self.send_button_to_bob)

        self.setLayout(self.layout)

        self.server_socket = None
        self.client_socket = None
        self.session_key = None
        self.trent_socket = None

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

    def connect_to_trent(self):
        self.log_signal.emit("Подключаюсь к Тренту...")
        self.trent_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self.trent_socket.connect(('localhost', 12345))  # Порт Трента
            self.log_signal.emit("Подключен к Тренту")
            return True
        except Exception as e:
            self.log_signal.emit(f"Ошибка подключения к Тренту: {e}")
            return False

    def send_message_to_trent(self):
        def worker():
            if self.connect_to_trent():
                # Генерация случайного числа для R_A
                R_A = str(random.randint(1, 100))
                A = 'Alice'  # Имя Алисы
                B = 'Bob'    # Имя Боба

                # Формируем сообщение
                message = f"{A},{B},{R_A}"
                self.log_signal.emit(f"Отправляю: {message}")

                try:
                    # Отправка сообщения без шифрования
                    self.trent_socket.send(message.encode('utf-8'))

                    # Ждём ответ от Трента
                    data = self.trent_socket.recv(1024)
                    self.log_signal.emit(f"Получено от Трента: {
                                     data.decode('utf-8')}")

                    # Обработка ответа
                    self.handle_trent_response(data)
                except Exception as e:
                    self.log_message(
                        f"Проблема отправки/получения от Трента: {e}")
                finally:
                    self.trent_socket.close()
                    self.log_signal.emit("Соединение с Трентом закрыто.")
                    self.connect_to_bob()
            else:
                self.log_signal.emit("Ошибка подключения к Тренту.")

        # Запуск процесса отправки в отдельном потоке
        threading.Thread(target=worker, daemon=True).start()

    def handle_trent_response(self, data):
        """Обработка ответа от Трента"""

        # Шаг 1: Декодируем сообщение от Трента из base64
        try:
            decoded_data = base64.b64decode(data).decode('utf-8')
            self.log_signal.emit(
                f"Получено от Трента (декодировано из base64): {decoded_data}")
        except Exception as e:
            self.log_signal.emit(f"Ошибка декодирования из base64: {e}")
            return

        # Шаг 2: Расшифровываем сообщение с использованием OTP и ключа K_A
        try:
            decrypted_msg = self.otp_decrypt(K_A, decoded_data)
            decrypted_msg_str = decrypted_msg.decode(
                'utf-8')  # Преобразуем байты в строку
            self.log_signal.emit(f"Расшифровано при помощи K_A: {
                             decrypted_msg_str}")
        except Exception as e:
            self.log_signal.emit(
                f"Ошибка расшифровки сообщения с использованием K_A: {e}")
            return

        # Шаг 3: Извлекаем компоненты сообщения: R_A, B, K, зашифрованное сообщение для Боба
        try:
            R_A, B, K, encrypted_msg_1_base64 = decrypted_msg_str.split(',')
            self.log_signal.emit(f"R_A: {R_A}, B: {B}, K: {
                K}, Зашифрованное сообщение для Боба: {encrypted_msg_1_base64}")
        except Exception as e:
            self.log_signal.emit(f"Ошибка извлечения данных из сообщения: {e}")
            return

    def send_to_bob(self, K, A):
        self.log_signal.emit("Отправляю сообщение Бобу с сеансовым ключом K.")
        self.bob_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.bob_socket.connect(('localhost', 12347))

        encrypted_message = self.otp_encrypt(K.encode('utf-8'), f"{K},{A}")
        self.bob_socket.send(base64.b64encode(
            encrypted_message).decode('utf-8').encode('utf-8'))
        self.bob_socket.close()

    def connect_to_bob(self):
        """Метод для подключения к Бобу на порт 12346, выполняется в потоке."""
        def worker():
            self.log_signal.emit("Подключаюсь к Бобу на порт 12346...")

            self.bob_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                self.bob_socket.connect(('localhost', 12346))  # Порт Боба
                self.log_signal.emit("Подключено к Бобу.")
            except Exception as e:
                self.log_signal.emit(f"Ошибка подключения к Бобу: {e}")

        # Запуск потока для подключения
        connection_thread = threading.Thread(target=worker, daemon=True)
        connection_thread.start()

    def receive_message_from_bob(self):
        """Метод для получения сообщения от Боба, выполняется в потоке."""
        def worker():
            while True:
                try:
                    # Получаем данные от Боба
                    data = self.bob_socket.recv(1024)  # Получаем 1024 байта
                    if not data:
                        break  # Прерываем цикл, если соединение закрыто

                    # Преобразуем данные в строку
                    decoded_data = base64.b64decode(data).decode('utf-8')
                    self.log_signal.emit(
                        f"Получено сообщение от Боба: {decoded_data}")

                    # Расшифровываем сообщение, если сессионный ключ доступен
                    decrypted_message = self.otp_decrypt(
                        self.session_key.encode('utf-8'), decoded_data.encode('utf-8'))
                    self.log_signal.emit(f"Расшифрованное сообщение: {
                        decrypted_message}")

                except Exception as e:
                    self.log_signal.emit(
                        f"Ошибка получения сообщения от Боба: {e}")
                    break

    def send_message_to_bob(self):
        def worker():
            message = self.message_input.text()
            if self.session_key:
                encrypted_message = self.otp_encrypt(
                    self.session_key.encode('utf-8'), message)
                try:
                    self.bob_socket = socket.socket(
                        socket.AF_INET, socket.SOCK_STREAM)
                    self.bob_socket.connect(('localhost', 12347))
                    self.bob_socket.send(base64.b64encode(
                        encrypted_message).decode('utf-8').encode('utf-8'))
                    self.log_signal.emit(
                        f"Отправлено зашифрованное сообщение Бобу: {message}")
                except Exception as e:
                    self.log_signal.emit(
                        f"Ошибка при отправке сообщения Бобу: {e}")
                finally:
                    self.bob_socket.close()
                    # Включение кнопки после завершения
                    self.send_button_to_bob.setEnabled(True)

        # Запускаем процесс отправки сообщения в отдельном потоке
        self.send_button_to_bob.setEnabled(False)  # Отключаем кнопку временно
        threading.Thread(target=worker, daemon=True).start()


def run_alice():
    app = QApplication([])
    window = AliceApp()
    window.show()
    app.exec_()


if __name__ == '__main__':
    run_alice()
