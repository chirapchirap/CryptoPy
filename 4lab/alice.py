import socket
import threading
import time
import base64
from PyQt5.QtWidgets import QApplication, QWidget, QVBoxLayout, QPushButton, QTextEdit, QLineEdit
from PyQt5.QtCore import QThread, pyqtSignal
from PyQt5.QtGui import QFont
import random
K_A = b'1010001000110110'


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
        self.send_button_to_bob.clicked.connect(self.handle_bob_responses)
        self.layout.addWidget(self.send_button_to_bob)

        self.setLayout(self.layout)

        self.server_socket = None
        self.client_socket = None
        self.session_key = None
        self.trent_socket = None
        self.bob_socket = None

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

                try:
                    # Отправка сообщения без шифрования
                    self.trent_socket.send(message.encode('utf-8'))
                    self.log_signal.emit(
                        f"Шаг 1 протокола: Отправлено Тренту: {message}")
                    # Ждём ответ от Трента
                    data = self.trent_socket.recv(1024)
                    self.log_signal.emit(f"Шаг 2-3 протокола: Получено от Трента: {
                        data.decode('utf-8')}")

                    # Обработка ответа
                    self.handle_trent_response(data)
                except Exception as e:
                    self.log_message(
                        f"Проблема отправки/получения от Трента: {e}")
                finally:
                    self.trent_socket.close()
                    self.log_signal.emit("Соединение с Трентом закрыто.")
            else:
                self.log_signal.emit("Ошибка подключения к Тренту.")

        # Запуск процесса отправки в отдельном потоке
        threading.Thread(target=worker, daemon=True).start()

    def send_to_bob(self, K, message, encrypt=True):
        # self.log_signal.emit("Начинаю отправку сообщения Бобу.")
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
            self.bob_socket.send(message_to_send.encode('utf-8'))
            # self.log_signal.emit("Сообщение успешно отправлено Бобу.")

            # Ждем ответ от Боба
            self.log_signal.emit("Ожидание ответа от Боба...")
            while True:
                encrypted_response = self.bob_socket.recv(1024)
                if encrypted_response:
                    # self.log_signal.emit(f"Получено зашифрованное сообщение от Боба: {
                    #     encrypted_response.decode('utf-8')}")
                    return encrypted_response
                else:
                    self.log_signal.emit(
                        "Сообщение от Боба пустое или соединение закрыто.")
        except Exception as e:
            self.log_signal.emit(f"Ошибка при отправке сообщения Бобу: {e}")

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

    def connect_to_bob(self):
        """Метод для подключения к Бобу на порт 12347, выполняется в потоке."""
        # def worker():
        self.log_signal.emit("Подключаюсь к Бобу на порт 12347...")

        self.bob_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self.bob_socket.connect(('localhost', 12347))  # Порт Боба
            self.log_signal.emit("Подключено к Бобу.")
        except Exception as e:
            self.log_signal.emit(f"Ошибка подключения к Бобу: {e}")

        # # Запуск потока для подключения
        # connection_thread = threading.Thread(target=worker, daemon=True)
        # connection_thread.start()

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
            self.log_signal.emit(f"Шаг 3 протокола: Расшифровано при помощи K_A: {
                decrypted_msg_str}")
        except Exception as e:
            self.log_signal.emit(
                f"Ошибка расшифровки сообщения с использованием K_A: {e}")
            return

        # Шаг 3.1: Извлекаем компоненты сообщения: R_A, B, K, зашифрованное сообщение для Боба
        try:
            R_A, B, K, encrypted_msg_1_base64 = decrypted_msg_str.split(',')
            self.log_signal.emit(f"R_A: {R_A}, B: {B}, K: {
                K}, Зашифрованное сообщение для Боба: {encrypted_msg_1_base64}")
            self.K = K
            self.enc_bob_msg = encrypted_msg_1_base64
        except Exception as e:
            self.log_signal.emit(f"Ошибка извлечения данных из сообщения: {e}")
            return

    def handle_bob_responses(self):

        # Подключение к Бобу.
        self.connect_to_bob()

        # Шаг 3.2: Отправка сообщения, зашифрованного Трентом ключом Боба, Бобу.
        # Шаг 4: Получение от Боба случайно сгенерированного числа R_B.
        try:
            encrypted_response = self.send_to_bob(
                self.K, self.enc_bob_msg, encrypt=False)
            self.log_signal.emit(f"Шаг 4-5 протокола: Получен от Боба шифрованный ответ R_B: {
                                 encrypted_response}")
            decrypted_response = self.decrypt_response(
                encrypted_response, self.K)
            self.log_signal.emit(f"Расшифрованное сообщение R_B от Боба: {
                                 decrypted_response}")
        except Exception as e:
            self.log_signal.emit(f"Ошибка извлечения данных из сообщения: {e}")
            return

        # Шаг 5: Отправка значения R_B-1 Бобу
        try:
            R_B_minus_1 = str(int(decrypted_response) - 1)  # Вычисляем R_B - 1
            self.log_signal.emit(
                f"Шаг 5 протокола: Вычислено R_B-1: {R_B_minus_1}")
            # Отправляем зашифрованное значение R_B-1
            encrypted_response = self.send_to_bob(
                self.K, R_B_minus_1, encrypt=True)
            self.log_signal.emit(
                "Шаг 5 протокола: Значение R_B-1 успешно отправлено Бобу.")
            self.log_signal.emit(f"Получено от Боба шифрованное сообщение: {
                                 encrypted_response}")
            decrypted_response = self.decrypt_response(
                encrypted_response, self.K)
            self.log_signal.emit(f"Боб: {
                                 decrypted_response}")
        except Exception as e:
            self.log_signal.emit(f"Ошибка при отправке R_B-1 Бобу: {e}")

        # Шаг 6: Обмен сообщениями с Бобом
        try:
            msg = "Привет, Боб. У меня всё отлично. Ты как поживаешь?"
            encrypted_response = self.send_to_bob(self.K, msg, encrypt=True)
            self.log_signal.emit(f"Вы: {msg}")
            self.log_signal.emit(f"Боб (шифрованное сообщение): {
                                 encrypted_response}")
            decrypted_response = self.decrypt_response(
                encrypted_response, self.K)
            self.log_signal.emit(f"Боб (расшифрованное сообщение): {
                                 decrypted_response}")
        except Exception as e:
            self.log_signal.emit(
                f"Ошибка при отправке сообщения Бобу и получении ответа от Боба: {e}")

    # def receive_message_from_bob(self):
    #     """Метод для получения сообщения от Боба, выполняется в потоке."""
    #     def worker():
    #         while True:
    #             try:
    #                 # Получаем данные от Боба
    #                 data = self.bob_socket.recv(1024)  # Получаем 1024 байта
    #                 if not data:
    #                     break  # Прерываем цикл, если соединение закрыто

    #                 # Преобразуем данные в строку
    #                 decoded_data = base64.b64decode(data).decode('utf-8')
    #                 self.log_signal.emit(
    #                     f"Получено сообщение от Боба: {decoded_data}")

    #                 # Расшифровываем сообщение, если сессионный ключ доступен
    #                 decrypted_message = self.otp_decrypt(
    #                     self.session_key.encode('utf-8'), decoded_data.encode('utf-8'))
    #                 self.log_signal.emit(f"Расшифрованное сообщение: {
    #                     decrypted_message}")

    #             except Exception as e:
    #                 self.log_signal.emit(
    #                     f"Ошибка получения сообщения от Боба: {e}")
    #                 break

    # def send_message_to_bob(self):
    #     def worker():
    #         message = self.message_input.text()
    #         if self.session_key:
    #             encrypted_message = self.otp_encrypt(
    #                 self.session_key.encode('utf-8'), message)
    #             try:
    #                 self.bob_socket = socket.socket(
    #                     socket.AF_INET, socket.SOCK_STREAM)
    #                 self.bob_socket.connect(('localhost', 12347))
    #                 self.bob_socket.send(base64.b64encode(
    #                     encrypted_message).decode('utf-8').encode('utf-8'))
    #                 self.log_signal.emit(
    #                     f"Отправлено зашифрованное сообщение Бобу: {message}")
    #             except Exception as e:
    #                 self.log_signal.emit(
    #                     f"Ошибка при отправке сообщения Бобу: {e}")
    #             finally:
    #                 self.bob_socket.close()
    #                 # Включение кнопки после завершения
    #                 self.send_button_to_bob.setEnabled(True)

    #     # Запускаем процесс отправки сообщения в отдельном потоке
    #     self.send_button_to_bob.setEnabled(False)  # Отключаем кнопку временно
    #     threading.Thread(target=worker, daemon=True).start()


def run_alice():
    app = QApplication([])
    window = AliceApp()
    window.show()
    app.exec_()


if __name__ == '__main__':
    run_alice()
