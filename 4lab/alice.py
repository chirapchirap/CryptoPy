import socket
import threading
import time
import tkinter as tk
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes


class AliceApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Алиса: Протокол обмена ключами")

        # Настройка окна
        self.connection_label = tk.Label(
            root, text="Ожидаю подключение...", font=("Helvetica", 12))
        self.connection_label.pack(pady=10)

        # Кнопка отправки запроса
        self.send_button = tk.Button(
            root, text="Отправить запрос Тренту", command=self.send_request, font=("Helvetica", 12))
        self.send_button.pack(pady=10)

        # Область для вывода сообщений
        self.message_area = tk.Text(
            root, height=15, width=50, font=("Helvetica", 10))
        self.message_area.pack(pady=10)
        self.message_area.config(state=tk.DISABLED)

        # Соединение с Трентом
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_address = ('localhost', 5000)  # Адрес сервера Трента

    def start_connection(self):
        """Запуск соединения с Трентом."""
        try:
            self.socket.connect(self.server_address)
            self.connection_label.config(
                text="Соединение с Трентом установлено.")
            self.send_request()
        except Exception as e:
            self.connection_label.config(text=f"Ошибка подключения: {str(e)}")

    def send_request(self):
        """Отправка запроса Тренту для получения сессионного ключа."""
        message = "Запрос на сессионный ключ от Алисы"  # Текстовое сообщение
        # Получаем текущее время
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
        message_with_timestamp = f"{timestamp} - {message}"

        if message:
            try:
                # Отправляем сообщение на сервер Трента
                self.socket.send(message_with_timestamp.encode())
                self.append_message(f"Отправлено Тренту: {
                                    message_with_timestamp}")
                self.connection_label.config(
                    text="Запрос отправлен Тренту. Ожидаю ответ...")
                # Ожидаем ответа
                threading.Thread(target=self.receive_response).start()
            except Exception as e:
                self.connection_label.config(
                    text=f"Ошибка отправки запроса: {str(e)}")

    def receive_response(self):
        """Получение ответа от Трента."""
        try:
            response = self.socket.recv(1024).decode()
            # Получаем время получения
            timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
            response_with_timestamp = f"{timestamp} - {response}"
            self.append_message(f"Ответ от Трента: {response_with_timestamp}")
        except Exception as e:
            self.connection_label.config(
                text=f"Ошибка получения ответа: {str(e)}")

    def append_message(self, message):
        """Добавить сообщение в область вывода."""
        self.message_area.config(state=tk.NORMAL)
        self.message_area.insert(tk.END, message + "\n")
        self.message_area.config(state=tk.DISABLED)


if __name__ == "__main__":
    root = tk.Tk()
    alice_app = AliceApp(root)
    alice_app.start_connection()
    root.mainloop()
