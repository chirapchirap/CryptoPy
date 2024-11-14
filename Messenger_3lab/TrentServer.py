import socket
import tkinter as tk
from tkinter import scrolledtext
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes
from datetime import datetime
import threading


class TrentServer:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.session_key = None  # Сеансовый ключ
        self.alice_socket = None
        self.bob_socket = None
        self.alice_public_key = None
        self.bob_public_key = None
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(2)

        # Настройка графического интерфейса для логов
        self.window = tk.Tk()
        self.window.title("Trent Server")

        # Логирование в GUI
        self.log_area = scrolledtext.ScrolledText(
            self.window, wrap=tk.WORD, width=40, height=20)
        self.log_area.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)

        # Запуск сервера в отдельном потоке
        threading.Thread(target=self.start_server, daemon=True).start()

        self.window.protocol("WM_DELETE_WINDOW", self.close_server)
        self.window.mainloop()

    def start_server(self):
        self.log(f"[{self.current_time()}] Трент запущен...\n")

        # Шаг 1: Подключение Алисы
        self.alice_socket, alice_address = self.server_socket.accept()
        self.log(f"[{self.current_time()}] Подключен клиент 1: {
                 alice_address}\n")
        self.alice_public_key = self.receive_public_key(self.alice_socket)

        # Генерация сеансового ключа
        self.session_key = get_random_bytes(16)
        self.log(f"[{self.current_time()}] Сессионный ключ сгенерирован: {
                 self.session_key.hex()}.\n")

        # Шифрование и отправка сеансового ключа Алисе
        cipher_rsa = PKCS1_OAEP.new(self.alice_public_key)
        encrypted_session_key = cipher_rsa.encrypt(self.session_key)
        self.alice_socket.send(encrypted_session_key)
        self.log(
            f"[{self.current_time()}] Сессионный ключ отправлен клиенту 1.\n")

        # Шаг 2: Подключение Боба
        self.bob_socket, bob_address = self.server_socket.accept()
        self.log(f"[{self.current_time()}] Подключен клиент 2: {
                 bob_address}\n")
        self.bob_public_key = self.receive_public_key(self.bob_socket)

        # Шифрование и отправка сеансового ключа Бобу
        cipher_rsa_bob = PKCS1_OAEP.new(self.bob_public_key)
        encrypted_session_key_bob = cipher_rsa_bob.encrypt(self.session_key)
        self.bob_socket.send(encrypted_session_key_bob)
        self.log(
            f"[{self.current_time()}] Сессионный ключ отправлен клиенту 2.\n")

        # Закрытие соединения с Алисой и Бобом
        self.alice_socket.close()
        self.bob_socket.close()
        self.log(f"[{self.current_time()}] Трент отсоединен.\n")

    def receive_public_key(self, client_socket):
        """Прием публичного ключа от клиента."""
        public_key_data = b''
        while True:
            part = client_socket.recv(1024)  # Получаем часть данных
            public_key_data += part  # Добавляем к общему ключу
            if len(part) < 1024:  # Если получено меньше данных, чем ожидалось, то это конец
                break
        # Импортируем ключ из полученных данных
        return RSA.import_key(public_key_data)

    def log(self, message):
        """Добавление логов в интерфейс."""
        self.log_area.insert(tk.END, message)
        self.log_area.yview(tk.END)

    def current_time(self):
        """Возвращает текущее время в формате строки"""
        return datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    def close_server(self):
        """Закрытие сервера при закрытии окна."""
        self.server_socket.close()
        self.window.quit()


if __name__ == "__main__":
    server = TrentServer("127.0.0.1", 12345)
