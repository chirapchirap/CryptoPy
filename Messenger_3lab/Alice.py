import socket
import tkinter as tk
from tkinter import scrolledtext
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Util.Padding import pad, unpad
from datetime import datetime
import threading
import base64
import time


class Client:
    def __init__(self, ip, trent_port, listen_port, peer_port):
        # Параметры для клиента
        self.ip = ip
        self.trent_port = trent_port
        self.listen_port = listen_port
        self.peer_port = peer_port
        self.session_key = None
        self.private_key = None
        self.public_key = None
        self.peer_socket = None
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # Подключение к Тренту
        self.server_socket.connect((self.ip, self.trent_port))

        # Генерация ключей RSA
        self.generate_rsa_keys()

        # Настройка графического интерфейса
        self.window = tk.Tk()
        self.window.title("Client")

        self.log_area = scrolledtext.ScrolledText(
            self.window, wrap=tk.WORD, width=40, height=20)
        self.log_area.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)

        self.message_entry = tk.Entry(self.window, width=40)
        self.message_entry.pack(padx=10, pady=5)
        self.send_button = tk.Button(
            self.window, text="Send", command=self.send_message)
        self.send_button.pack(padx=10, pady=5)

        # Привязка события нажатия клавиши Enter
        # <Return> - это клавиша Enter
        self.message_entry.bind("<Return>", self.send_message)

        threading.Thread(target=self.run_client, daemon=True).start()
        self.window.protocol("WM_DELETE_WINDOW", self.close_client)
        self.window.mainloop()

    def generate_rsa_keys(self):
        """Генерация публичного и приватного ключей RSA"""
        key = RSA.generate(2048)
        self.private_key = key
        self.public_key = key.publickey()

    def send_public_key(self):
        """Отправка публичного ключа серверу"""
        public_key_data = self.public_key.export_key()
        self.server_socket.send(public_key_data)

    def receive_session_key(self):
        """Получение зашифрованного сеансового ключа от Трента"""
        encrypted_session_key = self.server_socket.recv(1024)
        self.log(f"[{self.current_time()}] Зашифрованный сессионный ключ получен: {
                 encrypted_session_key.hex()}\n")
        cipher_rsa = PKCS1_OAEP.new(self.private_key)
        self.session_key = cipher_rsa.decrypt(encrypted_session_key)
        self.log(f"[{self.current_time()}] Сессионный ключ расшифрован: {
                 self.session_key.hex()}\n")

    def start_listening(self):
        """Этот метод будет вызываться первым клиентом, который должен начать слушать"""
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.bind((self.ip, self.listen_port))
        self.server_socket.listen(1)
        self.log(f"[{self.current_time()}] Слушаю на {
                 self.ip}:{self.listen_port}...\n")

        self.peer_socket, _ = self.server_socket.accept()
        self.log(
            f"[{self.current_time()}] Собеседник подключен. Готов к отправке/приему сообщений.\n")

    def connect_to_peer(self):
        """Попытки подключения к другому клиенту несколько раз"""
        attempt = 0
        while attempt < 2:
            try:
                self.peer_socket = socket.socket(
                    socket.AF_INET, socket.SOCK_STREAM)
                self.peer_socket.connect((self.ip, self.peer_port))
                self.log(f"[{self.current_time()}] Подключен к собеседнику {
                         self.ip}:{self.peer_port}.\n")
                return
            except (socket.error, ConnectionRefusedError) as e:
                self.log(f"[{self.current_time()}]  Попытка подключения к другому клиенту не удалась [{
                         attempt + 1}]. Повторная попытка...\n")
                time.sleep(2)  # Подождем 2 секунды перед повторной попыткой
                attempt += 1

        # Если не удалось подключиться, начинаем слушать
        self.log(f"[{self.current_time()}] Невозможно подключится к {self.ip}:{
                 self.peer_port}. Начинаю прослушивать подключения других клиентов...\n")
        self.start_listening()

    def send_message(self):
        """Шифрование сообщения сессионным ключом и отправка"""
        message = self.message_entry.get()
        cipher_aes = AES.new(self.session_key, AES.MODE_CBC)
        ct_bytes = cipher_aes.encrypt(pad(message.encode(), AES.block_size))
        iv = base64.b64encode(cipher_aes.iv).decode('utf-8')
        ciphertext = base64.b64encode(ct_bytes).decode('utf-8')
        self.peer_socket.send(f"{iv}{ciphertext}".encode())
        self.log(f"[{self.current_time()}] Вы: {message}\n")

    def receive_message(self):
        """Получение сообщения от другого клиента"""
        data = self.peer_socket.recv(1024)
        if data:
            iv = base64.b64decode(data[:24])  # Декодируем IV
            # Декодируем зашифрованное сообщение
            ciphertext = base64.b64decode(data[24:])
            cipher_aes = AES.new(self.session_key, AES.MODE_CBC, iv)
            message = unpad(cipher_aes.decrypt(
                ciphertext), AES.block_size).decode()
            self.log(f"[{self.current_time()}] Получено: {message}\n")

    def run_client(self):
        self.log(f"[{self.current_time()}] Клиент запущен...\n")
        self.send_public_key()
        self.log(f"[{self.current_time()}] Открытый ключ отправлен Тренту.\n")
        self.receive_session_key()
        self.log(f"[{self.current_time()}] Получен сессионный ключ.\n")

        # Пытаемся подключиться к другому клиенту
        self.connect_to_peer()

        while True:
            self.receive_message()

    def log(self, message):
        """Добавление логов в интерфейс"""
        self.log_area.insert(tk.END, message)
        self.log_area.yview(tk.END)

    def close_client(self):
        """Закрытие клиентского окна"""
        self.server_socket.close()
        if self.peer_socket:
            self.peer_socket.close()
        self.window.quit()

    def current_time(self):
        """Возвращает текущее время в формате строки"""
        return datetime.now().strftime('%Y-%m-%d %H:%M:%S')


if __name__ == "__main__":
    # Пример для клиента Алисы
    # (IP, порт Трента, порт для прослушивания, порт для подключения к Бобу)
    client = Client("127.0.0.1", 12345, 12346, 12347)

    # Пример для клиента Боба
    # client = Client("127.0.0.1", 12345, 12347, 12346)
