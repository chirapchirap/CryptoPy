import tkinter as tk
from tkinter import scrolledtext
import socket
import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


class BobApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Bob")

        # Создаем интерфейс для логов
        self.log = scrolledtext.ScrolledText(
            root, width=50, height=20, state='disabled')
        self.log.grid(row=0, column=0, padx=10, pady=10)

        # Кнопка для подключения к Тренту и получения сессионного ключа
        self.connect_button = tk.Button(
            root, text="Connect to Trent", command=self.connect_to_trent)
        self.connect_button.grid(row=1, column=0, padx=10, pady=10)

    def log_message(self, message):
        """Функция для добавления сообщений в лог интерфейса"""
        self.log.configure(state='normal')
        self.log.insert(tk.END, message + "\n")
        self.log.configure(state='disabled')

    def generate_key(self, password: str):
        """Функция для генерации симметричного ключа на основе пароля"""
        salt = os.urandom(16)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        return kdf.derive(password.encode()), salt

    def decrypt_message(self, key, message):
        """Функция для дешифрования сообщения с использованием AES"""
        iv = message[:16]
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv),
                        backend=default_backend())
        decryptor = cipher.decryptor()
        return decryptor.update(message[16:]) + decryptor.finalize()

    def connect_to_trent(self):
        """Функция для подключения к Тренту и получения сессионного ключа"""
        # Устанавливаем личный ключ Боба
        bob_key, _ = self.generate_key("bob_secret")

        try:
            # Подключение к серверу Трента
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.connect(('localhost', 5000))

                # Отправка идентификатора Боба
                sock.sendall(b"Bob")
                self.log_message("Connected to Trent and sent identifier")

                # Получение зашифрованного сообщения от Трента
                encrypted_data = sock.recv(1024)

                # Разделение данных: зашифрованное сообщение для Боба и Алисы
                encrypted_for_bob = encrypted_data.split(b'||')[1]

                # Дешифровка сессионного ключа
                decrypted_message = self.decrypt_message(
                    bob_key, encrypted_for_bob)
                session_key_hex, alice_id = decrypted_message.decode().split(',')

                # Логирование сессионного ключа и идентификатора Алисы
                self.log_message(f"Received session key: {session_key_hex}")
                self.log_message(f"Session initiated with Alice")

        except ConnectionError:
            self.log_message("Failed to connect to Trent")


# GUI setup
root = tk.Tk()
app = BobApp(root)
root.mainloop()
