import tkinter as tk
from tkinter import scrolledtext
import socket
import os
import threading
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


class TrentApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Trent - Authentication Server")

        # Создаем интерфейс для логов
        self.log = scrolledtext.ScrolledText(
            root, width=50, height=20, state='disabled')
        self.log.grid(row=0, column=0, padx=10, pady=10)

        # Кнопка для запуска сервера
        self.start_button = tk.Button(
            root, text="Start Server", command=self.start_server_thread)
        self.start_button.grid(row=1, column=0, padx=10, pady=10)

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

    def encrypt_message(self, key, message):
        """Функция для шифрования сообщения с использованием AES"""
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv),
                        backend=default_backend())
        encryptor = cipher.encryptor()
        return iv + encryptor.update(message.encode()) + encryptor.finalize()

    def decrypt_message(self, key, message):
        """Функция для дешифрования сообщения с использованием AES"""
        iv = message[:16]
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv),
                        backend=default_backend())
        decryptor = cipher.decryptor()
        return decryptor.update(message[16:]) + decryptor.finalize()

    def start_server_thread(self):
        """Запуск сервера в отдельном потоке"""
        thread = threading.Thread(target=self.start_server, daemon=True)
        thread.start()

    def start_server(self):
        """Основная функция сервера для приема подключений"""
        # Генерация ключей для Алисы и Боба
        alice_key, _ = self.generate_key("alice_secret")
        bob_key, _ = self.generate_key("bob_secret")

        # Запуск сервера
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.bind(('localhost', 5000))
        server_socket.listen(2)
        self.log_message("Trent is listening for connections...")

        while True:
            conn, addr = server_socket.accept()
            self.log_message(f"Connection from {addr}")

            # Получение идентификатора клиента (Alice или Bob)
            client_id = conn.recv(1024).decode()
            if client_id == "Alice":
                self.log_message("Identified connection as Alice")

                # Получаем зашифрованное сообщение от Алисы
                data = conn.recv(1024)
                decrypted_data = self.decrypt_message(alice_key, data)
                self.log_message(f"Received decrypted data from Alice: {
                                 decrypted_data.decode()}")

                # Генерация сессионного ключа
                session_key = os.urandom(32)
                message_to_alice = f"{session_key.hex()},Bob"
                encrypted_for_alice = self.encrypt_message(
                    alice_key, message_to_alice)
                encrypted_for_bob = self.encrypt_message(
                    bob_key, f"{session_key.hex()},Alice")

                # Отправка сессионного ключа Алисе
                conn.sendall(encrypted_for_alice + b'||' + encrypted_for_bob)
                self.log_message("Session key sent to Alice")

            elif client_id == "Bob":
                self.log_message("Identified connection as Bob")
                # Здесь можно прописать дополнительные действия для Боба, если они требуются

            conn.close()


# GUI setup
root = tk.Tk()
app = TrentApp(root)
root.mainloop()
