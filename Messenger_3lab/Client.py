import socket
import threading
import tkinter as tk
from tkinter import scrolledtext
from datetime import datetime
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import base64


class Client:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.client_socket.connect((self.host, self.port))

        # Генерация пары ключей RSA
        self.private_key = RSA.generate(2048)
        self.public_key = self.private_key.publickey()
        self.cipher_rsa = PKCS1_OAEP.new(self.private_key)

        # Интерфейс
        self.window = tk.Tk()
        self.window.title("RSA Chat Client")

        # Поле для логов
        self.chat_log = scrolledtext.ScrolledText(
            self.window, wrap=tk.WORD, width=40, height=10)
        self.chat_log.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)

        # Поле ввода
        self.entry = tk.Entry(self.window, width=40)
        self.entry.pack(padx=10, pady=5)
        self.entry.bind("<Return>", self.send_message)
        self.send_button = tk.Button(
            self.window, text="Send", command=self.send_message)
        self.send_button.pack(padx=10, pady=5)

        # Отправка открытого ключа серверу
        self.chat_log.insert(tk.END, f"Your Public Key:\n{
                             self.public_key.export_key().decode()}\n\n")
        self.client_socket.send(self.public_key.export_key())

        # Получение открытого ключа другого клиента
        other_public_key_data = self.client_socket.recv(1024)
        self.other_public_key = RSA.import_key(other_public_key_data)
        self.other_cipher = PKCS1_OAEP.new(self.other_public_key)

        # Поток для получения сообщений
        self.receive_thread = threading.Thread(target=self.receive_messages)
        self.receive_thread.start()

    def send_message(self, event=None):
        """Отправка зашифрованного сообщения серверу с меткой времени."""
        message = self.entry.get()
        if message:
            # Шифрование сообщения открытым ключом другого клиента
            encrypted_message = self.other_cipher.encrypt(
                message.encode('utf-8'))
            self.client_socket.send(base64.b64encode(encrypted_message))

            # Добавление времени отправки в чат
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            self.chat_log.insert(tk.END, f"[{timestamp}] You: {message}\n")
            self.entry.delete(0, tk.END)

    def receive_messages(self):
        """Получение и расшифровка сообщений от сервера с меткой времени."""
        while True:
            try:
                encrypted_message = self.receive_full_message()
                decrypted_message = self.cipher_rsa.decrypt(
                    encrypted_message).decode('utf-8')

                # Добавление времени получения в чат
                timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                self.chat_log.insert(tk.END, f"[{timestamp}] Friend: {
                                     decrypted_message}\n")
            except Exception as e:
                print(f"Error receiving message: {e}")
                break

    def receive_full_message(self):
        """Получение полного сообщения от сервера."""
        message = b""
        while True:
            chunk = self.client_socket.recv(1024)
            message += chunk
            if len(chunk) < 1024:
                break
        return base64.b64decode(message)

    def run(self):
        """Запуск интерфейса."""
        self.window.mainloop()


if __name__ == "__main__":
    client = Client("127.0.0.1", 5555)
    client.run()
