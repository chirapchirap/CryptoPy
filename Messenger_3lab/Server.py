import socket
import threading
import tkinter as tk
from tkinter import scrolledtext
from datetime import datetime
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import base64


class Server:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.clients = {}  # Хранение клиентов по адресу и их сокетам
        self.public_keys = {}  # Хранение открытых ключей клиентов
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(5)

        # Настройка графического интерфейса для логов
        self.window = tk.Tk()
        self.window.title("RSA Chat Server")

        # Логирование в GUI
        self.log_area = scrolledtext.ScrolledText(
            self.window, wrap=tk.WORD, width=40, height=40)
        self.log_area.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)

        # Запуск сервера в отдельном потоке
        threading.Thread(target=self.start_server, daemon=True).start()

        self.window.protocol("WM_DELETE_WINDOW", self.close_server)
        self.window.mainloop()

    def start_server(self):
        self.log("Server started...\n")
        while True:
            client_socket, client_address = self.server_socket.accept()
            self.log(f"[{self.current_time()}] Client {
                     client_address} connected\n")
            threading.Thread(target=self.handle_client, args=(
                client_socket, client_address)).start()

    def handle_client(self, client_socket, client_address):
        try:
            # Получаем и сохраняем открытый ключ клиента
            public_key_data = client_socket.recv(1024)
            client_public_key = RSA.import_key(public_key_data)
            self.public_keys[client_address] = client_public_key
            self.clients[client_address] = client_socket

            self.log(f"[{self.current_time()}] Received public key from {
                     client_address}\n")
            self.log(f"[{self.current_time()}] Public key of {client_address}:\n{
                     client_public_key.export_key().decode()}\n")

            # Передаем открытые ключи обоим клиентам
            if len(self.public_keys) == 2:
                for address, socket in self.clients.items():
                    other_address = next(
                        addr for addr in self.clients if addr != address)
                    socket.send(self.public_keys[other_address].export_key())
                self.log(
                    f"[{self.current_time()}] Exchanged public keys between clients.\n")

            while True:
                # Получаем и пересылаем зашифрованное сообщение
                message = self.receive_message(client_socket)
                if not message:
                    break
                self.log(f"[{self.current_time()}] Received encrypted message from {
                         client_address}: {message.decode('utf-8')}\n")
                self.broadcast(message, client_socket, client_address)

        except Exception as e:
            self.log(f"[{self.current_time()}] Error handling client {
                     client_address}: {e}\n")
        finally:
            client_socket.close()
            self.clients.pop(client_address, None)
            self.public_keys.pop(client_address, None)
            self.log(f"[{self.current_time()}] Client {
                     client_address} disconnected\n")

    def receive_message(self, client_socket):
        """Получение полного сообщения от клиента."""
        message = b""
        while True:
            chunk = client_socket.recv(1024)
            message += chunk
            if len(chunk) < 1024:
                break
        return message

    def broadcast(self, message, sender_socket, sender_address):
        """Пересылка сообщения другому клиенту."""
        for client_address, sock in self.clients.items():
            if sock != sender_socket:  # Не отправлять отправителю
                try:
                    sock.send(message)
                    self.log(f"[{self.current_time()}] Message forwarded to {
                             client_address}\n")
                except Exception as e:
                    self.log(f"[{self.current_time()}] Failed to forward message to {
                             client_address}: {e}\n")

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
    server = Server("127.0.0.1", 5555)
