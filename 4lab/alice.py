import sys
import socket
import random
import threading
from PyQt5.QtWidgets import QApplication, QMainWindow, QTextEdit, QPushButton, QVBoxLayout, QWidget
from PyQt5.QtCore import QThread, pyqtSignal
from datetime import datetime

# Utility functions


def log_message(log_widget, message):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_widget.append(f"[{timestamp}] {message}")


def generate_large_prime():
    # Simple large prime generation (for demonstration purposes)
    return random.choice([101, 103, 107, 109, 113, 127, 131, 137, 139, 149])


def mod_exp(base, exp, mod):
    """Perform modular exponentiation."""
    return pow(base, exp, mod)


def one_time_pad_encrypt(message, key):
    """Encrypt a message using a one-time pad."""
    return ''.join(chr(ord(c) ^ key[i % len(key)]) for i, c in enumerate(message))


def one_time_pad_decrypt(ciphertext, key):
    """Decrypt a message using a one-time pad."""
    return one_time_pad_encrypt(ciphertext, key)

# Alice's Client Class


class AliceClient(QThread):
    log_signal = pyqtSignal(str)

    def __init__(self):
        super().__init__()
        self.shared_key = None
        self.session_key = None

    def run(self):
        # Connect to Trent and generate a shared key using Diffie-Hellman
        self.connect_to_trent()
        # Proceed with the Needham-Schroeder protocol
        self.run_needham_schroeder()

    def connect_to_trent(self):
        try:
            self.log_signal.emit(
                "Connecting to Trent for Diffie-Hellman key exchange...")
            trent_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            trent_socket.connect(("127.0.0.1", 65432))

            # Receive n, g, and Trent's public key
            data = trent_socket.recv(1024).decode()
            n, g, trent_public_key = map(int, data.split(","))
            self.log_signal.emit(f"Received n={n}, g={
                                 g}, Trent's public key={trent_public_key}")

            # Generate Alice's private and public keys
            private_key = random.randint(2, n - 2)
            public_key = mod_exp(g, private_key, n)
            self.log_signal.emit(
                f"Alice's private key generated. Public key={public_key}")

            # Send Alice's public key to Trent
            trent_socket.send(str(public_key).encode())
            self.log_signal.emit("Sent public key to Trent.")

            # Compute shared key
            self.shared_key = mod_exp(trent_public_key, private_key, n)
            self.log_signal.emit(
                f"Computed shared key with Trent: {self.shared_key}")

            trent_socket.close()
        except Exception as e:
            self.log_signal.emit(f"Error during Diffie-Hellman: {e}")

    def run_needham_schroeder(self):
        try:
            self.log_signal.emit(
                "Starting Needham-Schroeder protocol with Trent...")
            trent_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            trent_socket.connect(("127.0.0.1", 65432))

            # Step 1: Send A, B, RA to Trent
            alice_name = "Alice"
            bob_name = "Bob"
            ra = random.randint(1, 1000000)
            message = f"{alice_name},{bob_name},{ra}"
            self.log_signal.emit(
                f"Step 1: Sending message to Trent: {message}")
            trent_socket.send(message.encode())

            # Step 2: Receive encrypted response from Trent
            encrypted_message = trent_socket.recv(1024)
            self.log_signal.emit(f"Received encrypted response from Trent: {
                                 encrypted_message}")

            # Decrypt message using shared key
            try:
                # Ensure proper decoding
                encrypted_message = encrypted_message.decode()
                decrypted_message = one_time_pad_decrypt(
                    encrypted_message, [self.shared_key])
                self.log_signal.emit(f"Decrypted message from Trent: {
                                     decrypted_message}")
            except Exception as e:
                self.log_signal.emit(f"Error decrypting message: {e}")
                return  # Abort if decryption fails

            # Parse the decrypted message
            try:
                decrypted_parts = decrypted_message.split(",")
                received_ra = int(decrypted_parts[0])
                session_key = int(decrypted_parts[1])
                encrypted_bob_message = decrypted_parts[2]

                if received_ra == ra:
                    self.log_signal.emit("Step 3: RA matches. Proceeding...")
                    self.session_key = session_key

                    # Connect to Bob and send encrypted message
                    self.connect_to_bob(encrypted_bob_message)
                else:
                    self.log_signal.emit("RA mismatch. Aborting protocol.")
            except Exception as e:
                self.log_signal.emit(f"Error parsing decrypted message: {e}")
                return  # Abort if parsing fails

        except Exception as e:
            self.log_signal.emit(
                f"Error during Needham-Schroeder protocol: {e}")
            return  # Abort if there is a general error

    def connect_to_bob(self, encrypted_bob_message):
        try:
            self.log_signal.emit("Connecting to Bob...")
            bob_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            bob_socket.connect(("127.0.0.1", 65433))

            # Send encrypted message to Bob
            self.log_signal.emit(f"Sending encrypted message to Bob: {
                                 encrypted_bob_message}")
            bob_socket.send(encrypted_bob_message.encode())

            # Receive and decrypt RB from Bob
            encrypted_rb = bob_socket.recv(1024).decode()
            rb = one_time_pad_decrypt(encrypted_rb, [self.session_key])
            self.log_signal.emit(f"Received RB from Bob: {rb}")

            # Send RB-1 back to Bob
            rb_minus_1 = int(rb) - 1
            encrypted_rb_minus_1 = one_time_pad_encrypt(
                str(rb_minus_1), [self.session_key])
            self.log_signal.emit(
                f"Sending RB-1 to Bob: {encrypted_rb_minus_1}")
            bob_socket.send(encrypted_rb_minus_1.encode())

            bob_socket.close()
        except Exception as e:
            self.log_signal.emit(f"Error during communication with Bob: {e}")

# Alice's GUI Application


class AliceApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Alice Application")
        self.setGeometry(100, 100, 600, 400)

        self.log_widget = QTextEdit(self)
        self.log_widget.setReadOnly(True)

        self.start_button = QPushButton("Start Protocol", self)
        self.start_button.clicked.connect(self.start_protocol)

        layout = QVBoxLayout()
        layout.addWidget(self.log_widget)
        layout.addWidget(self.start_button)

        container = QWidget()
        container.setLayout(layout)
        self.setCentralWidget(container)

        self.client_thread = AliceClient()
        self.client_thread.log_signal.connect(
            lambda msg: log_message(self.log_widget, msg))

    def start_protocol(self):
        log_message(self.log_widget, "Starting Alice's protocol...")
        self.client_thread.start()


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = AliceApp()
    window.show()
    sys.exit(app.exec_())
