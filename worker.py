import warnings
warnings.filterwarnings("ignore", category=DeprecationWarning)

import socket
import ipaddress
import pickle
import bcrypt
import crypt # Deprecated, but used for yescrypt
import string
import itertools
import argparse
from datetime import datetime

class Worker:
    LEGAL_CHARACTERS = (string.ascii_lowercase +
                        string.ascii_uppercase +
                        string.digits +
                        "@#%^&*()_+-=.,:;?")
    def __init__(self):

        # Variables to change based on server host location
        self.ipv4 = "10.0.0.34"
        self.ipv6 = "2604:3d08:597e:ef00:a21d:8635:3d84:d9d1"

        # Change to ipv4 for connection via IPv4 Address or ipv6 for IPv6
        self.server_port = 8080

        self.server_host = None
        self.client = None

        self.run()

    def run(self):
        self.create_args()
        self.check_args()
        self.handle_args()

        self.create_socket()
        self.connect_client()
        self.receive_response()
        start_time = datetime.now()
        cracked_password_result = self.crack_password(self.hashed_password, self.salt, self.algoritihm, self.rounds)
        end_time = datetime.now()
        self.crack_time = end_time - start_time
        self.send_response(cracked_password_result)

    def create_args(self):
        parser = argparse.ArgumentParser(
            description="Worker Script"
        )

        parser.add_argument(
            "-c", "--controller",
            required=True,
            help="IP Address of the controller"
        )

        parser.add_argument(
            "-p", "--port",
            type=int,
            required=True,
            help="Port number of the controller"
        )

        self.args = parser.parse_args()

    def check_args(self):
        try:
            self.is_ipv4(self.args.controller) # Will handle invalid addresses
        except Exception as e:
            self.handle_error(e)

    def handle_args(self):
        try:
            self.server_host = self.args.controller
            self.server_port = self.args.port
        except Exception as e:
            print(e)
            self.handle_error("Failed to retrieve inputted arguments.")

    def create_socket(self):
        try: 
            global client
            # INET = IPv4 /// INET6 = IPv6
            client = socket.socket((socket.AF_INET6, socket.AF_INET)[self.is_ipv4(self.server_host)], socket.SOCK_STREAM)

        except Exception as e:
            self.handle_error("Failed to create client socket")
            exit(1)

    def connect_client(self):
        try: 
            client.settimeout(10)
            client.connect((self.server_host, self.server_port))
        except Exception as e:
            print(e)
            self.handle_error(f"Failed to connect to socket with the address and port - {self.server_host}:{self.server_port}")
            exit(1)

    def send_response(self, password): 
        try: 
            response = {
                "password": password,
                "crack_time": self.crack_time,
                "dispatch_latency": self.dispatch_latency,
                "sent_time": datetime.now()
            }
            encoded = pickle.dumps(response)
            client.sendall(encoded)
        except Exception as e:
            print(e)
            self.handle_error("Failed to send response")

    def receive_response(self):
        try: 
            received_data = client.recv(1024)
            if not received_data:
                raise Exception("No data received from server")
            decoded_response = pickle.loads(received_data)
            self.display_message(decoded_response)
        except Exception as e:
            print(e)
            self.handle_error("Failed to receive response")

    def is_ipv4(self, ip_str):
        try:
            ipaddress.IPv4Address(ip_str)
            return True
        except ipaddress.AddressValueError:
            pass

        try:
            ipaddress.IPv6Address(ip_str)
            return False
        except ipaddress.AddressValueError:
            pass
        err_message = "Invalid IP Address found."
        self.handle_error(err_message)

    def handle_error(self, err_message):
        print(f"Error: {err_message}")
        self.cleanup(False)

    def display_message(self, message):
        print(f'Received response\n{message}')
        self.algoritihm = message.get('hash_algorithm')
        self.salt = message.get('salt')
        self.hashed_password = message.get('hashed_password')
        self.rounds = message.get('rounds')
        self.dispatch_latency = message.get('time_sent') - datetime.now()

    @staticmethod
    def brute_force(max_length):
        for length in range(1, max_length + 1):
            for combo in itertools.product(Worker.LEGAL_CHARACTERS, repeat=length):
                candidate = ''.join(combo)
                yield candidate

    @staticmethod
    def crack_password(hashed_password, salt, algorithm, rounds=None):

        if algorithm in ["y", "1", "5", "6"]:  # yescrypt, MD5, SHA-256, SHA-512
            return Worker.crack_general(algorithm, hashed_password, salt)
        elif algorithm == "2b":  # bcrypt
            if rounds is None:
                raise Exception("Rounds parameter is required for bcrypt")
            return Worker.crack_bcrypt(hashed_password, salt, rounds)
        else:
            raise Exception("Unsupported hash algorithm")
    
    @staticmethod
    def crack_general(algorithm, hashed_password, salt):
        salt = f"${algorithm}{salt}"
        for password in Worker.brute_force(255):
            hashed = crypt.crypt(password, salt)
            if hashed == f"{salt}{hashed_password}":
                print(f"Password found: {password}")
                return password
        print("Password not found.")
        
    @staticmethod
    def crack_bcrypt(hashed_password, salt, rounds):
        for password in Worker.brute_force(255):
            hashed = bcrypt.hashpw(password.encode(), f"$2b${rounds}${salt}".encode())
            if hashed.decode() == f"$2b${rounds}${salt}{hashed_password}":
                print(f"Password found: {password}")
                return password
        print("Password not found.")

    def cleanup(self, success):
        if self.client:
            self.client.close()
        if success:
            exit(0)
        exit(1)

if __name__ == "__main__":
    worker = Worker()