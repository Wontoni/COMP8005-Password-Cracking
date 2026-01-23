import socket
import sys
import ipaddress
import pickle
import hashlib
import bcrypt
from passlib.hash import yescrypt


class Worker:
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
        self.check_args(sys.argv)
        self.handle_args(sys.argv)

        self.create_socket()
        self.connect_client()
        self.receive_response()

    def check_args(self, args):
        try:
            if len(args) != 3:
                raise Exception("Invalid number of arguments")
            self.is_ipv4(args[1]) # Will handle invalid addresses
        except Exception as e:
            self.handle_error(e)
            exit(1)

    def handle_args(self, args):
        try:
            self.server_host = args[1]
            self.server_port = int(args[2])
        except Exception as e:
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

    def send_response(self, response): 
        try: 
            encoded = pickle.dumps(response)
            client.sendall(encoded)
        except Exception as e:
            self.handle_error("Failed to send words")
            exit(1)

    def receive_response(self):
        try: 
            received_data = client.recv(1024)
            if not received_data:
                raise Exception("No data received from server")
            decoded_response = pickle.loads(received_data)
            self.display_message(decoded_response)
        except Exception as e:
            self.handle_error("Failed to receive response")
            exit(1)


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
        print(type(message))

        self.cleanup(True)

    def cleanup(self, success):
        if self.client:
            self.client.close()
        if success:
            exit(0)
        exit(1)

if __name__ == "__main__":
    worker = Worker()