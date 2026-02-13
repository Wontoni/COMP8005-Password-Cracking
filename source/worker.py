import socket
import ipaddress
import pickle
import bcrypt
import crypt # Deprecated, but used for yescrypt
import string
import itertools
import argparse
from datetime import datetime
import threading
from queue import Queue
import hashlib

class Worker:
    attempts = 0
    attempts_lock = threading.Lock()
    found_event = threading.Event()
    shutdown_event = threading.Event()
    found_password = None

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

        self.threads = []
        
        self.run()

    def run(self):
        self.create_args()
        self.check_args()
        self.handle_args()

        self.create_socket()
        self.connect_client()
        decoded_response = self.receive_response()
        self.display_message(decoded_response)
        self.start_heartbeat_listener()

        start_time = datetime.now()
        self.crack_password(self.hashed_password, self.salt, self.algoritihm, self.rounds, num_threads=self.thread_count)
        end_time = datetime.now()
        self.crack_time = end_time - start_time
        response = {
                "type": "password",
                "password": Worker.found_password,
                "crack_time": self.crack_time,
                "dispatch_latency": self.dispatch_latency,
                "sent_time": datetime.now()
            }
        self.send_response(response)

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

        parser.add_argument(
            "-t", "--threads",
            type=int,
            required=True,
            help="Number of threads to create"
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
            self.thread_count = self.args.threads
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

    def send_response(self, response): 
        try: 
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
            return decoded_response
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
        self.dispatch_latency = datetime.now() - message.get('time_sent')


    def crack_worker(self, charset_slice, algorithm, full_hash, rounds=None):
        local_attempts = 0
        batch_size = 200
        max_length = 3

        for length in range(1, max_length + 1):

            for first_char in charset_slice:

                if Worker.found_event.is_set():
                    return

                if length == 1:
                    candidate = first_char
                    success = self.check_password(candidate, algorithm, full_hash, rounds)
                    local_attempts += 1

                    if success:
                        self.report_success(candidate, local_attempts, batch_size)
                        return

                else:
                    for combo in itertools.product(Worker.LEGAL_CHARACTERS, repeat=length - 1):

                        if Worker.found_event.is_set():
                            return

                        candidate = first_char + ''.join(combo)
                        success = self.check_password(candidate, algorithm, full_hash, rounds)
                        local_attempts += 1

                        if local_attempts % batch_size == 0:
                            with Worker.attempts_lock:
                                Worker.attempts += batch_size

                        if success:
                            self.report_success(candidate, local_attempts, batch_size)
                            return

        # flush remainder
        remainder = local_attempts % batch_size
        if remainder:
            with Worker.attempts_lock:
                Worker.attempts += remainder

    def check_password(self, password, algorithm, full_hash, rounds):
        if algorithm in ["y", "1", "5", "6"]:
            return crypt.crypt(password, full_hash) == full_hash

        elif algorithm == "2b":
            shadow_hash = f"${algorithm}${rounds}${full_hash[3:]}"
            return bcrypt.checkpw(password.encode(), shadow_hash.encode())

        else:
            raise Exception("Unsupported hash algorithm")
    
    def report_success(self, password, local_attempts, batch_size):
        print(f"[FOUND] Password: {password}")
        Worker.found_password = password
        Worker.found_event.set()

        remainder = local_attempts % batch_size
        if remainder:
            with Worker.attempts_lock:
                Worker.attempts += remainder

    def crack_password(self, hashed_password, salt, algorithm, rounds=None, num_threads=4):
        Worker.attempts = 0
        Worker.found_event.clear()
        Worker.found_password = None

        full_hash = f"${algorithm}{salt}{hashed_password}"

        charset = Worker.LEGAL_CHARACTERS
        chunk_size = len(charset) // num_threads

        threads = []

        for i in range(num_threads):
            start = i * chunk_size
            end = None if i == num_threads - 1 else (i + 1) * chunk_size
            charset_slice = charset[start:end]

            t = threading.Thread(
                target=self.crack_worker,
                args=(charset_slice, algorithm, full_hash, rounds)
            )
            t.start()
            threads.append(t)

        for t in threads:
            t.join()

        if Worker.found_event.is_set():
            print(f"Total attempts: {Worker.attempts}")
        else:
            print("Password not found.")


    def start_heartbeat_listener(self):
        hb_thread = threading.Thread(
            target=self.heartbeat_listener,
            daemon=True)
        hb_thread.start()

    def heartbeat_listener(self):
        
        while not Worker.shutdown_event.is_set():

            request = self.receive_response()
            print("[HEARTBEAT] Request received")
            if request:
                with Worker.attempts_lock:
                    response = {"type": "heartbeat", "attempts": Worker.attempts}
                    self.send_response(response)
                    print("[HEARTBEAT] Response sent")


    def cleanup(self, success):
        # Wait for all threads to finish
        for t in self.threads:
            if t.is_alive():
                t.join()

        if self.client:
            self.client.close()

        exit(0 if success else 1)

if __name__ == "__main__":
    worker = Worker()