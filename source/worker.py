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
    jobs_lock = threading.Lock()
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
        self.job_list = [] # [(start_index, end_index), (...)]
        
        self.run()

    def run(self):
        self.create_args()
        self.check_args()
        self.handle_args()

        self.create_socket()
        self.connect_client()
        self.start_thread_listener()
        while True:
            self.accept_job()


    def accept_job(self):
        decoded_response = self.receive_response()
        self.display_message(decoded_response)

        start_time = datetime.now()
        self.crack_password(self.hashed_password, self.salt, self.algoritihm, self.rounds, num_threads=self.thread_count)
        end_time = datetime.now()
        self.crack_time = end_time - start_time

        if Worker.found_event.is_set():
            print(f"Total attempts: {Worker.attempts}")
            # Send a crack_password type
            response = self.create_response("cracked_success")
        else:
            print("Password not found.")
            # Request a new job
            response = self.create_response("job_finished")
        
        self.send_response(response)


    def create_response(self, type):
        response = {
            "type": type,
            "password": Worker.found_password,
            "crack_time": self.crack_time,
            "dispatch_latency": self.dispatch_latency,
            "sent_time": datetime.now()
        }
        return response

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
                raise Exception
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
        self.start_index = message.get("start_index")
        self.end_index = message.get("end_index")

    def index_to_password(self, global_index):
        N = len(self.LEGAL_CHARACTERS)

        # Step 1: Find correct length
        length = 1
        block_size = N

        while global_index >= block_size:
            global_index -= block_size
            length += 1
            block_size = N ** length

        # Step 2: Convert remaining index to base-N
        chars = []
        for _ in range(length):
            chars.append(self.LEGAL_CHARACTERS[global_index % N])
            global_index //= N

        return "".join(reversed(chars))

    def crack_worker(self, algorithm, full_hash, start_index, end_index, rounds=None):
        local_attempts = 0
        batch_size = 200
        current_index = start_index

        while current_index <= end_index:
            if Worker.found_event.is_set():
                return
            candidate = self.index_to_password(current_index)
            success = self.check_password(candidate, algorithm, full_hash, rounds)
            if success:
                self.report_success(candidate, local_attempts, batch_size)
                return
            current_index += 1
            local_attempts += 1

            if local_attempts % batch_size == 0:
                with Worker.attempts_lock:
                    Worker.attempts += batch_size

        print("Finished trying passwords:", local_attempts)
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

        chunk_size = self.end_index - self.start_index 
        thread_chunk = chunk_size // num_threads
        threads = []

        for i in range(num_threads):
            start = i * thread_chunk
            end = self.end_index if i == num_threads - 1 else (i + 1) * thread_chunk

            t = threading.Thread(
                target=self.crack_worker,
                args=(algorithm, full_hash, start, end, rounds)
            )
            t.start()
            threads.append(t)

        for t in threads:
            t.join()


    def start_thread_listener(self):
        thread_listener = threading.Thread(
            target=self.listener_thread,
            daemon=True)
        thread_listener.start()

    def listener_thread(self):
        decoded_message = self.receive_response()

        if decoded_message.get('type') == "job":
            self.accept_job()
        elif decoded_message.get('type') == "heartbeat_request":
            self.handle_heartbeat_request()
        else:
            print('[ERROR] Invalid response received')
            self.cleanup(False)

    def handle_heartbeat_request(self):
        
        while not Worker.shutdown_event.is_set():
            print("[HEARTBEAT] Request received")
            with Worker.attempts_lock:
                response = {"type": "heartbeat", "attempts": Worker.attempts} # TODO: DELTA
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