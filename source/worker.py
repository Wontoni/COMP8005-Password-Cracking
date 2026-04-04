import socket
import ipaddress
import pickle
import bcrypt
from passlib.hash import md5_crypt, sha256_crypt, sha512_crypt
import string
import argparse
import threading
import queue
import time
import faulthandler
from yescrypt_wrap import verify_yescrypt
import os

faulthandler.enable()

# libcrypt = ctypes.CDLL("libcrypt.so.1")
# libcrypt.crypt.restype = ctypes.c_char_p


class Worker:
    attempts = 0
    last_attempt = 0
    attempts_lock = threading.Lock()
    jobs_lock = threading.Lock()
    found_event = threading.Event()
    shutdown_event = threading.Event()
    request_event = threading.Event()
    found_password = None
    active_jobs = 0
    active_jobs_lock = threading.Lock()
    yescrypt_lock = threading.Lock()

    LEGAL_CHARACTERS = (
        string.ascii_lowercase +
        string.ascii_uppercase +
        string.digits +
        "@#%^&*()_+-=.,:;?"
    )

    def __init__(self):
        self.ipv4 = "10.0.0.34"
        self.ipv6 = "2604:3d08:597e:ef00:a21d:8635:3d84:d9d1"

        self.waiting_for_job = False
        self.server_port = 8080
        self.server_host = None
        self.client = None

        self.threads = []
        self.listener = None
        self.job_queue = queue.Queue()

        self.dispatch_latency = 0
        self.total_crack_time = 0
        self.run()

    def run(self):
        self.create_args()
        self.check_args()
        self.handle_args()

        self.create_socket()
        self.connect_client()


        self.start_thread_listener()
        self.start_worker_threads(self.thread_count)

        # Keep main thread alive until shutdown
        try:
            while not Worker.shutdown_event.is_set():
                time.sleep(0.1)
        finally:
            self.cleanup(True)

    def accept_job(self, decoded_message):
        print(decoded_message)

        Worker.found_password = None
        Worker.found_event.clear()

        algorithm = decoded_message.get("hash_algorithm")
        salt = decoded_message.get("salt")
        hashed_password = decoded_message.get("hashed_password")
        rounds = decoded_message.get("rounds")
        start_index = decoded_message.get("start_index")
        curr_checkpoint = decoded_message.get("curr_checkpoint")
        end_index = decoded_message.get("end_index")
        checkpoint_interval = decoded_message.get("checkpoint_interval")

        if algorithm == "2b":
            full_hash = f"$2b${str(rounds).zfill(2)}${salt}{hashed_password}"
        elif algorithm in ["1", "5", "6", "y"]:
            full_hash = f"${algorithm}{salt}{hashed_password}"
        else:
            raise Exception(f"Unsupported hash algorithm: {algorithm}")

        self.dispatch_latency = time.time() - decoded_message.get("time_sent")

        chunk_size = end_index - curr_checkpoint + 1
        thread_chunk = max(1, chunk_size // self.thread_count)

        for i in range(self.thread_count):
            thread_start = curr_checkpoint + i * thread_chunk
            if thread_start > end_index:
                break

            if i == self.thread_count - 1:
                thread_end = end_index
            else:
                thread_end = min(end_index, thread_start + thread_chunk - 1)

            self.job_queue.put((algorithm, full_hash, thread_start, thread_end, checkpoint_interval, start_index))
            print(f"[JOB SPLIT] thread={i} range=({thread_start}, {thread_end})")

    def create_response(self, msg_type, checkpoint=0):
        return {
            "type": msg_type,
            "password": Worker.found_password,
            "crack_time": self.total_crack_time,
            "dispatch_latency": self.dispatch_latency,
            "sent_time": time.time(),
            "checkpoint": checkpoint
        }

    def create_args(self):
        parser = argparse.ArgumentParser(description="Worker Script")
        parser.add_argument("-c", "--controller", required=True, help="IP Address of the controller")
        parser.add_argument("-p", "--port", type=int, required=True, help="Port number of the controller")
        parser.add_argument("-t", "--threads", type=int, required=True, help="Number of threads to create")
        self.args = parser.parse_args()

    def check_args(self):
        try:
            self.is_ipv4(self.args.controller)
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
            client = socket.socket(
                (socket.AF_INET6, socket.AF_INET)[self.is_ipv4(self.server_host)],
                socket.SOCK_STREAM
            )
            self.client = client
        except Exception as e:
            self.handle_error(f"Failed to create client socket: {e}")
            raise

    def connect_client(self):
        try:
            client.settimeout(5)
            client.connect((self.server_host, self.server_port))
        except Exception as e:
            self.handle_error(f"Failed to connect to socket with the address and port - {self.server_host}:{self.server_port}")
            raise

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
                return None
            return pickle.loads(received_data)
        except socket.timeout:
            return None
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

        self.handle_error("Invalid IP Address found.")

    def handle_error(self, err_message):
        print(f"Error: {err_message}")
        Worker.shutdown_event.set()

    def index_to_password(self, global_index):
        n = len(self.LEGAL_CHARACTERS)

        length = 1
        block_size = n

        while global_index >= block_size:
            global_index -= block_size
            length += 1
            block_size = n ** length

        chars = []
        for _ in range(length):
            chars.append(self.LEGAL_CHARACTERS[global_index % n])
            global_index //= n

        return "".join(reversed(chars))

    @staticmethod
    def store_job_info(job_info, filename="checkpoint.bin"):
        with open(filename, "wb") as f:
            pickle.dump(job_info, f)

    @staticmethod
    def load_job_info(filename="checkpoint.bin"):
        if os.path.exists(filename):
            with open(filename, "rb") as f:
                return pickle.load(f)
        return []
    
    def crack_worker(self):
        while not Worker.shutdown_event.is_set():
            try:
                algorithm, full_hash, start_index, end_index, checkpoint_interval, chunk_start = self.job_queue.get(timeout=0.5)
                last_job = self.load_job_info()
                if [algorithm, full_hash, chunk_start, end_index, checkpoint_interval] == last_job[:5]:
                    start_index = last_job[5]
                else:
                    self.store_job_info([algorithm, full_hash, chunk_start, end_index, checkpoint_interval, start_index])
            except queue.Empty:
                continue

            with Worker.active_jobs_lock:
                Worker.active_jobs += 1

            print(f"[START] {threading.current_thread().name} range=({start_index}, {end_index})")

            start_crack_time = time.time()
            local_attempts = 0
            batch_size = 50

            try:
                for current_index in range(start_index, end_index + 1):
                    if Worker.shutdown_event.is_set() or Worker.found_event.is_set():
                        break

                    candidate = self.index_to_password(current_index)
                    local_attempts += 1

                    if self.check_password(candidate, algorithm, full_hash):
                        elapsed = time.time() - start_crack_time
                        self.total_crack_time += elapsed
                        self.report_success(candidate, local_attempts)
                        

                    if local_attempts % batch_size == 0:
                        with Worker.attempts_lock:
                            Worker.attempts += batch_size
                            print("[WORKER ATTEMPTS]", Worker.attempts)
                            print("[MODULUS]", Worker.attempts % checkpoint_interval)
                            if Worker.attempts % checkpoint_interval == 0:
                                print("SEND")
                                response = self.create_response("checkpoint", Worker.attempts)
                                self.send_response(response)

                remainder = local_attempts % batch_size
                print(local_attempts)
                if remainder:
                    with Worker.attempts_lock:
                        Worker.attempts += remainder

            finally:
                elapsed = time.time() - start_crack_time
                self.total_crack_time += elapsed

                with Worker.active_jobs_lock:
                    Worker.active_jobs -= 1

                self.job_queue.task_done()
                print(f"[END] {threading.current_thread().name} attempts={local_attempts}")
                with Worker.active_jobs_lock:
                    if self.job_queue.qsize() == 0 and Worker.active_jobs == 0 and not self.waiting_for_job:
                        self.request_job()
                        self.waiting_for_job = True


    def check_password(self, password, algorithm, full_hash):
        if algorithm == "1":
            return md5_crypt.verify(password, full_hash)

        elif algorithm == "5":
            return sha256_crypt.verify(password, full_hash)

        elif algorithm == "6":
            return sha512_crypt.verify(password, full_hash)

        elif algorithm == "2b":
            return bcrypt.checkpw(password.encode()[:72], full_hash.encode())

        elif algorithm == "y":
            return verify_yescrypt(password, full_hash)

        else:
            raise Exception(f"Unsupported hash algorithm: {algorithm}")

    def report_success(self, password, local_attempts):
        if Worker.found_event.is_set():
            return

        Worker.found_password = password
        Worker.found_event.set()

        print(f"[FOUND] Password: {password}")
        print(f"Total attempts: {Worker.attempts + local_attempts}")

        response = self.create_response("cracked_success")
        self.send_response(response)

    def start_worker_threads(self, num_threads=4):
        for i in range(num_threads):
            t = threading.Thread(target=self.crack_worker, name=f"crack-{i}", daemon=True)
            t.start()
            self.threads.append(t)

    def start_thread_listener(self):
        self.listener = threading.Thread(target=self.listener_thread, daemon=True, name="listener")
        self.listener.start()

    def listener_thread(self):
        while not Worker.shutdown_event.is_set():
            if Worker.found_event.is_set():
                Worker.shutdown_event.set()
                break

            decoded_message = self.receive_response()
            if decoded_message is None:
                continue

            msg_type = decoded_message.get("type")
            if msg_type == "job":
                print("============================ JOB RECEIVED ============================")
                self.waiting_for_job = False
                self.accept_job(decoded_message)

            elif msg_type == "heartbeat_request":
                print("==================== HEARTBEAT REQUEST RECEIVED ====================")
                self.handle_heartbeat_request()
            elif msg_type == "end":
                print("==================== SHUTDOWN FLAG RECEIVED ====================")
                Worker.shutdown_event.set()
            else:
                print("[ERROR] Invalid response received")
                Worker.shutdown_event.set()
                break

    def request_job(self):
        response = self.create_response("job_finished")
        self.send_response(response)

    def handle_heartbeat_request(self):
        with Worker.attempts_lock:
            delta = Worker.attempts - Worker.last_attempt
            Worker.last_attempt = Worker.attempts

        response = {
            "type": "heartbeat",
            "attempts": Worker.attempts,
            "delta_attempts": delta
        }
        self.send_response(response)
        print("[HEARTBEAT] Response sent")

    def cleanup(self, success):
        Worker.shutdown_event.set()

        if self.client:
            try:
                self.client.close()
            except Exception:
                pass

        current = threading.current_thread()
        for t in self.threads:
            if t.is_alive() and t is not current:
                t.join(timeout=1.0)


if __name__ == "__main__":
    worker = Worker()