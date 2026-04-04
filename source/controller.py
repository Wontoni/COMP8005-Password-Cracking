import socket
import select
import queue
import pickle
import argparse
from datetime import datetime
import time
import itertools

class Controller:
    # MD5: $1$salt$hash
    # bcrypt: $2b$cost$saltAndHash
    # SHA-256: $5$salt$hash
    # SHA-512: $6$salt$hash
    # yescrypt: $y$options$salt$hash
    ALGORITHMS = {
        "1": "MD5",
        "2b": "bcrypt",
        "5": "SHA-256",
        "6": "SHA-512",
        "y": "yescrypt"
    }

    def __init__(self):
        self.create_args()
        self.handle_args()
        self.connection = None
        self.server = None
        self.server_host = "::"
        self.inputs = []
        self.outputs = []
        self.message_queues = {}
        self.next_index = 0
        self.failed_jobs = [] # [(start, end, checkpoint), (), (), ()]

        self.workers = {}

        self.total_dispatch_latency = 0
        self.total_crack_time = 0
        self.total_return_latency = 0

        self.start_time = time.time()
        self.shadow_file_contents = self.check_shadow_file(self.shadow_file)
        self.parse_shadow_username(self.shadow_file_contents)
        parse_time = time.time()

        self.controller_parsing_time = parse_time - self.start_time
        self.start_server()

    def create_args(self):
        def positive_int(value):
            ivalue = int(value)
            if ivalue <= 0:
                raise argparse.ArgumentTypeError(f"{value} is not a positive integer")
            return ivalue
        
        parser = argparse.ArgumentParser(
            description="Password Cracker Controller Script"
        )

        parser.add_argument(
            "-f", "--file",
            required=True,
            help="Path to the shadow file"
        )

        parser.add_argument(
            "-u", "--user",
            required=True,
            help="Username of the password to crack"
        )

        parser.add_argument(
            "-p", "--port",
            type=positive_int,
            required=True,
            help="Port number to host on"
        )

        parser.add_argument(
            "-b", "--heartbeat_seconds",
            type=positive_int,
            required=True,
            help="Interval between heartbeat requests (seconds)"
        )

        parser.add_argument(
            "-c", "--chunk_size",
            type=positive_int,
            required=True,
            help="Chunk size to send workers"
        )

        parser.add_argument(
            "-k", "--checkpoint_attempts",
            type=positive_int,
            required=True,
            help="Number of passwords attempts for each checkpoint"
        )

        self.args = parser.parse_args()
 
    def handle_args(self):
        try:
            self.shadow_file = self.args.file
            self.username = self.args.user
            self.server_port = self.args.port
            self.heartbeat_timeout = self.args.heartbeat_seconds # seconds
            self.chunksize = self.args.chunk_size
            self.checkpoint_attempts = self.args.checkpoint_attempts

        except Exception as e:
            print(e)
            self.handle_error("Failed to retrieve inputted arguments.")

    def check_shadow_file(self, shadow_file):
        try:
            with open(shadow_file, 'r') as f:
                return self.read_shadow_file(f)
        except Exception as e:
            self.handle_error("Failed to open shadow file.")
        
    def read_shadow_file(self, shadow_file):
        try:
            lines = shadow_file.readlines()
            for line in lines:
                parts = line.strip().split(':')
                if parts[0] == self.username:
                    print(f"Shadow file line:\n{line.strip()}")
                    return line
            self.handle_error("Username not found in shadow file.")
        except Exception as e:
            self.handle_error("Failed to read shadow file.")

    def parse_shadow_username(self, shadow_line):
        try:
            parts = shadow_line.strip().split(':')
            self.hash_algorithm = parts[1].split('$')[1]
            # MD5: $1$salt$hash
            # bcrypt: $2b$cost$saltAndHash
            # SHA-256: $5$salt$hash
            # SHA-512: $6$salt$hash
            # yescrypt: $y$options$salt$hash

            if self.hash_algorithm == "y": # yescrypt
                self.salt = f"${parts[1].split('$')[2]}${parts[1].split('$')[3]}$" # $options$salt$
                self.hashed_password = parts[1].split('$')[4]
            if self.hash_algorithm in ["1", "5", "6"]: # MD5, SHA-256, SHA-512
                self.salt = f"${parts[1].split('$')[2]}$" # $salt$
                self.hashed_password = parts[1].split('$')[3]
            elif self.hash_algorithm == "2b": # bcrypt
                self.rounds = parts[1].split('$')[2]
                self.salt = parts[1].split('$')[3][:22] # Salt is combined with hashed password (first 22 characters)
                self.hashed_password = parts[1].split('$')[3][22:] # Remaining is hashed password
            return
        except Exception as e:
            print(e)
            self.handle_error("Failed to parse shadow file line for username.")

    def start_server(self):
        self.create_socket()
        self.listen_connections()
        self.accept_connection()
        try:
            self.accept_connection()

        except Exception as e:
            print(e)
            self.handle_error("Failed to receive data from client")

    def create_socket(self):
        try:
            addr = (self.server_host, self.server_port)
            if socket.has_dualstack_ipv6():
                self.server = socket.create_server(addr, family=socket.AF_INET6, dualstack_ipv6=True)
                print("Server running on dual-stack mode (IPv4 and IPv6).")
            else:
                self.server = socket.create_server(addr)
                print("Server running on default mode.")
            self.inputs = [self.server]
            self.server.setblocking(False) # CHANGE IN THE FUTURE
                
        except Exception as e:
            print(e)
            self.handle_error("Failed to create socket server")
            
    def listen_connections(self):
        try:
            self.server.listen(5)
            print(f'Server is listening on port {self.server_port} for incoming connections...')
        except Exception as e:
            self.handle_error("Failed to listen to connections")

    def accept_connection(self):
        while self.inputs:
            readable, writable, exceptional = select.select(
                self.inputs,
                self.outputs,
                self.inputs,
                1.0
            )

            for s in readable:
                if s is self.server:
                    # New worker connection
                    connection, addr = self.server.accept()
                    # print("Connection from", addr)
                    connection.setblocking(False)

                    self.inputs.append(connection)
                    self.workers[connection] = {
                        "addr": addr,
                        "registered": True,
                        "last_heartbeat_sent": time.time() - 0.000001,
                        "last_heartbeat_received": time.time(),
                        "assigned_chunk": (0, 0, 0) # (start_index, end_index, last_checkpoint)
                    }
                    print("Worker registered:", addr)
                    job_order, job_assigned = self.construct_job()
                    self.workers[connection]['assigned_chunk'] = job_assigned
                    connection.sendall(job_order) # send first job
                else:
                    data = s.recv(1024)
                    if not data:
                        continue
                    data = pickle.loads(data)
                    print("RECEIVED")
                    print(data)

                    if data:
                        if self.workers[s]["registered"]:

                            if data.get('type') == "job_finished":
                                # send a new job
                                self.handle_performance(data)
                                job, assigned_job = self.construct_job()
                                print("[ASSIGN] Assigning job", assigned_job)
                                print(s)
                                self.workers[s]["assgined_chunk"] = assigned_job
                                s.sendall(job)
                            elif data.get('type') == "heartbeat":
                                self.heartbeat_response(data, s)
                            elif data.get('type') == "cracked_success":
                                self.result_response(data)
                            elif data.get('type') == "checkpoint":
                                self.handle_checkpoint(data, s)
                        else:
                            # Worker registration, not needed
                            continue
                    else:
                        print("Worker disconnected FIX SOMETHING HERE RAHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHH")
                        self.inputs.remove(s)
                        del self.workers[s]
                        s.close()

            # Heartbeat
            now = time.time()
            for ws, wdata in list(self.workers.items()):
                if not wdata['registered']:
                    continue

                if wdata['last_heartbeat_received'] > wdata['last_heartbeat_sent']:
                    if now - wdata['last_heartbeat_sent'] > self.heartbeat_timeout: # send every x (heartbeat_timeout) seconds
                        try:
                            self.request_heartbeat(ws)
                            wdata['last_heartbeat_sent'] = now
                        except Exception as e:
                            print(f"[HEARTBEAT] Error sending heartbeat to {wdata['addr']}: {e}")
                            self.remove_worker(ws)
                elif now - wdata['last_heartbeat_sent'] > self.heartbeat_timeout:
                    print(now)
                    print(wdata['last_heartbeat_sent'])
                    print(self.heartbeat_timeout)
                    print(f"[HEARTBEAT] Worker timing out: {wdata['addr']}")
                    self.remove_worker(ws)


            for s in exceptional:
                self.inputs.remove(s)
                if s in self.workers:
                    del self.workers[s]
                s.close()

    def handle_checkpoint(self, data, worker):
        start = data["start_index"]
        end = data["end_index"]
        checkpoint = data["checkpoint"]

        self.workers[worker]["assigned_chunk"] = (start, end, checkpoint)
        print("[Worker Checkpoint]:", self.workers[worker]["assigned_chunk"])

    def handle_performance(self, data):
        dispatch_latency = data.get('dispatch_latency')
        self.total_dispatch_latency += dispatch_latency

        crack_time = data.get('crack_time')
        self.total_crack_time += crack_time

        return_latency = data.get('sent_time')
        self.total_return_latency += time.time() - return_latency

    def construct_job(self):
        if self.failed_jobs:
            print("[JOB] Sending failed job")
            failed_job = self.failed_jobs.pop(0)
            start_index = failed_job[0]
            end_index = failed_job[1]
            curr_checkpoint = failed_job[2]
        else:
            start_index = self.next_index
            end_index = self.next_index + self.chunksize - 1 # 0-999 is 1000 passwords, inclusive end_index is 999
            curr_checkpoint = start_index
            self.next_index += self.chunksize # Start at the next password after the chunksize

        data = {
            'type': "job",
            'hash_algorithm': self.hash_algorithm,
            'salt': self.salt,
            'hashed_password': self.hashed_password,
            'rounds': getattr(self, 'rounds', None),
            'time_sent': time.time(),
            'start_index': start_index,
            'end_index': end_index,
            'curr_checkpoint': curr_checkpoint,
            'checkpoint_interval': self.checkpoint_attempts
        }

        job_assigned = [start_index, end_index, curr_checkpoint]
        response = pickle.dumps(data)
        return response, job_assigned
    
    def remove_worker(self, ws):
        addr = self.workers[ws]['addr']
        failed_job = self.workers[ws]["assigned_chunk"]
        print("[JOB] Saving failed job", failed_job)
        self.failed_jobs.append(failed_job)

        print(f"[WORKER] Removing worker {addr}")
        if ws in self.inputs:
            self.inputs.remove(ws)
        del self.workers[ws]
        try:
            ws.close()
        except Exception:
            pass
    
    # TODO: CHANGE FOR MULTIPLE CLIENTS, THIS IS REDUNDANT RN
    def receive_response(self):
        try:
            received = self.connection.recv(4096)
            if not received:
                raise socket.timeout
        except socket.timeout:
            print("[HEARTBEAT] Failed to receive heartbeat response, shutting down")
            self.cleanup(False)
            return None

        try:
            data = pickle.loads(received)
            print("Received data from client:", data)
            return data
        except Exception as e:
            pass
            # self.handle_error(f"Failed to unpickle data: {e}")

    def request_heartbeat(self, worker_socket):
        try:
            # Send heartbeat request
            msg = {"type": "heartbeat_request", "time_sent": time.time()}
            worker_socket.sendall(pickle.dumps(msg))
            print(f"[HEARTBEAT] Sent request to {self.workers[worker_socket]['addr']}")
        except Exception as e:
            print(f"[HEARTBEAT] Error communicating with {self.workers[worker_socket]['addr']}: {e}")
            self.remove_worker(worker_socket)

    def handle_data(self):
        data = {
            'type': "job",
            'hash_algorithm': self.hash_algorithm,
            'salt': self.salt,
            'hashed_password': self.hashed_password,
            'rounds': getattr(self, 'rounds', None),
            'time_sent': time.time()
        }
        response = pickle.dumps(data)
        return response

    def result_response(self, data):
        end_runtime = time.time() - self.start_time
        self.total_dispatch_latency += data.get('dispatch_latency')
        self.total_crack_time += data.get('crack_time')
        self.total_return_latency += time.time() - data.get('sent_time')

        print("=============================================================")
        print(f"Hash Algorithm: {Controller.ALGORITHMS[self.hash_algorithm]}")
        print(f"Password Found: {data['password']}")
        print(f"Controller Parsing Time: {abs(self.controller_parsing_time)} seconds")
        print(f"Dispatch Latency: {abs(self.total_dispatch_latency)} seconds")
        print(f"Cracking Time: {abs(self.total_crack_time)} seconds")
        print(f"Return Latency: {abs(self.total_return_latency)} seconds")
        print(f"Total end-to-end Runtime: {abs(end_runtime)} seconds")
        print("=============================================================")
        
        print(f"{abs(self.controller_parsing_time)}")
        print(f"{abs(self.total_dispatch_latency)}")
        print(f"{abs(self.total_crack_time)}")
        print(f"{abs(self.total_return_latency)}")
        print(f"{abs(end_runtime)}")
        self.end_workers()
        self.cleanup(True)

    def end_workers(self):
        for ws in list(self.workers.keys()):
            try:
                msg = {"type": "end"}
                print("Sending end signal to worker", self.workers[ws]['addr'])
                ws.sendall(pickle.dumps(msg))
                ws.close()
            except Exception:
                pass
        
    def heartbeat_response(self, data, ws):
        print(f"[HEARTBEAT] Response received, {abs(data['delta_attempts'])} attempts tried since last heartbeat.")
        self.workers[ws]["last_heartbeat_received"] = time.time()

    def handle_error(self, err_message):
        print(f"Error: {err_message}")
        self.cleanup(False)
        
    def cleanup(self, success):
        if hasattr(self, "server") and self.server:
            self.server.close()
        if success:
            exit(0)
        exit(1)

def main():
    Controller()

if __name__ == "__main__":
    main()
