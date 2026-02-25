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
        
        self.workers = {} # Addr: socket

        self.start_time = datetime.now()
        self.shadow_file_contents = self.check_shadow_file(self.shadow_file)
        self.parse_shadow_username(self.shadow_file_contents)
        parse_time = datetime.now()

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

        self.args = parser.parse_args()
 
    def handle_args(self):
        try:
            self.shadow_file = self.args.file
            self.username = self.args.user
            self.server_port = self.args.port
            self.heartbeat_timeout = self.args.heartbeat_seconds # seconds
            self.chunksize = self.args.chunk_size

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
            self.accept_connection() # Accept connection then sends out the parsing information
                # while True:
                #     data = self.request_heartbeat()
                #     self.process_response(data)
                #     time.sleep(self.heartbeat_timeout)

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
                self.inputs
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
                        "registered": True # Condition to register? not for this assignment..
                    }
                    print("Worker registered:", addr)
                    job = self.construct_job()
                    connection.sendall(job) # send first job
                else:
                    # Existing worker sent data
                    # CHECK WHAT IS BEING SENT BACk
                    # HEARTBEAT? UPDATE VALUES
                    # JOB FINISHED/REQUEST? SEND NEXT JOB
                    data = s.recv(1024)
                    data = pickle.loads(data)
                    print("RECEIVED")
                    print(data)

                    if data:
                        if self.workers[s]["registered"]:

                            if data.get('type') == "job_finished":
                                # send a new job
                                job = self.construct_job()
                                s.sendall(job)
                            elif data.get('type') == "heartbeat":
                                continue
                            elif data.get('type') == "cracked_success":
                                self.result_response(data)
                                continue
                        else:
                            # Worker registration, not needed
                            continue
                    else:
                        # Connection closed
                        print("Worker disconnected")
                        self.inputs.remove(s)
                        del self.workers[s]
                        s.close()

            for s in exceptional:
                self.inputs.remove(s)
                if s in self.workers:
                    del self.workers[s]
                s.close()
    
    def construct_job(self):
        start_index = self.next_index
        end_index = self.next_index + self.chunksize - 1 # 0-999 is 1000 passwords, inclusive end_index is 999
        data = {
            'type': "job",
            'hash_algorithm': self.hash_algorithm,
            'salt': self.salt,
            'hashed_password': self.hashed_password,
            'rounds': getattr(self, 'rounds', None),
            'time_sent': datetime.now(),
            'start_index': start_index,
            'end_index': end_index
        }
        self.next_index += self.chunksize # Start at the next password after the chunksize
        response = pickle.dumps(data)
        return response
    
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
            self.handle_error(f"Failed to unpickle data: {e}")

    def request_heartbeat(self):
        outgoing = {"type": "heartbeat-request"}
        response = pickle.dumps(outgoing)
        self.connection.sendall(response)
        print('Sent heartbeat request to', self.client_addr)

        data = self.receive_response()
        return data

    def handle_data(self):
        data = {
            'type': "job",
            'hash_algorithm': self.hash_algorithm,
            'salt': self.salt,
            'hashed_password': self.hashed_password,
            'rounds': getattr(self, 'rounds', None),
            'time_sent': datetime.now()
        }
        response = pickle.dumps(data)
        return response

    def process_response(self, data):
        if data["type"] == "password":
            self.result_response(data)
        elif data["type"] == "heartbeat":
            self.heartbeat_response(data)
        else:
            print("RECEIVED UNKNOWN RESPONSE")
            self.cleanup(False)

    def result_response(self, data):
        return_latency = datetime.now() - data["sent_time"]
        end_runtime = self.controller_parsing_time.total_seconds() + data['dispatch_latency'].total_seconds() + data['crack_time'].total_seconds() + return_latency.total_seconds()
        print("=============================================================")
        print(f"Hash Algorithm: {Controller.ALGORITHMS[self.hash_algorithm]}")
        print(f"Password Found: {data['password']}")
        print(f"Controller Parsing Time: {self.controller_parsing_time.total_seconds()} seconds")
        print(f"Dispatch Latency: {data['dispatch_latency'].total_seconds()} seconds")
        print(f"Cracking Time: {data['crack_time'].total_seconds()} seconds")
        print(f"Return Latency: {return_latency.total_seconds()} seconds")
        print(f"Total end-to-end Runtime: {end_runtime} seconds")
        print("=============================================================")
        
        print(f"{self.controller_parsing_time.total_seconds()}")
        print(f"{data['dispatch_latency'].total_seconds()}")
        print(f"{data['crack_time'].total_seconds()}")
        print(f"{return_latency.total_seconds()}")
        print(f"{end_runtime}")
        self.cleanup(True)

    def heartbeat_response(self, data):
        print(f"[HEARTBEAT] Response received, {data['attempts']} attempts tried.")

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
