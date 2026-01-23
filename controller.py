import socket
import re
import select
import queue
import struct
import pickle
import sys

TESTING_LINE = "abc:$2b$05$5tWeu9RE4wiQ.RWTSDBebOaone9Wz2cILBmCN7zGI65CiRlMfCCdW:20474:0:99999:7:::"
class Controller:
    def __init__(self):
        self.check_args(sys.argv)
        self.handle_args(sys.argv)
        self.connection = None
        self.server = None
        self.server_host = "::"
        self.server_port = 8080
        self.inputs = []
        self.outputs = []
        self.message_queues = {}

        self.shadow_file_contents = self.check_shadow_file(self.shadow_file)
        self.parse_shadow_username(self.shadow_file_contents)

        self.start_server()

    def check_args(self, args):
        try:
            if len(args) != 3:
                raise Exception("Invalid number of arguments")

        except Exception as e:
            self.handle_error(e)
            exit(1)

    def handle_args(self, args):
        try:
            self.shadow_file = args[1]
            self.username = args[2]
        except Exception as e:
            self.handle_error("Failed to retrieve inputted arguments.")


    def check_shadow_file(self, shadow_file):
        try:
            with open(shadow_file, 'r') as f:
                return self.read_shadow_file(f)
        except Exception as e:
            self.handle_error("Failed to open shadow file.")
        
    def read_shadow_file(self, shadow_file):
        if True: # TODO: CHANGE HERE FOR COMMAND LINE INPUTS

            return TESTING_LINE
        else:
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
                print("Parsed shadow file line:")
                print(f"Hash Algorithm: {self.hash_algorithm}")
                print(f"Salt: {self.salt}")     
                print(f"Password: {self.hashed_password}")
            if self.hash_algorithm in ["1", "5", "6"]: # MD5, SHA-256, SHA-512
                self.salt = f"${parts[1].split('$')[2]}$" # $salt$
                self.hashed_password = parts[1].split('$')[3]
                print("Parsed shadow file line:")
                print(f"Hash Algorithm: {self.hash_algorithm}")
                print(f"Salt: {self.salt}")     
                print(f"Password: {self.hashed_password}")
            elif self.hash_algorithm == "2b": # bcrypt
                self.rounds = parts[1].split('$')[2]
                self.salt = parts[1].split('$')[3][:22] # Salt is combined with hashed password (first 22 characters)
                self.hashed_password = parts[1].split('$')[3][22:] # Remaining is hashed password
                print("Parsed shadow file line:")
                print(f"Hash Algorithm: {self.hash_algorithm}")
                print(f"Salt: {self.salt}")     
                print(f"Rounds: {self.rounds}")
                print(f"Password: {self.hashed_password}")
            return
        except Exception as e:
            print(e)
            self.handle_error("Failed to parse shadow file line for username.")

    def start_server(self):
        self.create_socket()
        self.listen_connections()
        
        try:
            while True:
                self.accept_connection()
        except Exception as e:
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
            self.server.setblocking(0)
                
        except Exception as e:
            self.handle_error("Failed to create socket server")
            
    def listen_connections(self):
        try:
            self.server.listen(5)
            print(f'Server is listening on port {self.server_port} for incoming connections...')
        except Exception as e:
            self.handle_error("Failed to listen to connections")

    def accept_connection(self):
        try:
            while self.inputs:
                readable, writable, exceptional = select.select(self.inputs, self.outputs, self.inputs)

                for s in readable:
                    if s is self.server:
                        self.connection, client_addr = s.accept()
                        print('Connection Received: ', client_addr)
                        self.connection.setblocking(1)
                        self.inputs.append(self.connection)

                        self.message_queues[self.connection] = queue.Queue()

                        try:
                            next_msg = self.handle_data()
                            self.connection.sendall(next_msg)
                            print('Sent initial response to', client_addr)
                        except Exception as e:
                            print(f"Warning: failed to send initial response: {e}")
                    else:
                        received = s.recv(1024)

                        if received:
                            try:
                                data = pickle.loads(received)
                            except Exception as e:
                                self.handle_error(f"Failed to unpickle data: {e}")
                                continue

                            self.inputs.remove(s)
                            self.message_queues[s].put(data)
                            if s not in self.outputs:
                                self.outputs.append(s)
                        else:
                            if s in self.outputs:
                                self.outputs.remove(s)
                            self.inputs.remove(s)
                            s.close()

                            del self.message_queues[s]

                for s in writable:
                    try:
                        message_data = self.message_queues[s].get_nowait()
                    except queue.Empty:
                        self.outputs.remove(s)
                    else:
                        next_msg = self.handle_data()
                        s.sendall(next_msg)
                
                for s in exceptional:
                    self.inputs.remove(s)
                    if s in self.outputs:
                        self.outputs.remove(s)
                    s.close()

                    del self.message_queues[s]
        except Exception as e:
            self.handle_error(e)

    def handle_data(self):
        data = {
            'hash_algorithm': self.hash_algorithm,
            'salt': self.salt,
            'hashed_password': self.hashed_password,
            'rounds': getattr(self, 'rounds', None)
        }
        response = pickle.dumps(data)
        return response

    def handle_error(self, err_message):
        print(f"Error: {err_message}")
        self.cleanup(False)
        
    def cleanup(self, success):
        if self.server:
            self.server.close()
        if success:
            exit(0)
        exit(1)

def main():
    controller = Controller()

if __name__ == "__main__":
    main()
