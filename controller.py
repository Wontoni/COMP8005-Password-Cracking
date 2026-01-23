import socket
import re
import select
import queue
import struct
import pickle
import sys

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
        print(self.shadow_file_contents)

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
        try:
            lines = shadow_file.readlines()
            for line in lines:
                parts = line.strip().split(':')
                print(line)
                if parts[0] == self.username:
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
                self.algorithm_options = parts[1].split('$')[2]
                self.salt = parts[1].split('$')[3]
                self.hashed_password = parts[1].split('$')[4]
                print("Parsed shadow file line:")
                print(f"Hash Algorithm: {self.hash_algorithm}")
                print(f"Algorithm Options: {self.algorithm_options}")
                print(f"Salt: {self.salt}")     
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
                    else:
                        data_size = struct.unpack(">I", s.recv(4))[0]
                        receieved_data = b""
                        remaining_data_size = data_size

                        if data_size:
                            while remaining_data_size != 0:
                                receieved_data += s.recv(remaining_data_size)
                                remaining_data_size = data_size - len(receieved_data)
                            data = pickle.loads(receieved_data)
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
                        s.sendall(struct.pack(">I", len(next_msg)))
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
            'algorithm_options': self.algorithm_options,
            'salt': self.salt,
            'hashed_password': self.hashed_password
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
