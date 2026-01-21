import socket
import re
import select
import queue
import struct
import pickle


class Controller:
    def __init__(self):
        self.connection = None
        self.server = None
        self.server_host = "::"
        self.server_port = 8080
        self.inputs = []
        self.outputs = []
        self.message_queues = {}

        self.start_server()

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
            exit(1)
            
    def listen_connections(self):
        try:
            self.server.listen(5)
            print(f'Server is listening on port {self.server_port} for incoming connections...')
        except Exception as e:
            self.handle_error("Failed to listen to connections")
            exit(1)

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
                        next_msg = self.handle_data(message_data)
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
            exit(1)

    @staticmethod
    def handle_data(data):
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
    controller = Controller() # Args and arg handling here?

if __name__ == "__main__":
    main()
