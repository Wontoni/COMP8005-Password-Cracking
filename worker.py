import socket
import sys
import ipaddress
import struct
import pickle

# Variables to change based on server host location
ipv4 = "10.0.0.34"
ipv6 = "2604:3d08:597e:ef00:a21d:8635:3d84:d9d1"

# Change to ipv4 for connection via IPv4 Address or ipv6 for IPv6
server_port = 8080


file_name = None
server_host = None
client = None


def main():
    check_args(sys.argv)
    handle_args(sys.argv)
    words = read_file()

    if words:
        create_socket()
        connect_client()
        send_message(words)
        receieve_response()

def check_args(args):
    try:
        if len(args) != 3:
            raise Exception("Invalid number of arguments")
        elif not args[1].endswith('.txt'):
            raise Exception("Invalid file extension, please input a .txt file")
        is_ipv4(args[2]) # Will handle invalid addresses
    except Exception as e:
        handle_error(e)
        exit(1)

def handle_args(args):
    global file_name, server_host
    try:
        file_name = sys.argv[1]
        server_host = sys.argv[2]
    except Exception as e:
        handle_error("Failed to retrieve inputted arguments.")

def create_socket():
    try: 
        global client
        # INET = IPv4 /// INET6 = IPv6
        client = socket.socket((socket.AF_INET6, socket.AF_INET)[is_ipv4(server_host)], socket.SOCK_STREAM)

    except Exception as e:
        handle_error("Failed to create client socket")
        exit(1)

def connect_client():
    try: 
        client.settimeout(10)
        client.connect((server_host, server_port))
    except Exception as e:
        handle_error(f"Failed to connect to socket with the address and port - {server_host}:{server_port}")
        exit(1)

def send_message(words): 
    try: 
        encoded = pickle.dumps(words)
        client.sendall(struct.pack(">I", len(encoded)))
        client.sendall(encoded)
    except Exception as e:
        handle_error("Failed to send words")
        exit(1)

def receieve_response():
    try: 
        data_size = struct.unpack(">I", client.recv(4))[0]
        # receive payload till received payload size is equal to data_size received
        received_data = b""
        remaining_size = data_size
        while remaining_size != 0:
            received_data += client.recv(remaining_size)
            remaining_size = data_size - len(received_data)
        decoded_response = pickle.loads(received_data)

        display_message(decoded_response)
    except Exception as e:
        handle_error("Failed to receive response")
        exit(1)

def read_file():
    try:
        with open(file_name, 'r', errors="ignore") as file:
            content = file.read()
            if not content:
                raise Exception("File is empty.")
            formatted_data = replace_new_lines(content)
            return formatted_data
    except FileNotFoundError:
        handle_error(f"File '{file_name}' not found.")
    except Exception as e:
        handle_error(e)

def replace_new_lines(text_data):
    try:
        res = text_data.replace('\n', ' ')
        return res
    except Exception as e:
        handle_error(e)

def is_ipv4(ip_str):
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
    handle_error(err_message)
    
def handle_error(err_message):
    print(f"Error: {err_message}")
    cleanup(False)
    
def display_message(message):
    print(f'Received response\n{message}')
    cleanup(True)

def cleanup(success):
    if client:
        client.close()
    if success:
        exit(0)
    exit(1)

if __name__ == "__main__":
    main()