import socket
import re
import select
import queue
import struct
import pickle


connection = None
server = None
server_host = "::"
server_port = 8080
inputs = []
outputs = []
message_queues = {}

def main():
    create_socket()
    listen_connections()
    try:
        while True:
            accept_connection()
    except Exception as e:
        handle_error("Failed to receive data from client")

def create_socket():
    try:
        global server, inputs
        addr = (server_host, server_port)
        if socket.has_dualstack_ipv6():
            server = socket.create_server(addr, family=socket.AF_INET6, dualstack_ipv6=True)
            print("Server running on dual-stack mode (IPv4 and IPv6).")
        else:
            server = socket.create_server(addr)
            print("Server running on default mode.")
        inputs = [server]
        server.setblocking(0)
            
    except Exception as e:
        handle_error("Failed to create socket server")
        exit(1)
        
def listen_connections():
    try:
        server.listen(5)
        print(f'Server is listening on port {server_port} for incoming connections...')
    except Exception as e:
        handle_error("Failed to listen to connections")
        exit(1)

def accept_connection():
    try:
        while inputs:
            readable, writable, exceptional = select.select(inputs, outputs, inputs)

            for s in readable:
                if s is server:
                    connection, client_addr = s.accept()
                    print('Connection Received: ', client_addr)
                    connection.setblocking(1)
                    inputs.append(connection)

                    message_queues[connection] = queue.Queue()
                else:
                    data_size = struct.unpack(">I", s.recv(4))[0]
                    receieved_data = b""
                    remaining_data_size = data_size

                    if data_size:
                        while remaining_data_size != 0:
                            receieved_data += s.recv(remaining_data_size)
                            remaining_data_size = data_size - len(receieved_data)
                        data = pickle.loads(receieved_data)
                        inputs.remove(s)
                        message_queues[s].put(data)
                        if s not in outputs:
                            outputs.append(s)
                    else:
                        if s in outputs:
                            outputs.remove(s)
                        inputs.remove(s)
                        s.close()

                        del message_queues[s]

            for s in writable:
                try:
                    message_data = message_queues[s].get_nowait()
                except queue.Empty:
                    outputs.remove(s)
                else:
                    next_msg = handle_data(message_data)
                    s.sendall(struct.pack(">I", len(next_msg)))
                    s.sendall(next_msg)
            
            for s in exceptional:
                inputs.remove(s)
                if s in outputs:
                    outputs.remove(s)
                s.close()

                del message_queues[s]
    except Exception as e:
        handle_error(e)
        exit(1)

def handle_data(data):
    words = get_words(data)
    word_count = get_word_count(words)
    char_count = get_char_count(words)
    char_freq = get_char_freq(words)
    sorted_chars = sort_dict(char_freq)
    response = format_response(word_count, char_count, sorted_chars)
    response = pickle.dumps(response)
    return response

def get_words(word_string):
    formatted_string = remove_whitespace(word_string)
    words = formatted_string.split(" ")
    words = [x for x in words if x]
    return words

def get_word_count(words):
    return len(words)

def remove_whitespace(word_string):
    try:
        return re.sub(' +', ' ', word_string)
    except Exception as e:
        handle_error("Failed to remove whitespaces in data")
        exit(1)

def get_char_count(words):
    count = 0
    for word in words:
        count += len(word)
    return count

def get_char_freq(words):
    char_dict = {}
    words = [word.lower() for word in words]
    words = "".join(words)
    for c in words:
        if c in char_dict:
            char_dict[c] += 1
        else:
            char_dict[c] = 1
    return char_dict

def format_response(word_count, char_count, char_freq):
    response = "Word Count: %d\nCharacter Count: %d\nCharacter Frequencies:"%(word_count, char_count)

    for key, value in char_freq.items():
        response += "\n%s: %d"%(key, value)
    response += "\n"
    return response

def sort_dict(char_freq):
    keys = list(char_freq.keys())
    keys.sort()
    return {i: char_freq[i] for i in keys}

def handle_error(err_message):
    print(f"Error: {err_message}")
    cleanup(False)
    
def cleanup(success):
    if server:
        server.close()
    if success:
        exit(0)
    exit(1)

main()