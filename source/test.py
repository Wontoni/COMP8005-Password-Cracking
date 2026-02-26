import string
import time
def index_to_password(global_index, search_space):
    N = len(search_space)

    length = 1
    block_size = N

    while global_index >= block_size:
        global_index -= block_size
        length += 1
        block_size = N ** length

    chars = []
    for _ in range(length):
        chars.append(search_space[global_index % N])
        global_index //= N

    return "".join(reversed(chars))

LEGAL_CHARACTERS = (string.ascii_lowercase +
                    string.ascii_uppercase +
                    string.digits +
                    "@#%^&*()_+-=.,:;?")

# for i in range(1000000, 1000200):
    # print(index_to_password(i, LEGAL_CHARACTERS))

