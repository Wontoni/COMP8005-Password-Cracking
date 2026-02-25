import string

def index_to_password(global_index, search_space):
    N = len(search_space)

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
        chars.append(search_space[global_index % N])
        global_index //= N

    return "".join(reversed(chars))

LEGAL_CHARACTERS = (string.ascii_lowercase +
                    string.ascii_uppercase +
                    string.digits +
                    "@#%^&*()_+-=.,:;?")

for i in range(10):
    print(i)
    print(index_to_password(i, LEGAL_CHARACTERS))