import socket
import os

E = [32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9,
     8, 9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17,
     16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25,
     24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1]

S_BOXES = [
    [[14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
     [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
     [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
     [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]],

    [[15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
     [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
     [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
     [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]],

    [[10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
     [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
     [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
     [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]],

    [[7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
     [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
     [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
     [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]],

    [[2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
     [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
     [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
     [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]],

    [[12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
     [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
     [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
     [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]],

    [[4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
     [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
     [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
     [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]],

    [[13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
     [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
     [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
     [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]]]

P = [16, 7, 20, 21, 29, 12, 28, 17,
     1, 15, 23, 26, 5, 18, 31, 10,
     2, 8, 24, 14, 32, 27, 3, 9,
     19, 13, 30, 6, 22, 11, 4, 25]

def key_generator(key):
    subkeys = []
    for i in range(16):
        subkey = key[i:i+48]  
        if len(subkey) < 48:
            subkey = subkey.zfill(48)
        subkeys.append(subkey)
    return [bytearray(int(subkey[j:j+8], 2) for j in range(0, 48, 8)) for subkey in subkeys]

def generate_key():
    key = os.urandom(8)
    key_bin = ''.join(f'{byte:08b}' for byte in key)
    subkeys = key_generator(key_bin)
    return key, subkeys

def generate_iv():
    return os.urandom(8)

def feistel_function(right, subkey):
    expanded_right = bytearray(6)
    
    # Expand the right block
    for i in range(48):
        bit = (right[(E[i] - 1) // 8] >> (7 - ((E[i] - 1) % 8))) & 1
        expanded_right[i // 8] |= bit << (7 - (i % 8))

    # XOR with the subkey
    for i in range(6):
        expanded_right[i] ^= subkey[i]

    substituted = bytearray(4)
    for i in range(8):
        segment = expanded_right[i * 6 // 8] >> (7 - (i * 6 % 8)) & 0x3F
        row = ((segment & 0x20) >> 4) | (segment & 0x01)
        col = (segment >> 1) & 0x0F
        substituted[i // 2] |= S_BOXES[i][row][col] << (4 * (1 - (i % 2)))

    permuted = bytearray(4)
    for i in range(32):
        bit = (substituted[(P[i] - 1) // 8] >> (7 - ((P[i] - 1) % 8))) & 1
        permuted[i // 8] |= bit << (7 - (i % 8))

    return permuted

def des_feistel(block, subkeys):
    if len(block) != 8:
        raise ValueError(f"Block length is {len(block)} instead of 8.")

    left, right = block[:4], block[4:]
    for subkey in subkeys:
        temp = right
        right = bytearray(left)

        f_result = feistel_function(temp, subkey)
        if f_result is None:
            raise ValueError("Feistel function returned None")
        
        for i in range(4):
            right[i] ^= f_result[i]
        left = temp

    return right + left


def des_cfb_encrypt(plaintext, subkeys, iv):
    ciphertext = bytearray()
    current_block = iv

    for i in range(0, len(plaintext), 8):
        block = plaintext[i:i + 8].ljust(8, b'\0')
        current_block = des_feistel(current_block, subkeys)
        ciphertext.extend(bytes(b ^ c for b, c in zip(current_block, block)))
    return bytes(ciphertext)

def des_cfb_decrypt(ciphertext, subkeys, iv):
    plaintext = bytearray()
    current_block = iv

    for i in range(0, len(ciphertext), 8):
        block = ciphertext[i:i + 8]
        current_block = des_feistel(current_block, subkeys)
        
        plaintext.extend(bytes(b ^ c for b, c in zip(current_block, block)))
    return bytes(plaintext).rstrip(b'\0')

# Server function to receive and decrypt messages
def start_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('0.0.0.0', 12345))  # Bind to all available network interfaces
    server_socket.listen(1)
    print("Server is listening for connections...")

    conn, addr = server_socket.accept()
    print(f"Connected by {addr}")

    # Receive encrypted message, key, and IV
    encrypted_data = conn.recv(1024)
    key_hex = conn.recv(16).decode()
    iv_hex = conn.recv(16).decode()

    # Convert received hex key and IV to bytes and generate subkeys
    key = bytes.fromhex(key_hex)
    key_bin = ''.join(f'{byte:08b}' for byte in key)
    subkeys = key_generator(key_bin)
    iv = bytes.fromhex(iv_hex)

    # Decrypt the message
    decrypted_message = des_cfb_decrypt(encrypted_data, subkeys, iv)
    print("Decrypted message:", decrypted_message.decode('utf-8', 'ignore'))

    conn.close()
    server_socket.close()


# Client function to encrypt and send messages
def send_message(message):
    # Generate key, IV, and subkeys for DES encryption
    key, subkeys = generate_key()
    iv = generate_iv()

    # Encrypt the message
    ciphertext = des_cfb_encrypt(message.encode(), subkeys, iv)

    # Setup the client socket
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(('172.20.10.2', 12345))  # Connect to the specified IP address and port

    # Send encrypted message, key, and IV to the server
    client_socket.sendall(ciphertext)
    client_socket.sendall(key.hex().encode())  # Send key in hex format
    client_socket.sendall(iv.hex().encode())   # Send IV in hex format

    client_socket.close()


def main():
    mode = input("Select mode (1 for Server, 2 for Client): ")
    if mode == '1':
        start_server()
    elif mode == '2':
        message = input("Enter the message to send: ")
        send_message(message)
    else:
        print("Invalid mode selected. Choose 1 or 2.")

if __name__ == "__main__":
    main()

