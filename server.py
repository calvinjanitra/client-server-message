import socket
from des import des_cfb_decrypt, key_generator

def start_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('0.0.0.0', 5008))
    server_socket.listen(1)
    print("Server is listening for connections...")

    while True:
        conn, addr = server_socket.accept()
        print(f"Connected by {addr}")

        try:
            encrypted_data = conn.recv(1024)
            if not encrypted_data:
                print("Failed to receive encrypted data.")
                continue

            key_hex = conn.recv(1024).decode()
            if not key_hex:
                print("Failed to receive key.")
                continue

            iv_hex = conn.recv(1024).decode()
            if not iv_hex:
                print("Failed to receive IV.")
                continue

            key = bytes.fromhex(key_hex)
            key_bin = ''.join(f'{byte:08b}' for byte in key)
            subkeys = key_generator(key_bin)
            iv = bytes.fromhex(iv_hex)

            print("Key:", key)
            print("IV:", iv)
            print("Chipertext:", encrypted_data)

            decrypted_message = des_cfb_decrypt(encrypted_data, subkeys, iv)
            print("Decrypted message:", decrypted_message.decode())

        finally:
            conn.close()

if __name__ == "__main__":
    start_server()

