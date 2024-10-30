import socket
from des import generate_iv, generate_key, des_cfb_encrypt, des_cfb_decrypt
import time

def send_message(message):
    key, subkeys = generate_key()
    iv = generate_iv()

    ciphertext = des_cfb_encrypt(message.encode(), subkeys, iv)

    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(('172.20.10.2', 5008))
    client_socket.sendall(ciphertext)
    print("Encoded Text:", ciphertext)
    client_socket.sendall(key.hex().encode())
    print("Key:", key)
    time.sleep(0.1)
    client_socket.sendall(iv.hex().encode())
    print("IV:", iv)
    time.sleep(0.1)

    client_socket.close()

    return subkeys, iv

def receive_message():
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.bind(('0.0.0.0', 5009))
    client_socket.listen(1)
    print("Client is waiting for response from server...")

    conn, addr = client_socket.accept()
    print(f"Connected by server {addr}")

    try:
        encrypted_response = conn.recv(1024)
        if encrypted_response:
            decrypted_response = des_cfb_decrypt(encrypted_response, subkeys, iv)
            print("Decrypted response from server:", decrypted_response.decode())
    finally:
        conn.close()

if __name__ == "__main__":
    message = input("Enter the message to send: ")
    subkeys, iv = send_message(message)
    receive_message()
