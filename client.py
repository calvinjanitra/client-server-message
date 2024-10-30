import socket
from des import generate_iv, generate_key, des_cfb_encrypt
import time

def send_message(message):
    key, subkeys = generate_key()
    iv = generate_iv()

    ciphertext = des_cfb_encrypt(message.encode(), subkeys, iv)

    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(('172.20.10.2', 5008))
    client_socket.sendall(ciphertext)
    print("Encoded Text : ", ciphertext)
    client_socket.sendall(key.hex().encode())  
    print("Key : ", key)
    time.sleep(0.1)
    client_socket.sendall(iv.hex().encode())  
    print("IV : ", iv)
    time.sleep(0.1)
    client_socket.close()

if __name__ == "__main__":
    message = input("Enter the message to send: ")
    
    send_message(message)

