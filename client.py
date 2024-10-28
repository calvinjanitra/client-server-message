import socket
from des import generate_iv, generate_key, des_cfb_encrypt

def send_message(message):
    key, subkeys = generate_key()
    iv = generate_iv()

    ciphertext = des_cfb_encrypt(message.encode(), subkeys, iv)

    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(('172.20.10.2', 12345))  # Connect to the specified IP address and port

    client_socket.sendall(ciphertext)
    client_socket.sendall(key.hex().encode())  
    client_socket.sendall(iv.hex().encode())  

    client_socket.close()

if __name__ == "__main__":
    main()

