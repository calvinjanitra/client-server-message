import socket
from des import des_cfb_decrypt, des_cfb_encrypt, key_generator

def receive_message_from_client():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
<<<<<<< Updated upstream
    server_socket.bind(('0.0.0.0', 5008))
=======
    server_socket.bind(('0.0.0.0', 5004)) 
>>>>>>> Stashed changes
    server_socket.listen(1)
    print("Server is listening for connections...")

    conn, addr = server_socket.accept()
    print(f"Connected by {addr}")

    try:
        encrypted_data = conn.recv(1024)
        if not encrypted_data:
            print("Failed to receive encrypted data.")
            return None, None, None

        key_hex = conn.recv(1024).decode()
        if not key_hex:
            print("Failed to receive key.")
            return None, None, None

        iv_hex = conn.recv(1024).decode()
        if not iv_hex:
            print("Failed to receive IV.")
            return None, None, None

        key = bytes.fromhex(key_hex)
        key_bin = ''.join(f'{byte:08b}' for byte in key)
        subkeys = key_generator(key_bin)
        iv = bytes.fromhex(iv_hex)

        print("Key:", key)
        print("IV:", iv)
        print("Ciphertext received:", encrypted_data)

        decrypted_message = des_cfb_decrypt(encrypted_data, subkeys, iv)
        print("Decrypted message from client:", decrypted_message.decode())

        return subkeys, iv, addr[0]  
    finally:
        conn.close()

def send_message_to_client(subkeys, iv, client_ip):
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((client_ip, 5009)) 

    message = input("Enter the message to send to client: ")
    encrypted_response = des_cfb_encrypt(message.encode(), subkeys, iv)
    client_socket.sendall(encrypted_response)
    print("Encrypted response sent to client:", encrypted_response)
    
    client_socket.close()

if __name__ == "__main__":

    subkeys, iv, client_ip = receive_message_from_client()
    
    if subkeys and iv and client_ip:
        send_message_to_client(subkeys, iv, client_ip)
