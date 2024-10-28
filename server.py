import socket
from des import des_cfb_decrypt, key_generator

def start_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('0.0.0.0', 12345)) 
    server_socket.listen(1)
    print("Server is listening for connections...")

    conn, addr = server_socket.accept()
    print(f"Connected by {addr}")

    encrypted_data = conn.recv(1024)
    
    key_hex = conn.recv(16).decode()  
    iv_hex = conn.recv(16).decode()   

    key = bytes.fromhex(key_hex)
    key_bin = ''.join(f'{byte:08b}' for byte in key)
    
    subkeys = key_generator(key_bin)
    iv = bytes.fromhex(iv_hex)

    decrypted_message = des_cfb_decrypt(encrypted_data, subkeys, iv)
    print("Decrypted message:", decrypted_message.decode())

    conn.close()
    server_socket.close()

if __name__ == "__main__":
    start_server()
