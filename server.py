import os
import socket
from des import des_cfb_decrypt, des_cfb_encrypt, key_generator
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

def load_rsa_keys():
    """
    Load RSA private key from the file 'server_private_key.pem' to be used for decrypting 
    the DES key that was encrypted with the RSA public key.
    """
    with open("server_private_key.pem", "rb") as f:
        private_key = RSA.import_key(f.read())
    return private_key

def handle_client_connection(conn, addr):
    """
    Handle the client connection to receive the encrypted DES key, IV, and data. It decrypts 
    the received data using the DES key, and sends an encrypted response back to the client.
    """
    try:
        encrypted_des_key = conn.recv(256)
        if not encrypted_des_key:
            print("Failed to receive encrypted DES key.")
            return None, None

        print(f"Received encrypted DES key, length: {len(encrypted_des_key)}")

        iv_length_bytes = conn.recv(4)
        iv_length = int.from_bytes(iv_length_bytes, 'big')
        print(f"Expected IV length: {iv_length}")

        iv_data = conn.recv(iv_length)
        if not iv_data or len(iv_data) != iv_length:
            print("Failed to receive complete IV.")
            return None, None
        
        iv = iv_data 
        print(f"Received IV (hex): {iv.hex()}")

        private_key = load_rsa_keys()
        cipher_rsa = PKCS1_OAEP.new(private_key)
        des_key = cipher_rsa.decrypt(encrypted_des_key)
        
        key_bin = ''.join(f'{byte:08b}' for byte in des_key)
        subkeys = key_generator(key_bin)

        encrypted_data = conn.recv(1024)
        if not encrypted_data:
            print("Failed to receive encrypted data.")
            return None, None
        
        decrypted_message = des_cfb_decrypt(encrypted_data, subkeys, iv)
        print("Decrypted message from client:", decrypted_message.decode())

        message = input("Enter response message for client: ")
        
        encrypted_response = des_cfb_encrypt(message.encode(), subkeys, iv)
        
        conn.sendall(encrypted_response)
        print(f"Encrypted response sent to client (hex): {encrypted_response.hex()}")

    except Exception as e:
        print(f"Error handling client connection: {e}")
    finally:
        conn.close()

def run_server(port=5010):
    """
    Initialize the server to listen for incoming connections on the specified port. 
    Accept connections and delegate processing to handle_client_connection.
    """
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        server_socket.bind(('0.0.0.0', port))
        server_socket.listen(1)
        print(f"Server is listening on port {port}...")
        
        while True:
            conn, addr = server_socket.accept()
            print(f"Connected by {addr}")
            handle_client_connection(conn, addr)
            
    except Exception as e:
        print(f"Server error: {e}")
    finally:
        server_socket.close()

if __name__ == "__main__":
    run_server(5010)
