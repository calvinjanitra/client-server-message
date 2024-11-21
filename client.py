import socket
from des import des_cfb_encrypt, des_cfb_decrypt, generate_iv, generate_key
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import os

def load_server_public_key(file_path="server_public_key.pem"):
    """Load the server's public RSA key from a PEM file."""
    try:
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"Error: '{file_path}' file not found.")
        with open(file_path, "rb") as f:
            public_key = RSA.import_key(f.read())
        print("Server public key successfully loaded.")
        return public_key
    except FileNotFoundError as e:
        print(e)
        print("Please ensure the server's public key is available.")
        exit(1)
    except Exception as e:
        print(f"Error loading server's public key: {e}")
        exit(1)

def send_message_to_server(message, server_address=('192.168.188.10', 5010)):
    des_key, subkeys = generate_key()
    iv = generate_iv()
    
    public_key = load_server_public_key()
    cipher_rsa = PKCS1_OAEP.new(public_key)

    encrypted_des_key = cipher_rsa.encrypt(des_key)

    ciphertext = des_cfb_encrypt(message.encode(), subkeys, iv)

    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        client_socket.connect(server_address)
        print(f"Connected to server at {server_address}")

        client_socket.sendall(encrypted_des_key)
        print("Encrypted DES Key Sent.")

        iv_length = len(iv)
        client_socket.sendall(iv_length.to_bytes(4, 'big')) 
        client_socket.sendall(iv)
        print(f"IV Sent (hex): {iv.hex()}")

        client_socket.sendall(ciphertext)
        print(f"Ciphertext Sent (hex): {ciphertext.hex()}")

        print("Waiting for server response...")
        encrypted_response = client_socket.recv(1024)
        if encrypted_response:
            decrypted_response = des_cfb_decrypt(encrypted_response, subkeys, iv)
            print("Decrypted response from server:", decrypted_response.decode())
        else:
            print("No response received from the server.")

    except ConnectionRefusedError:
        print(f"Connection refused. Make sure the server is running at {server_address}")
    except socket.error as e:
        print(f"Socket error: {e}")
    except Exception as e:
        print(f"Error in send_message_to_server: {e}")
    finally:
        client_socket.close()

def main():
    SERVER_IP = '192.168.188.10' 
    SERVER_PORT = 5010         
    
    while True:
        message = input("Enter the message to send to the server (or 'quit' to exit): ")
        if message.lower() == 'quit':
            break
        
        send_message_to_server(message, (SERVER_IP, SERVER_PORT))

if __name__ == "__main__":
    main()
