import socket
import struct
from des import des_cfb_encrypt, des_cfb_decrypt, generate_iv, generate_key

def get_server_key(pka_host='localhost', pka_port=5000):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.connect((pka_host, pka_port))
        sock.send(b'\x02')
        
        n_len = struct.unpack('!I', sock.recv(4))[0]
        if n_len == 0:
            return None
            
        n = int.from_bytes(sock.recv(n_len), 'big')
        
        e = struct.unpack('!I', sock.recv(4))[0]
        
        return (n, e)
    finally:
        sock.close()

def send_message(message, server_host='localhost', server_port=5010):
    try:
        public_key = get_server_key()
        if not public_key:
            print("Failed to get server's public key")
            return
        n, e = public_key
        print("Got server's public key from PKA")

        des_key, subkeys = generate_key()
        iv = generate_iv()

        des_key_int = int.from_bytes(des_key, 'big')
        encrypted_des_key = pow(des_key_int, e, n)
        encrypted_des_key_bytes = encrypted_des_key.to_bytes((encrypted_des_key.bit_length() + 7) // 8, 'big')

        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.connect((server_host, server_port))

        client.send(encrypted_des_key_bytes)
        print("Sent encrypted DES key")

        client.send(struct.pack('!I', len(iv)))
        client.send(iv)
        print("Sent IV")

        encrypted_msg = des_cfb_encrypt(message.encode(), subkeys, iv)
        client.send(struct.pack('!I', len(encrypted_msg)))
        client.send(encrypted_msg)
        print("Sent encrypted message")

        resp_len = struct.unpack('!I', client.recv(4))[0]
        encrypted_response = client.recv(resp_len)
        decrypted_response = des_cfb_decrypt(encrypted_response, subkeys, iv)
        print(f"Server response: {decrypted_response.decode()}")

        client.close()

    except Exception as e:
        print(f"Error: {e}")
        print(f"Error details:", end=" ")
        import traceback
        traceback.print_exc()

def main():
    while True:
        message = input("Enter message (or 'quit' to exit): ")
        if message.lower() == 'quit':
            break
        send_message(message)

if __name__ == "__main__":
    main()
