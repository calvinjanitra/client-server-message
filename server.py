import socket
import struct
from des import des_cfb_decrypt, des_cfb_encrypt, key_generator
from rsa_utils import generate_keypair

def register_with_pka(public_key, pka_host='localhost', pka_port=5000):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.connect((pka_host, pka_port))
        n, e = public_key
        sock.send(b'\x01')
        
        n_bytes = n.to_bytes((n.bit_length() + 7) // 8, 'big')
        sock.send(struct.pack('!I', len(n_bytes)))
        sock.send(n_bytes)
        
        sock.send(struct.pack('!I', e))

        return sock.recv(1) == b'\x01'
    finally:
        sock.close()

def receive_exact(sock, n):
    data = b''
    while len(data) < n:
        packet = sock.recv(n - len(data))
        if not packet:
            return None
        data += packet
    return data

def start_server(port=5010):
    public_key, private_key = generate_keypair(bits=1024)
    # print("Generated RSA keys")
    
    if not register_with_pka(public_key):
        print("Failed to register with PKA")
        return

    # print("Public key registered with PKA")
    
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(('0.0.0.0', port))
    server.listen(1)
    print(f"Chat server running on port {port}")

    while True:
        try:
            client, addr = server.accept()
            print(f"Connection from {addr}")

            key_size_bytes = receive_exact(client, 4)
            if not key_size_bytes:
                print("Failed to receive key size")
                continue
            key_size = struct.unpack('!I', key_size_bytes)[0]

            enc_des_key = receive_exact(client, key_size)
            if not enc_des_key:
                print("Failed to receive encrypted DES key")
                continue
            print(f"Received encrypted DES key, length: {len(enc_des_key)}")
            
            iv_len_bytes = receive_exact(client, 4)
            if not iv_len_bytes:
                print("Failed to receive IV length")
                continue
            iv_len = struct.unpack('!I', iv_len_bytes)[0]
            
            iv = receive_exact(client, iv_len)
            if not iv:
                print("Failed to receive IV")
                continue
            print(f"Received IV, length: {iv_len}")
            
            n, d = private_key
            encrypted = int.from_bytes(enc_des_key, 'big')
            decrypted = pow(encrypted, d, n)
            des_key = decrypted.to_bytes((decrypted.bit_length() + 7) // 8, 'big')
            print("Decrypted DES key")
            
            key_bin = ''.join(f'{byte:08b}' for byte in des_key)
            subkeys = key_generator(key_bin)

            msg_len_bytes = receive_exact(client, 4)
            if not msg_len_bytes:
                print("Failed to receive message length")
                continue
            msg_len = struct.unpack('!I', msg_len_bytes)[0]
            
            encrypted_msg = receive_exact(client, msg_len)
            if not encrypted_msg:
                print("Failed to receive encrypted message")
                continue
            
            decrypted_msg = des_cfb_decrypt(encrypted_msg, subkeys, iv)
            print(f"Received message: {decrypted_msg.decode()}")

            response = input("Enter response: ").encode()
            encrypted_response = des_cfb_encrypt(response, subkeys, iv)
            
            client.send(struct.pack('!I', len(encrypted_response)))
            client.send(encrypted_response)
            print("Response sent")
            
            client.close()

        except Exception as e:
            print(f"Error: {e}")
            import traceback
            traceback.print_exc()

if __name__ == "__main__":
    start_server()
