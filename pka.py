# pka.py
import socket
import struct

class PKAServer:
    def __init__(self, port=5000):
        self.port = port
        self.public_key = None

    def start(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind(('0.0.0.0', self.port))
        server.listen(1)
        print(f"PKA Server is running on port {self.port}")

        while True:
            try:
                client, addr = server.accept()
                print(f"Connection from {addr}")
                
                # Read command byte
                command = client.recv(1)[0]  # Read single byte as integer
                print(f"Received command: {command}")

                if command == 1:  # Register
                    # Read n_length (4 bytes)
                    n_length = struct.unpack('!I', client.recv(4))[0]
                    print(f"Reading n of length: {n_length}")
                    
                    # Read n
                    n_bytes = client.recv(n_length)
                    n = int.from_bytes(n_bytes, 'big')
                    
                    # Read e (4 bytes)
                    e = struct.unpack('!I', client.recv(4))[0]
                    
                    self.public_key = (n, e)
                    client.send(b'\x01')  # Success
                    print("Public key registered successfully")
                
                elif command == 2:  # Get
                    if self.public_key:
                        n, e = self.public_key
                        # Convert n to bytes
                        n_bytes = n.to_bytes((n.bit_length() + 7) // 8, 'big')
                        # Send n length and n
                        client.send(struct.pack('!I', len(n_bytes)))
                        client.send(n_bytes)
                        # Send e
                        client.send(struct.pack('!I', e))
                        print("Sent public key to client")
                    else:
                        client.send(struct.pack('!I', 0))  # No key available
                        print("No public key available")
                
                client.close()

            except Exception as e:
                print(f"Error: {e}")
                print(f"Error details:", end=" ")
                import traceback
                traceback.print_exc()

if __name__ == "__main__":
    pka = PKAServer()
    pka.start()