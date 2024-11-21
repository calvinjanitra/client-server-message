from Crypto.PublicKey import RSA

def generate_key_pair(bits=2048):
    """Generate a new RSA key pair and save to files."""
    key = RSA.generate(bits)
    
    public_key = key.publickey()
    
    with open("server_private_key.pem", "wb") as f:
        f.write(key.export_key('PEM'))
    print("Private key saved to 'server_private_key.pem'")
    
    with open("server_public_key.pem", "wb") as f:
        f.write(public_key.export_key('PEM'))
    print("Public key saved to 'server_public_key.pem'")

if __name__ == "__main__":
    try:
        generate_key_pair()
        print("RSA key pair generated successfully!")
    except Exception as e:
        print(f"Error generating keys: {e}")