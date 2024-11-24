import random
import math

def is_prime(n, k=5):
    """Miller-Rabin primality test"""
    if n == 2 or n == 3:
        return True
    if n < 2 or n % 2 == 0:
        return False

    # n-1 as 2^r * d
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2

    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True

def generate_prime(bits):
    while True:
        n = random.getrandbits(bits)
        n |= (1 << bits - 1) | 1 
        if is_prime(n):
            return n

def mod_inverse(e, phi):
    """Extended Euclidean Algorithm"""
    def extended_gcd(a, b):
        if a == 0:
            return b, 0, 1
        gcd, x1, y1 = extended_gcd(b % a, a)
        x = y1 - (b // a) * x1
        y = x1
        return gcd, x, y

    _, x, _ = extended_gcd(e, phi)
    return x % phi

def generate_keypair(bits=2048):
    p = generate_prime(bits // 2)
    q = generate_prime(bits // 2)
    
    n = p * q
    phi = (p - 1) * (q - 1)
    
    e = 65537 
    
    d = mod_inverse(e, phi)
    
    # Public key: (n, e)
    # Private key: (n, d)
    return ((n, e), (n, d))

def encrypt(message, public_key):
    n, e = public_key
    m = int.from_bytes(message, 'big')
    c = pow(m, e, n)
    return c

def decrypt(ciphertext, private_key):
    n, d = private_key
    m = pow(ciphertext, d, n)
    return m.to_bytes((m.bit_length() + 7) // 8, 'big')

if __name__ == "__main__":
    # public_key, private_key = generate_keypair(bits=1024) 
    # print(f"Public Key (n, e): {public_key}")
    # print(f"Private Key (n, d): {private_key}")

    # message = b"Tes RSA"
    # print(f"\nOriginal message: {message}")
    
    # encrypted = encrypt(message, public_key)
    # print(f"Encrypted: {encrypted}")
    
    # decrypted = decrypt(encrypted, private_key)
    # print(f"Decrypted: {decrypted}")