"""
This is implementation of ElGamal encryption and decryption algorithm.
"""

def generate_keypair(p, g, x):
    """
    Generate a pair of public and private keys for ElGamal encryption.
    
    Parameters:
        p: A prime number, which is the modulus of the finite field.
        g: A primitive root of p.
        x: A random integer in the range [1, p-2].
    
    Returns:
        A tuple (public_key, private_key), where:
            public_key is a tuple (p, g, h), and
            private_key is an integer x.
    """
    h = pow(g, x, p)
    public_key = (p, g, h)
    return public_key, x

def encrypt(public_key, m):
    """
    Encrypt a message using ElGamal encryption.
    
    Parameters:
        public_key: A tuple (p, g, h).
        m: An integer representing the message to be encrypted.
    
    Returns:
        A tuple (c1, c2), which is the ciphertext.
    """
    p, g, h = public_key
    y = randint(1, p-2)
    c1 = pow(g, y, p)
    c2 = (m * pow(h, y, p)) % p
    return c1, c2

def decrypt(public_key, private_key, ciphertext):
    """
    Decrypt a ciphertext using ElGamal decryption.
    
    Parameters:
        public_key: A tuple (p, g, h).
        private_key: An integer x.
        ciphertext: A tuple (c1, c2).
    
    Returns:
        An integer representing the decrypted message.
    """
    p, g, h = public_key
    c1, c2 = ciphertext
    s = pow(c1, private_key, p)
    m = (c2 * pow(s, -1, p)) % p
    return m

if __name__ == '__main__':
    from random import randint
    
    # Generate a pair of keys
    p = 2579
    g = 2
    x = 765
    public_key, private_key = generate_keypair(p, g, x)
    print(f"Public key: {public_key}")
    print(f"Private key: {private_key}")
    
    # Encrypt a message
    m = 1299
    ciphertext = encrypt(public_key, m)
    print(f"Ciphertext: {ciphertext}")
    
    # Decrypt the ciphertext
    decrypted_message = decrypt(public_key, private_key, ciphertext)
    print(f"Decrypted message: {decrypted_message}")
    
    assert m == decrypted_message, "Decryption failed"

