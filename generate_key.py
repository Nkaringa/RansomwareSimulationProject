# generate_key.py
# This script generates a strong AES-256 key and saves it to key.txt
# along with a randomly generated salt.

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import os
import base64

def generate_key(password: str, salt: bytes):
    """Generates a 256-bit AES key using PBKDF2HMAC."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),  # Use SHA256 as the hash algorithm
        length=32,                   # Generate a 32-byte key (256 bits)
        salt=salt,                   # Use the provided salt
        iterations=100000,           # Number of iterations for key derivation (higher is more secure)
        backend=default_backend()    # Use the default cryptographic backend
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))  # Derive the key and encode it in base64

password = "strong_password"  # The master password used to derive the key
salt = os.urandom(16)         # Generate a random 16-byte salt
key = generate_key(password, salt)  # Generate the key

# Save the key securely
with open("key.txt", "wb") as key_file:
    key_file.write(salt + b"\n" + key)  # Write the salt on the first line and the key on the second

print("Key generated and saved in key.txt")