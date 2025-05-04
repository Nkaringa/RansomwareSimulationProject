# decrypt.py
# This script simulates the decryption of files encrypted by encrypt.py
# using AES-256-CBC. It loads the key from key.txt and removes the .enc extension.

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.backends import default_backend
import os
import base64

def load_key():
    """Loads the AES key from key.txt"""
    with open("key.txt", "rb") as key_file:
        lines = key_file.readlines()
        salt = lines[0].strip()  # Read the salt (not directly used in decryption here)
        key = lines[1].strip()    # Read the base64 encoded key
        return base64.urlsafe_b64decode(key)  # Decode the key from base64

def decrypt_file(file_path, key):
    """Decrypts a file using AES-256-CBC."""
    with open(file_path, "rb") as f:
        iv = f.read(16)  # Read the initial 16 bytes as the Initialization Vector (IV)
        encrypted_data = f.read()  # Read the rest of the data as the encrypted content

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    decrypted_padded = decryptor.update(encrypted_data) + decryptor.finalize()

    unpadder = PKCS7(128).unpadder()  # Create an unpadder for PKCS#7 with 128-bit block size
    decrypted_data = unpadder.update(decrypted_padded) + unpadder.finalize()

    decrypted_file_path = file_path.replace(".enc", "")  # Remove the ".enc" extension from the filename
    with open(decrypted_file_path, "wb") as f:
        f.write(decrypted_data)  # Write the decrypted data to the new file

    os.remove(file_path)  # Delete the encrypted file

def decrypt_directory(directory, key):
    """Recursively decrypts all .enc files in a directory."""
    for root, _, files in os.walk(directory):
        for file in files:
            if file.endswith(".enc"):  # Only process files with the ".enc" extension
                file_path = os.path.join(root, file)
                decrypt_file(file_path, key)

# Load key
key = load_key()

# Decrypt all files in "critical"
decrypt_directory("critical", key)
print("Decryption completed successfully.")