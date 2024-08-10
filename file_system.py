from key_management import generate_rsa_keys, encrypt_aes_key_with_rsa, decrypt_aes_key_with_rsa
from encryption import generate_aes_key, encrypt_file_aes, decrypt_file_aes, hash_file_sha256
import os

class EncryptedFileSystem:
    def __init__(self, rsa_private_key, rsa_public_key):
        self.rsa_private_key = rsa_private_key
        self.rsa_public_key = rsa_public_key

    def create_file(self, file_path, data):
        aes_key = generate_aes_key()

        # Encrypt the AES key using RSA
        encrypted_aes_key = encrypt_aes_key_with_rsa(aes_key, self.rsa_public_key)

        # Encrypt the file data
        with open(file_path, 'wb') as f:
            f.write(encrypted_aes_key)
        
        encrypt_file_aes(file_path, aes_key)

        # Optionally store a hash for integrity check
        file_hash = hash_file_sha256(file_path)
        print(f"File created with hash: {file_hash}")