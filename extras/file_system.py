from key_management import generate_rsa_keys, encrypt_aes_key_with_rsa, decrypt_aes_key_with_rsa
from encryption import generate_aes_key, encrypt_file_aes, decrypt_file_aes, hash_file_sha256
import os

class EncryptedFileSystem:
    def __init__(self, rsa_private_key, rsa_public_key):
        self.rsa_private_key = rsa_private_key
        self.rsa_public_key = rsa_public_key

    def create_file(self, file_path, data):
        aes_key = generate_aes_key()
        print(f"Generated AES key: {aes_key.hex()}")  # Debug print
        encrypted_aes_key = encrypt_aes_key_with_rsa(aes_key, self.rsa_public_key)
        print(f"Encrypted AES key: {encrypted_aes_key.hex()}")  # Debug print
        with open(file_path, 'wb') as f:
            f.write(encrypted_aes_key)
        encrypt_file_aes(file_path, aes_key)
        file_hash = hash_file_sha256(file_path)
        print(f"File created with hash: {file_hash}")


    def read_file(self, file_path):
        with open(file_path, 'rb') as f:
            encrypted_aes_key = f.read(256)  # Read the first 256 bytes (assuming RSA-2048)
            print(f"Encrypted AES key: {encrypted_aes_key.hex()}")  # Debug print
        try:
            aes_key = decrypt_aes_key_with_rsa(encrypted_aes_key, self.rsa_private_key)
            print(f"Decrypted AES key: {aes_key.hex()}")  # Debug print
        except ValueError as e:
            print("Decryption failed:", e)
            return None
        decrypt_file_aes(file_path, aes_key)
        with open(file_path[:-4], 'rb') as f:
            data = f.read()
        return data

    def delete_file(self, file_path):
        os.remove(file_path)
        if os.path.exists(file_path[:-4]):  
            os.remove(file_path[:-4])

    def write_to_file(self, file_path, data):
        self.create_file(file_path, data)

