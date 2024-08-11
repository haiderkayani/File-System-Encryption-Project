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

    def read_file(self, file_path):
        with open(file_path, 'rb') as f:
            encrypted_aes_key = f.read(256)  # RSA-encrypted key length

        aes_key = decrypt_aes_key_with_rsa(encrypted_aes_key, self.rsa_private_key)

        # Decrypt the file data
        decrypt_file_aes(file_path, aes_key)

        with open(file_path[:-4], 'rb') as f:
            data = f.read()

        return data

    def delete_file(self, file_path):
        os.remove(file_path)
        if os.path.exists(file_path[:-4]):  # Remove the decrypted file as well
            os.remove(file_path[:-4])

    def write_to_file(self, file_path, data):
        # Overwrite existing file or create new one
        self.create_file(file_path, data)

# Example Usage
if __name__ == "__main__":
    private_key, public_key = generate_rsa_keys()
    efs = EncryptedFileSystem(private_key, public_key)

    # Creating a new encrypted file
    efs.create_file("testfile.txt", b"Sensitive data inside the file.")

    # Reading the encrypted file
    data = efs.read_file("testfile.txt.enc")
    print(f"Decrypted data: {data}")

    # Deleting the file
    efs.delete_file("testfile.txt.enc")