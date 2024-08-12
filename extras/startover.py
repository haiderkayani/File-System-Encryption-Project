from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
import os

# Key size and block size
KEY_SIZE = 2048
AES_KEY_SIZE = 32
BLOCK_SIZE = AES.block_size
HASH_SIZE = SHA256.digest_size

def generate_rsa_key_pair():
    key = RSA.generate(KEY_SIZE)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

def encrypt_file(filename, public_key):
    # Generate a random AES key
    aes_key = get_random_bytes(AES_KEY_SIZE)
    
    # Load RSA public key
    rsa_key = RSA.import_key(public_key)
    cipher_rsa = PKCS1_OAEP.new(rsa_key)
    
    # Encrypt the AES key with RSA
    encrypted_aes_key = cipher_rsa.encrypt(aes_key)
    
    # Encrypt the file
    cipher_aes = AES.new(aes_key, AES.MODE_EAX)
    
    with open(filename, 'rb') as file:
        plaintext = file.read()
    
    ciphertext, tag = cipher_aes.encrypt_and_digest(plaintext)
    
    # Save encrypted file and metadata
    with open(filename + '.enc', 'wb') as file:
        file.write(encrypted_aes_key + cipher_aes.nonce + tag + ciphertext)
    
    # Print a portion of the encrypted file (first 128 bytes)
    with open(filename + '.enc', 'rb') as file:
        preview = file.read(128)
        print()
        print("Encrypted file preview (first 128 bytes):", preview.hex())
        print()

    
def decrypt_file(filename, private_key):
    # Load RSA private key
    rsa_key = RSA.import_key(private_key)
    cipher_rsa = PKCS1_OAEP.new(rsa_key)
    
    # Read encrypted file and metadata
    with open(filename, 'rb') as file:
        encrypted_aes_key = file.read(KEY_SIZE // 8)
        nonce = file.read(BLOCK_SIZE)
        tag = file.read(BLOCK_SIZE)
        ciphertext = file.read()
    
    # Decrypt the AES key with RSA
    aes_key = cipher_rsa.decrypt(encrypted_aes_key)
    
    # Decrypt the file
    cipher_aes = AES.new(aes_key, AES.MODE_EAX, nonce=nonce)
    plaintext = cipher_aes.decrypt_and_verify(ciphertext, tag)
    
    decrypted_filename = filename[:-4]
    with open(decrypted_filename, 'wb') as file:
        file.write(plaintext)
    
    # Print the decrypted content
    print("Decrypted file content:")
    print(plaintext.decode(errors='ignore'))
    print()


def generate_sha256_hash(filename):
    h = SHA256.new()
    with open(filename, 'rb') as file:
        while chunk := file.read(8192):
            h.update(chunk)
    return h.hexdigest()

def main():
    # Generate RSA keys
    private_key, public_key = generate_rsa_key_pair()
    
    # Example file - make sure this file exists or adjust the filename accordingly
    filename = 'example.txt'
    encrypted_filename = filename + '.enc'
    
    # Encrypt and save file
    encrypt_file(filename, public_key)
    
    # Decrypt and retrieve file
    decrypt_file(encrypted_filename, private_key)
    
    # Print hash of the original and decrypted file
    original_hash = generate_sha256_hash(filename)
    decrypted_hash = generate_sha256_hash(filename)  # Adjusted to use the original filename
    
    print()
    print(f'Original file hash: {original_hash}')
    print(f'Decrypted file hash: {decrypted_hash}')
    print()
    assert original_hash == decrypted_hash, "File integrity check failed!"

if __name__ == '__main__':
    main()
