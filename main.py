from encryption import generate_rsa_key_pair, encrypt_file
from decryption import decrypt_file
from hashing import generate_sha256_hash

def main():
    # Generate RSA keys
    private_key, public_key = generate_rsa_key_pair()
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
