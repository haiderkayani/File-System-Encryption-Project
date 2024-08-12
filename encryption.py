from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes

# Key size and block size
AES_KEY_SIZE = 32
BLOCK_SIZE = AES.block_size
KEY_SIZE = 2048

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
