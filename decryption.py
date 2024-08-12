from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA

# Key size and block size
BLOCK_SIZE = AES.block_size
KEY_SIZE = 2048

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
