from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import hashlib

def generate_aes_key():
    return get_random_bytes(32)

def encrypt_file_aes(file_path, key):
    with open(file_path,'rb') as f:
        plaintext=f.read()
    
    cipher = AES.new(key, AES.MODE_GCM)
    
    ciphertext, tag=cipher.encrypt_and_digest(plaintext)
    
    with open(file_path +".enc",'wb') as f:
        for x in [cipher.nonce, tag, ciphertext]:
            f.write(x)