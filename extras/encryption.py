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
            
def decrypt_file_aes(file_path, key):
    with open(file_path,'rb') as f:
        nonce, tag, ciphertext=[f.read(x) for x in (16, 16, -1)]
    cipher=AES.new(key, AES.MODE_GCM, nonce=nonce)
    plaintext=cipher.decrypt_and_verify(ciphertext, tag)
    with open(file_path[:-4],'wb') as f:
        f.write(plaintext)
        
def decrypt_file_aes(filename, aes_key):
    with open(filename, 'rb') as f:
        nonce = f.read(16)  # Read the nonce
        encrypted_data = f.read()
    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(nonce))
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()
    return decrypted_data

def hash_file_sha256(file_path):
    sha256=hashlib.sha256()
    with open(file_path,'rb') as f:
        while chunk:=f.read(8192):
            sha256.update(chunk)
    return sha256.hexdigest()