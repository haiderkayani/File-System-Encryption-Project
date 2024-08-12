from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
import os

def generate_aes_key():
    return os.urandom(32)  # AES-256 key

def encrypt_aes_key_with_rsa(aes_key, public_key):
    return public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def decrypt_aes_key_with_rsa(encrypted_aes_key, private_key):
    return private_key.decrypt(
        encrypted_aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def encrypt_file_aes(filename, aes_key):
    nonce = os.urandom(16)
    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(nonce))
    encryptor = cipher.encryptor()
    
    with open(filename, 'rb') as f:
        data = f.read()
    
    encrypted_data = encryptor.update(data) + encryptor.finalize()
    
    with open(f"{filename}.enc", 'wb') as f:
        f.write(nonce + encrypted_data)

def decrypt_file_aes(filename, aes_key):
    with open(filename, 'rb') as f:
        nonce = f.read(16)  # Read the nonce
        encrypted_data = f.read()
    
    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(nonce))
    decryptor = cipher.decryptor()
    
    decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()
    return decrypted_data

def generate_rsa_keys():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    return private_key, public_key

def serialize_keys(private_key, public_key):
    pem_private_key = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    pem_public_key = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return pem_private_key, pem_public_key

def main():
    # Generate RSA keys
    rsa_private_key, rsa_public_key = generate_rsa_keys()
    
    # Encrypt the file
    aes_key = generate_aes_key()
    encrypted_aes_key = encrypt_aes_key_with_rsa(aes_key, rsa_public_key)
    
    print(f"Original AES key: {aes_key.hex()}")
    print(f"Encrypted AES key: {encrypted_aes_key.hex()}")

    # Encrypt file content
    encrypt_file_aes('sensitive_data.txt', aes_key)
    print("File encrypted as 'sensitive_data.txt.enc'")

    # Decrypt the AES key
    try:
        decrypted_aes_key = decrypt_aes_key_with_rsa(encrypted_aes_key, rsa_private_key)
        print(f"Decrypted AES key: {decrypted_aes_key.hex()}")
    except Exception as e:
        print(f"Decryption failed: {e}")
        return

    if decrypted_aes_key is None:
        print("Decryption failed, exiting...")
        return

    # Decrypt file content
    try:
        decrypted_data = decrypt_file_aes('sensitive_data.txt.enc', decrypted_aes_key)
        # Write the decrypted data to a new file
        with open('decrypted_data.txt', 'wb') as f:
            f.write(decrypted_data)
        print("File decrypted and saved as 'decrypted_data.txt'")
    except Exception as e:
        print(f"Decryption failed: {e}")

if __name__ == "__main__":
    main()

