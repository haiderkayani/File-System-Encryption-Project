from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend

def generate_rsa_keys():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
    public_key = private_key.public_key()
    return private_key, public_key

def serialize_keys(private_key, public_key):
    pem_private_key = private_key.private_bytes( encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.TraditionalOpenSSL, 
        encryption_algorithm=serialization.NoEncryption())
    pem_public_key = public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)
    return pem_private_key, pem_public_key

def encrypt_aes_key_with_rsa(aes_key, public_key):
    encrypted_key = public_key.encrypt(aes_key, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
    return encrypted_key

def decrypt_aes_key_with_rsa(encrypted_key, private_key):
    decrypted_key = private_key.decrypt(encrypted_key, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
    return decrypted_key
