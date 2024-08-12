from file_system import EncryptedFileSystem
from key_management import generate_rsa_keys, serialize_keys, decrypt_aes_key_with_rsa, encrypt_aes_key_with_rsa
from encryption import generate_aes_key, encrypt_file_aes, decrypt_file_aes
def main():
    # # Step 1: Key Generation
    # print("Generating RSA keys...")
    # private_key, public_key = generate_rsa_keys()
    # pem_private_key, pem_public_key = serialize_keys(private_key, public_key)
    # print("Private Key:")
    # print(pem_private_key.decode())
    # print("Public Key:")
    # print(pem_public_key.decode())
    # print("\n")

    # # Initialize the EncryptedFileSystem with the generated keys
    # efs = EncryptedFileSystem(private_key, public_key)

    # # Step 2: File Encryption
    # print("Encrypting the file 'sensitive_data.txt'...")
    # efs.create_file("sensitive_data.txt", b"Sensitive Information: User passwords, credit card numbers, etc.")
    # print("File encrypted as 'sensitive_data.txt.enc'")
    # print("\n")

    # # Step 3: File Decryption
    # print("Decrypting the file 'sensitive_data.txt.enc'...")
    # data = efs.read_file("sensitive_data.txt.enc")
    # print(f"Decrypted data: {data.decode()}")
    # print("\n")

    # # Step 4: File Integrity Check
    # print("Calculating SHA-256 hash of the encrypted file...")
    # file_hash = efs.hash_file_sha256("sensitive_data.txt.enc")
    # print(f"SHA-256 Hash: {file_hash}")
    # print("\n")

    # # Step 5: File Deletion
    # print("Deleting the encrypted file 'sensitive_data.txt.enc'...")
    # efs.delete_file("sensitive_data.txt.enc")
    # print("File deleted.")
    
    # Generate RSA keys
    rsa_private_key, rsa_public_key = generate_rsa_keys()

    # Encrypt the file
    aes_key = generate_aes_key()
    encrypted_aes_key = encrypt_aes_key_with_rsa(aes_key, rsa_public_key)
    
    # Debugging output
    print(f"Original AES key: {aes_key.hex()}")
    print(f"Encrypted AES key: {encrypted_aes_key.hex()}")

    # Encrypt file content
    encrypt_file_aes('sensitive_data.txt', aes_key)
    print("File encrypted as 'sensitive_data.txt.enc'")

    # Decrypt the file
    try:
        decrypted_aes_key = decrypt_aes_key_with_rsa(encrypted_aes_key, rsa_private_key)
        print(f"Decrypted AES key: {decrypted_aes_key.hex()}")
    except Exception as e:
        print(f"Decryption failed: {e}")

    if decrypted_aes_key is None:
        print("Decryption failed, exiting...")
        return

    # Decrypt file content
    data = decrypt_file_aes('sensitive_data.txt.enc', decrypted_aes_key)
    if data:
        print(f"Decrypted data: {data.decode()}")
    else:
        print("Decryption failed.")

if __name__ == "__main__":
    main()
