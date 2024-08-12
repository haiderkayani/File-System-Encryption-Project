from Crypto.Hash import SHA256

def generate_sha256_hash(filename):
    h = SHA256.new()
    with open(filename, 'rb') as file:
        while chunk := file.read(8192):
            h.update(chunk)
    return h.hexdigest()
