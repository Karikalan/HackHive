import os
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

KEY_LENGTH = 32
ITERATIONS = 100000

def derive_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_LENGTH,
        salt=salt,
        iterations=ITERATIONS,
        backend=default_backend(),
    )
    return kdf.derive(password.encode())

def encrypt_image(image_data, password):
    salt = os.urandom(16)
    iv = os.urandom(16)
    key = derive_key(password, salt)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    
    padding_length = 16 - (len(image_data) % 16)
    image_data += bytes([padding_length]) * padding_length
    ciphertext = encryptor.update(image_data) + encryptor.finalize()
    return salt + iv + ciphertext

def decrypt_image(encrypted_data, password):
    salt, iv, ciphertext = encrypted_data[:16], encrypted_data[16:32], encrypted_data[32:]
    key = derive_key(password, salt)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    
    decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()
    padding_length = decrypted_data[-1]
    return decrypted_data[:-padding_length]

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)