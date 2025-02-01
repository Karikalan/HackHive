import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
from argon2.low_level import Type, hash_secret_raw
from cryptography.exceptions import InvalidKey

ARGON2_SALT_LENGTH = 16
IV_LENGTH = 16
KEY_LENGTH = 32  # 256-bit AES key

def derive_key(password: str, salt: bytes) -> bytes:
    """Derives a cryptographic key using Argon2ID."""
    return hash_secret_raw(
        password.encode(),
        salt,
        time_cost=3,
        memory_cost=65536,
        parallelism=2,
        hash_len=KEY_LENGTH,
        type=Type.ID
    )

def encrypt_image(image_data: bytes, password: str) -> bytes:
    """Encrypts image data and returns the ciphertext with salt and IV."""
    salt = os.urandom(ARGON2_SALT_LENGTH)
    iv = os.urandom(IV_LENGTH)
    key = derive_key(password, salt)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    
    padder = padding.PKCS7(128).padder()
    image_data = padder.update(image_data) + padder.finalize()

    ciphertext = encryptor.update(image_data) + encryptor.finalize()
    return salt + iv + ciphertext

def decrypt_image(encrypted_data: bytes, password: str) -> bytes:
    """Decrypts the ciphertext and returns the original image data."""
    salt, iv, ciphertext = encrypted_data[:ARGON2_SALT_LENGTH], encrypted_data[ARGON2_SALT_LENGTH:ARGON2_SALT_LENGTH + IV_LENGTH], encrypted_data[ARGON2_SALT_LENGTH + IV_LENGTH:]
    key = derive_key(password, salt)
    
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    try:
        decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()
    except InvalidKey:
        raise ValueError("Invalid password: Decryption failed")
    
    try:
        unpadder = padding.PKCS7(128).unpadder()
        decrypted_data = unpadder.update(decrypted_data) + unpadder.finalize()
    except ValueError:
        raise ValueError("Corrupted data: Decryption failed")

    return decrypted_data