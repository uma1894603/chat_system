# utils/encryption.py

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from Crypto.Random import get_random_bytes
import base64
import hashlib

NONCE_SIZE = 12  # Recommended size for AES-GCM
KEY_SIZE = 32    # 256 bits

def derive_key(password: str) -> bytes:
    return hashlib.sha256(password.encode()).digest()

def encrypt_message(message: str, key: bytes) -> str:
    aesgcm = AESGCM(key)
    nonce = get_random_bytes(NONCE_SIZE)
    ciphertext = aesgcm.encrypt(nonce, message.encode(), associated_data=None)
    encrypted = base64.b64encode(nonce + ciphertext).decode()
    return encrypted

def decrypt_message(ciphertext: str, key: bytes) -> str:
    data = base64.b64decode(ciphertext)
    nonce = data[:NONCE_SIZE]
    encrypted_data = data[NONCE_SIZE:]

    aesgcm = AESGCM(key)
    decrypted = aesgcm.decrypt(nonce, encrypted_data, associated_data=None)
    return decrypted.decode()
