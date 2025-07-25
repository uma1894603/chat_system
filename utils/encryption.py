# utils/encryption.py

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64
import hashlib

BLOCK_SIZE = 16  # Bytes for AES block size

def pad(s):
    padding = BLOCK_SIZE - len(s) % BLOCK_SIZE
    return s + chr(padding) * padding

def unpad(s):
    return s[:-ord(s[-1])]

def derive_key(password: str) -> bytes:
    """Derives a 32-byte AES key from a password using SHA-256"""
    return hashlib.sha256(password.encode()).digest()

def encrypt_message(message: str, key: bytes) -> str:
    """Encrypts message using AES CBC"""
    iv = get_random_bytes(BLOCK_SIZE)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_message = pad(message)
    encrypted = cipher.encrypt(padded_message.encode())
    return base64.b64encode(iv + encrypted).decode()

def decrypt_message(ciphertext: str, key: bytes) -> str:
    """Decrypts AES CBC encrypted message"""
    raw = base64.b64decode(ciphertext)
    iv = raw[:BLOCK_SIZE]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted = cipher.decrypt(raw[BLOCK_SIZE:]).decode()
    return unpad(decrypted)
