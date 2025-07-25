# utils/crypto_rsa.py

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
import os

KEYS_DIR = os.path.expanduser("~/.guardedim")

def generate_rsa_keypair(username):
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()

    if not os.path.exists(KEYS_DIR):
        os.makedirs(KEYS_DIR)

    # Save private key locally (PEM format)
    priv_path = os.path.join(KEYS_DIR, f"{username}_private.pem")
    with open(priv_path, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))

    # Return public key PEM
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()
    return public_pem


def load_private_key(username):
    priv_path = os.path.join(KEYS_DIR, f"{username}_private.pem")
    with open(priv_path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)


def encrypt_with_public_key(public_pem, message):
    public_key = serialization.load_pem_public_key(public_pem.encode())
    ciphertext = public_key.encrypt(
        message.encode(),
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )
    return ciphertext


def decrypt_with_private_key(private_key, ciphertext):
    return private_key.decrypt(
        ciphertext,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    ).decode()
