# chat_client.py


import socket
import ssl
import os
import threading
import json
import bcrypt
import base64
import getpass
import re
from datetime import datetime
from dotenv import load_dotenv

from utils.encryption import derive_key, encrypt_message, decrypt_message
from utils.logger import log
from utils.crypto_rsa import (
    generate_rsa_keypair,
    encrypt_with_public_key,
    decrypt_with_private_key,
    load_private_key,
    sign_message,
    verify_signature
)

# Load environment variables
load_dotenv()
CHANNEL_SECRET = os.getenv("CHANNEL_SECRET", "fallback_shared_secret")

SERVER = '127.0.0.1'
PORT = 5000

key = None
channel_key = derive_key(CHANNEL_SECRET)
username = None

def receive(sock):
    global username
    while True:
        try:
            data = sock.recv(4096).decode()
            if not data:
                break

            if data.startswith("FILE::"):
                try:
                    _, sender, filename, b64content = data.split("::", 3)
                    privkey = load_private_key(username)
                    encrypted = base64.b64decode(b64content)
                    decrypted = decrypt_with_private_key(privkey, encrypted)

                    os.makedirs("downloads", exist_ok=True)
                    filepath = os.path.join("downloads", filename)
                    with open(filepath, "wb") as f:
                        f.write(decrypted)
                    print(f"📥 File received from {sender}: saved to downloads/{filename}")
                except Exception as e:
                    print(f"❌ Failed to receive file: {e}")
                continue

            if "]: " in data:
                try:
                    prefix, encrypted_msg = data.split("]: ", 1)
                    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

                    if "DM from" in prefix and encrypted_msg.startswith("RSA:"):
                        enc_part = encrypted_msg[4:].strip()
                        cipher_b64, sig_b64, sender = enc_part.split("::")
                        encrypted_bytes = base64.b64decode(cipher_b64)
                        signature = base64.b64decode(sig_b64)

                        privkey = load_private_key(username)
                        decrypted = decrypt_with_private_key(privkey, encrypted_bytes)

                        with open("config/public_keys.json") as f:
                            pub_key_pem = json.load(f)[sender]
                        pubkey = encrypt_with_public_key.__globals__["serialization"].load_pem_public_key(pub_key_pem.encode())

                        if verify_signature(pubkey, decrypted, signature):
                            print(f"[{timestamp}] {prefix}]: {decrypted}")
                        else:
                            print(f"[{timestamp}] {prefix}]: ⚠️ Signature verification failed!")

                    else:
                        decrypted = decrypt_message(encrypted_msg.strip(), channel_key)
                        print(f"[{timestamp}] {prefix}]: {decrypted}")

                except Exception as e:
                    print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] ❌ Failed to decrypt message: {e}")
                    print(f"(❌ Encrypted) {data}")
            else:
                print(data)

        except Exception as e:
            print(f"⚠️ Error receiving data: {e}")
            break

def show_help():
    print("""
Available commands:
  join <channel>              Join a chat channel
  leave <channel>             Leave a chat channel
  msg <channel> <message>     Send encrypted message to a channel
  dm <user> <message>         Send encrypted direct message
  sendfile <user> <path>      Send file to user (RSA encrypted)
  exit                        Exit chat
  help                        Show this help message
""")

def register():
    uname = input("Choose username: ").strip()
    pwd = getpass.getpass("Choose password: ").strip()

    if len(pwd) < 8 or not re.search(r"[A-Z]", pwd) or not re.search(r"\d", pwd):
        print("❌ Password must be at least 8 characters long and include a number and an uppercase letter.")
        return

    try:
        with open("config/users.json", "r+") as f:
            data = json.load(f)
            if any(u['username'] == uname for u in data['users']):
                print("❌ Username already exists.")
                return

            hashed = bcrypt.hashpw(pwd.encode(), bcrypt.gensalt()).decode()
            data['users'].append({
                "username": uname,
                "password_hash": hashed
            })

            public_key_pem = generate_rsa_keypair(uname)

            pub_file = "config/public_keys.json"
            if os.path.exists(pub_file):
                with open(pub_file, "r") as pubf:
                    pub_data = json.load(pubf)
            else:
                pub_data = {}

            pub_data[uname] = public_key_pem
            with open(pub_file, "w") as pubf:
                json.dump(pub_data, pubf, indent=2)

            f.seek(0)
            json.dump(data, f, indent=2)
            f.truncate()

        print("✅ Registration successful.")

    except Exception as e:
        print(f"❌ Error during registration: {e}")

def login(sock):
    global key, username
    username = input("Username: ").strip()
    password = getpass.getpass("Password: ").strip()
    sock.sendall(f"login {username} {password}".encode())
    response = sock.recv(1024).decode()
    print(response)
    if "successful" in response:
        key = derive_key(password)
        return True
    return False

def main():
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock = context.wrap_socket(raw_sock, server_hostname=SERVER)

    try:
        sock.connect((SERVER, PORT))
    except Exception as e:
        print(f"❌ Could not connect to server: {e}")
        return

    print("Welcome to GuardedIM Secure CLI Chat")
    choice = input("Login or Register? (l/r): ").strip().lower()
    if choice == "r":
        register()
        sock.close()
        return

    if not login(sock):
        print("❌ Login failed.")
        sock.close()
        return

    threading.Thread(target=receive, args=(sock,), daemon=True).start()
    show_help()

    try:
        while True:
            cmd = input("> ").strip()
            if not cmd:
                continue

            if cmd == "help":
                show_help()
                continue
            elif cmd == "exit":
                sock.sendall(b"exit")
                break

            elif cmd.startswith("msg "):
                parts = cmd.split(" ", 2)
                if len(parts) < 3:
                    print("⚠️ Usage: msg <channel> <message>")
                    continue
                channel, msg = parts[1], parts[2]
                encrypted = encrypt_message(msg, channel_key)
                sock.sendall(f"msg {channel} {encrypted}".encode())

            elif cmd.startswith("dm "):
                parts = cmd.split(" ", 2)
                if len(parts) < 3:
                    print("⚠️ Usage: dm <user> <message>")
                    continue
                recipient, msg = parts[1], parts[2]

                try:
                    with open("config/public_keys.json", "r") as f:
                        pub_keys = json.load(f)
                        if recipient not in pub_keys:
                            print(f"❌ No public key found for {recipient}")
                            continue
                        public_pem = pub_keys[recipient]

                    encrypted = encrypt_with_public_key(public_pem, msg)
                    encoded = base64.b64encode(encrypted).decode()

                    privkey = load_private_key(username)
                    signature = sign_message(privkey, msg)
                    sig_b64 = base64.b64encode(signature).decode()

                    sock.sendall(f"dm {recipient} RSA:{encoded}::{sig_b64}::{username}".encode())

                except Exception as e:
                    print(f"❌ Error sending DM: {e}")

            elif cmd.startswith("sendfile "):
                parts = cmd.split(" ", 2)
                if len(parts) < 3:
                    print("⚠️ Usage: sendfile <user> <file_path>")
                    continue
                recipient, filepath = parts[1], parts[2]
                if not os.path.isfile(filepath):
                    print(f"❌ File not found: {filepath}")
                    continue

                try:
                    with open("config/public_keys.json", "r") as f:
                        pub_keys = json.load(f)
                    if recipient not in pub_keys:
                        print(f"❌ No public key found for {recipient}")
                        continue
                    pubkey = encrypt_with_public_key.__globals__["serialization"].load_pem_public_key(
                        pub_keys[recipient].encode()
                    )

                    with open(filepath, "rb") as f:
                        content = f.read()
                    filename = os.path.basename(filepath)

                    encrypted = pubkey.encrypt(
                        content,
                        padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
                    )
                    encoded = base64.b64encode(encrypted).decode()

                    payload = f"{filename}::{encoded}"
                    sock.sendall(f"file {recipient} {payload}".encode())
                    print(f"📤 Sent file {filename} to {recipient}")

                except Exception as e:
                    print(f"❌ Failed to send file: {e}")

            elif cmd.startswith("join ") or cmd.startswith("leave "):
                sock.sendall(cmd.encode())
            else:
                print("❌ Unknown command. Type 'help' to see available options.")

    except KeyboardInterrupt:
        sock.sendall(b"exit")
    finally:
        sock.close()
        print("Disconnected from GuardedIM.")


if __name__ == "__main__":
    main()
