# chat_client.py

import socket
import os
import threading
import json
import bcrypt
from datetime import datetime
from utils.encryption import derive_key, encrypt_message, decrypt_message
from utils.logger import log
import base64
from utils.crypto_rsa import generate_rsa_keypair, encrypt_with_public_key, decrypt_with_private_key, load_private_key

SERVER = '127.0.0.1'
PORT = 5000

key = None
channel_key = derive_key("channel_shared_secret")  # Shared AES key for channels
username = None

def receive(sock):
    global username
    while True:
        try:
            data = sock.recv(2048).decode()
            if not data:
                break

            if "]: " in data:
                try:
                    prefix, encrypted_msg = data.split("]: ", 1)
                    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

                    if "DM from" in prefix and encrypted_msg.startswith("RSA:"):
                        enc_b64 = encrypted_msg[4:].strip()
                        encrypted_bytes = base64.b64decode(enc_b64)
                        privkey = load_private_key(username)
                        decrypted = decrypt_with_private_key(privkey, encrypted_bytes)
                        print(f"[{timestamp}] {prefix}]: {decrypted}")

                    else:
                        decrypted = decrypt_message(encrypted_msg.strip(), channel_key)
                        print(f"[{timestamp}] {prefix}]: {decrypted}")

                except Exception as e:
                    print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] \u274c Failed to decrypt message: {e}")
                    print(f"(\u274c Encrypted) {data}")
            else:
                print(data)

        except Exception as e:
            print(f"\u26a0\ufe0f Error receiving data: {e}")
            break

def show_help():
    print("""
Available commands:
  join <channel>            Join a chat channel
  leave <channel>           Leave a chat channel
  msg <channel> <message>   Send encrypted message to a channel
  dm <user> <message>       Send encrypted direct message
  exit                      Exit chat
  help                      Show this help message
""")

def register():
    uname = input("Choose username: ").strip()
    pwd = input("Choose password: ").strip()

    try:
        with open("config/users.json", "r+") as f:
            data = json.load(f)
            if any(u['username'] == uname for u in data['users']):
                print("\u274c Username already exists.")
                return

            hashed = bcrypt.hashpw(pwd.encode(), bcrypt.gensalt()).decode()
            data['users'].append({
                "username": uname,
                "password_hash": hashed
            })

            # Generate RSA keys
            public_key_pem = generate_rsa_keypair(uname)

            # Save public key to shared config
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

        print("\u2705 Registration successful.")

    except Exception as e:
        print(f"\u274c Error during registration: {e}")

def login(sock):
    global key, username
    username = input("Username: ").strip()
    password = input("Password: ").strip()
    sock.sendall(f"login {username} {password}".encode())
    response = sock.recv(1024).decode()
    print(response)
    if "successful" in response:
        key = derive_key(password)
        return True
    return False

def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.connect((SERVER, PORT))
    except Exception as e:
        print(f"\u274c Could not connect to server: {e}")
        return

    print("Welcome to GuardedIM Secure CLI Chat")
    choice = input("Login or Register? (l/r): ").strip().lower()
    if choice == "r":
        register()
        sock.close()
        return

    if not login(sock):
        print("\u274c Login failed.")
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
                    print("\u26a0\ufe0f Usage: msg <channel> <message>")
                    continue
                channel, msg = parts[1], parts[2]
                encrypted = encrypt_message(msg, channel_key)
                sock.sendall(f"msg {channel} {encrypted}".encode())

            elif cmd.startswith("dm "):
                parts = cmd.split(" ", 2)
                if len(parts) < 3:
                    print("\u26a0\ufe0f Usage: dm <user> <message>")
                    continue
                recipient, msg = parts[1], parts[2]

                try:
                    with open("config/public_keys.json", "r") as f:
                        pub_keys = json.load(f)
                        if recipient not in pub_keys:
                            print(f"\u274c No public key found for {recipient}")
                            continue
                        public_pem = pub_keys[recipient]

                    encrypted = encrypt_with_public_key(public_pem, msg)
                    encoded = base64.b64encode(encrypted).decode()
                    sock.sendall(f"dm {recipient} RSA:{encoded}".encode())

                except Exception as e:
                    print(f"\u274c Error sending DM: {e}")

            elif cmd.startswith("join ") or cmd.startswith("leave "):
                sock.sendall(cmd.encode())

            else:
                print("\u274c Unknown command. Type 'help' to see available options.")

    except KeyboardInterrupt:
        sock.sendall(b"exit")
    finally:
        sock.close()
        print("Disconnected from GuardedIM.")

if __name__ == "__main__":
    main()
