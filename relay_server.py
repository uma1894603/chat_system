# relay_server.py

import socket
import threading
import json
import ssl
import base64
from utils.logger import log

HOST = '0.0.0.0'
PORT = 5000

clients = {}       # username -> client socket
channels = {}      # channel_name -> set of usernames

def load_users():
    with open('config/users.json') as f:
        return json.load(f)['users']

def validate_login(username, password):
    import bcrypt
    users = load_users()
    for user in users:
        if user['username'] == username:
            return bcrypt.checkpw(password.encode(), user['password_hash'].encode())
    return False

def broadcast(channel, sender, message):
    if channel not in channels:
        return
    for user in channels[channel]:
        if user != sender and user in clients:
            try:
                clients[user].sendall(f"[{sender}@{channel}]: {message}".encode())
            except:
                log(f"Failed to send to {user}", "ERROR")

def handle_client(conn, addr):
    log(f"Connection from {addr}")
    username = None
    try:
        while True:
            data = conn.recv(4096).decode()
            if not data:
                break
            parts = data.strip().split(' ', 2)
            cmd = parts[0].lower()

            if cmd == "login":
                username, password = parts[1], parts[2]
                if validate_login(username, password):
                    clients[username] = conn
                    conn.sendall(b"Login successful\n")
                    log(f"{username} logged in")
                else:
                    conn.sendall(b"Invalid credentials\n")
                    break

            elif cmd == "join":
                channel = parts[1]
                channels.setdefault(channel, set()).add(username)
                conn.sendall(f"Joined {channel}\n".encode())

            elif cmd == "leave":
                channel = parts[1]
                if channel in channels and username in channels[channel]:
                    channels[channel].remove(username)
                    conn.sendall(f"Left {channel}\n".encode())

            elif cmd == "msg":
                if len(parts) < 3:
                    continue
                channel, msg = parts[1], parts[2]
                broadcast(channel, username, msg)

            elif cmd == "dm":
                if len(parts) < 3:
                    continue
                recipient, payload = parts[1], parts[2]

                if "::" not in payload:
                    conn.sendall(b"Invalid DM format\n")
                    continue

                enc_b64, sig_b64, sender = payload.split("::")
                try:
                    with open("config/public_keys.json", "r") as f:
                        public_keys = json.load(f)

                    if sender != username:
                        conn.sendall(b"Sender mismatch\n")
                        continue

                    if sender not in public_keys:
                        conn.sendall(b"Sender key not found\n")
                        continue

                    from cryptography.hazmat.primitives import serialization, hashes
                    from cryptography.hazmat.primitives.asymmetric import padding
                    from cryptography.exceptions import InvalidSignature

                    pubkey = serialization.load_pem_public_key(public_keys[sender].encode())
                    signature = base64.b64decode(sig_b64)
                    encrypted = base64.b64decode(enc_b64)

                    pubkey.verify(
                        signature,
                        encrypted,
                        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                        hashes.SHA256()
                    )

                    if recipient in clients:
                        clients[recipient].sendall(f"[DM from {sender}]: RSA:{enc_b64}::{sig_b64}::{sender}".encode())
                    else:
                        conn.sendall(b"User not online\n")

                except InvalidSignature:
                    log(f"❌ Invalid signature from {username}", "ERROR")
                    conn.sendall(b"❌ Invalid signature\n")

                except Exception as e:
                    log(f"❌ Error in DM from {username}: {e}", "ERROR")
                    conn.sendall(b"❌ Error processing DM\n")

            elif cmd == "file":
                if len(parts) < 3:
                    continue
                recipient, payload = parts[1], parts[2]
                try:
                    filename, b64data = payload.split("::", 1)
                    if recipient in clients:
                        clients[recipient].sendall(f"FILE::{username}::{filename}::{b64data}".encode())
                        log(f"📁 {username} sent file to {recipient}")
                    else:
                        conn.sendall(b"User not online\n")
                except Exception as e:
                    log(f"❌ Error relaying file: {e}", "ERROR")
                    conn.sendall(b"❌ Failed to send file\n")

            elif cmd == "exit":
                break

    except Exception as e:
        log(f"Error with {addr}: {e}", "ERROR")
    finally:
        if username:
            clients.pop(username, None)
            for chan in channels.values():
                chan.discard(username)
        conn.close()
        log(f"Connection closed: {addr}")

def start_server():
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(certfile='cert.pem', keyfile='key.pem')

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen()
        log(f"Relay server running on TLS {HOST}:{PORT}")

        while True:
            client_sock, addr = s.accept()
            try:
                tls_conn = context.wrap_socket(client_sock, server_side=True)
                threading.Thread(target=handle_client, args=(tls_conn, addr), daemon=True).start()
            except ssl.SSLError as e:
                log(f"TLS handshake failed with {addr}: {e}", "ERROR")
                client_sock.close()

if __name__ == "__main__":
    start_server()
