# relay_server.py

import socket
import threading
import json
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
            data = conn.recv(1024).decode()
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
                channel, msg = parts[1], parts[2]
                broadcast(channel, username, msg)

            elif cmd == "dm":
                recipient, msg = parts[1], parts[2]
                if recipient in clients:
                    clients[recipient].sendall(f"[DM from {username}]: {msg}".encode())
                else:
                    conn.sendall(b"User not online\n")

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
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen()
        log(f"Relay server running on {HOST}:{PORT}")

        while True:
            conn, addr = s.accept()
            threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()

if __name__ == "__main__":
    start_server()
