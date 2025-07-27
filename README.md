# GuardedIM - Secure CLI Chat System

**GuardedIM** is a secure, peer-authenticated command-line chat application that uses end-to-end encryption for direct messages (RSA) and optionally AES for channel messages. It uses a central relay server to facilitate communication and WireGuard to establish secure transport if configured.

---

## 🚀 Features

- ✅ Encrypted Direct Messaging (RSA)
- ✅ Encrypted Channel Messaging (AES with per-channel derived keys)
- ✅ User Registration & Login (with bcrypt password hashing)
- ✅ Per-user RSA keypair generation
- ✅ Public Key Directory for DM encryption
- ✅ Lightweight CLI interface
- ✅ Extendable modular design

---

## 🗂 Project Structure

```
chat_system/
├── relay_server.py
├── chat_client.py
├── wg0.conf           # Sample WireGuard config (optional)
├── config/
│   ├── users.json         # Registered users and password hashes
│   └── public_keys.json   # Public keys per user for RSA encryption
├── utils/
│   ├── encryption.py      # AES helpers (for channel encryption)
│   ├── crypto_rsa.py      # RSA encryption/decryption logic
│   └── logger.py          # Logging utility (optional)
└── requirements.txt
```

---

## 🔐 Encryption Overview

| Feature            | Method       |
|--------------------|--------------|
| Password Storage   | bcrypt       |
| Direct Messages    | RSA (2048)   |
| Channel Messages   | AES (CBC)    |
| Key Derivation     | SHA-256      |

---

## ⚙️ Setup Instructions

### 1. Clone the Repository

```bash
git clone https://github.com/yourusername/guardedim.git
cd guardedim
```

### 2. Create Virtual Environment & Install Requirements

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 3. Recreate Missing Configuration Files

If not included, manually create:

- `config/users.json`:
```json
{{
  "users": []
}}
```

- `config/public_keys.json`:
```json
{{
}}
```

### 4. Run Relay Server

```bash
python relay_server.py
```

### 5. Run Client

```bash
python chat_client.py
```

You can now register, login, join channels, and send messages.

---

## 📦 Requirements

- Python 3.7+
- PyCryptodome
- cryptography
- bcrypt

Install using:

```bash
pip install -r requirements.txt
```

---

## 🛡 RSA Key Storage

- Private keys are stored in `~/.guardedim/{{username}}_private.pem`
- Public keys are stored in `config/public_keys.json`

---

## 📋 Command List (Client)

```
join <channel>            Join a chat channel
leave <channel>           Leave a chat channel
msg <channel> <message>   Send encrypted message to a channel (AES)
dm <user> <message>       Send encrypted direct message (RSA)
exit                      Exit chat
help                      Show help menu
```

---

## 🧠 Notes

- All messages include a UTC timestamp.
- AES decryption failures show a warning if the key is invalid.
- You may implement WireGuard in `wg0.conf` to create private relay tunnels.
---

## Group Members

- Anh Ho
- Uma Naga Laskshmi Musunuru
- Gayathri Kodakandla
- Mannya Muralidhar Acharya
---
