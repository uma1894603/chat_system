# GuardedIM - Secure CLI Chat System

**GuardedIM** is a secure, peer-authenticated command-line chat application that uses end-to-end encryption for direct messages (RSA) with digital signatures, AES for channel messaging, TLS for transport security, and file sharing support. It uses a central relay server to facilitate communication.

---

## 🚀 Features

- ✅ Encrypted Direct Messaging (RSA + Digital Signature)
- ✅ Encrypted Channel Messaging (AES with per-channel derived keys)
- ✅ File Sharing between users (Base64 over TLS)
- ✅ TLS-secured Login and Communication
- ✅ User Registration & Login (with bcrypt password hashing)
- ✅ RSA keypair generation per user
- ✅ Public Key Directory for DM encryption and verification
- ✅ Command-line interface
- ✅ Modular, secure-by-default architecture

---

## 🗂 Project Structure

```
CHAT_SYSTEM/
├── chat_client.py
├── relay_server.py
├── wg0.conf               # Optional: WireGuard config
├── config/
│   ├── users.json         # User accounts and password hashes
│   └── public_keys.json   # RSA public keys per user
├── db/
│   └── chat_history.db    # SQLite DB (if used for logging/chat storage)
├── messages/
│   └── __init__.py        # Reserved for message persistence or protocol logic
├── utils/
│   ├── crypto_rsa.py      # RSA encryption, signature, verification
│   ├── encryption.py      # AES channel encryption
│   ├── handshake.py       # TLS/handshake utilities (optional)
│   └── logger.py          # Logging utility
├── cert.pem               # TLS certificate (self-signed or CA)
├── key.pem                # TLS private key
├── .env                   # Contains channel key (optional)
├── requirements.txt
└── README.md
```

---

## 🔐 Encryption Overview

| Feature            | Method                     |
|--------------------|----------------------------|
| Password Storage   | bcrypt                     |
| Direct Messages    | RSA (2048-bit) + Signature |
| Channel Messages   | AES (CBC)                  |
| Key Derivation     | SHA-256                    |
| Transport Layer    | TLS                        |

---

## ⚙️ Setup Instructions

### 1. Clone the Repository

```bash
git clone https://github.com/uma1894603/chat_system.git
cd chat_system
```

### 2. Setup Virtual Environment

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 3. Generate TLS Certificates (Optional for development)

```bash
openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365 -nodes
```

### 4. Create Initial Configuration Files

- `config/users.json`:

```json
{
  "users": []
}
```

- `config/public_keys.json`:

```json
{}
```

- `.env`:

```env
CHANNEL_SECRET=your_shared_channel_secret
```

### 5. Run the Server

```bash
python relay_server.py
```

### 6. Launch the Client

```bash
python chat_client.py
```

---

## 📋 Command List

```
join <channel>            Join a channel
leave <channel>           Leave a channel
msg <channel> <message>   Send encrypted message to channel (AES)
dm <user> <message>       Send signed encrypted direct message (RSA)
sendfile <user> <path>    Send file (base64-encoded, over TLS)
exit                      Exit session
help                      Show help menu
```

---

## 📦 Requirements

- Python 3.7+
- cryptography
- bcrypt
- python-dotenv
- (Optional) PyCryptodome

Install all dependencies with:

```bash
pip install -r requirements.txt
```

---

## 🧠 Notes

- RSA private keys are stored securely under `~/.guardedim/`
- Public keys are stored in `config/public_keys.json`
- All DMs include a digital signature for authenticity
- TLS ensures encrypted transport even before login
- Base64 is used to safely encode binary files during transfer

---

## 📜 License

MIT License. See `LICENSE` for details.

---
