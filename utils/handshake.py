# utils/handshake.py

def generate_keys():
    # In production, use subprocess to call wg genkey and wg pubkey
    return {
        "private": "mock_private_key",
        "public": "mock_public_key"
    }

def perform_handshake():
    # Simulated handshake (in reality use wg commands or API)
    print("Performing handshake... (simulated)")
