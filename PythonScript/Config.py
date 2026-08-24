import os
import base64

from dotenv import load_dotenv
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad


ENV_FILE = "/home/yogavarman/Projects/Config/config.env"

# Load environment variables
load_dotenv(ENV_FILE, override=True)


def decrypt_config(server_name: str) -> dict:
    app_key = os.getenv("APP_KEY")
    if not app_key:
        raise ValueError("APP_KEY not found in config.env")
    encrypted = os.getenv(server_name)
    if not encrypted:
        raise ValueError(f"{server_name} not found in config.env")
    # Decode APP_KEY
    try:
        key = base64.b64decode(app_key)
    except Exception as e:
        raise ValueError(f"Invalid APP_KEY: {e}")

    # Validate AES key
    if len(key) not in (16, 24, 32):
        raise ValueError(f"Invalid AES key length: {len(key)} bytes")
    # Decode encrypted value
    try:
        encrypted_data = base64.b64decode(encrypted)
    except Exception as e:
        raise ValueError(f"Invalid encrypted data: {e}")
    # Validate IV + ciphertext
    if len(encrypted_data) <= AES.block_size:
        raise ValueError(f"Invalid encrypted data for {server_name}")
    # Extract IV
    iv = encrypted_data[:AES.block_size]
    # Extract ciphertext
    ciphertext = encrypted_data[AES.block_size:]
    # Validate ciphertext length
    if len(ciphertext) % AES.block_size != 0:
        raise ValueError(f"Invalid ciphertext length for {server_name}")
    # AES CBC
    cipher = AES.new(key,AES.MODE_CBC,iv)

    # Decrypt
    try:
        decrypted = cipher.decrypt(ciphertext)
        decrypted = unpad(decrypted,AES.block_size)
        decrypted = decrypted.decode("utf-8")
    except ValueError:
        raise ValueError(
            f"Unable to decrypt {server_name}. "
            "APP_KEY and encrypted value do not match."
        )

    # Convert decrypted text to dictionary
    config = {}
    for line in decrypted.splitlines():
        line = line.strip()
        if not line:
            continue
        if "=" in line:
            name, value = line.split("=", 1)
            config[name.strip()] = value.strip()
    return config