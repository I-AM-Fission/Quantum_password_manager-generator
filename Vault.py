import os
import json
from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from Quantum_Protected_Password_Generator import get_quantum_bytes

MAGIC = b"QVLT1"
SALT_LEN = 16
NONCE_LEN = 12
KEY_LEN = 32
VAULT_FILE = Path(__file__).with_name("vault.enc")

def kdf(master_password, salt):
    k = Scrypt(salt=salt, length=KEY_LEN, n=2**15, r=8, p=1)
    return k.derive(master_password.encode("utf-8"))

def encrypt(master_password, data):
    try:
        salt = get_quantum_bytes(SALT_LEN)
    except:
        salt = os.urandom(SALT_LEN)
    key = kdf(master_password, salt)
    nonce = os.urandom(NONCE_LEN)
    aes = AESGCM(key)
    plaintext = json.dumps(data, ensure_ascii=False).encode("utf-8")
    ciphertext = aes.encrypt(nonce, plaintext, MAGIC)
    return MAGIC + salt + nonce + ciphertext

def decrypt(master_password, blob):
    if len(blob) < len(MAGIC) + SALT_LEN + NONCE_LEN + 1:
        raise ValueError("Invalid vault")
    if blob[:len(MAGIC)] != MAGIC:
        raise ValueError("Invalid vault")
    offset = len(MAGIC)
    salt = blob[offset:offset + SALT_LEN]
    offset += SALT_LEN
    nonce = blob[offset:offset + NONCE_LEN]
    offset += NONCE_LEN
    ciphertext = blob[offset:]
    key = kdf(master_password, salt)
    aes = AESGCM(key)
    plaintext = aes.decrypt(nonce, ciphertext, MAGIC)
    return json.loads(plaintext.decode("utf-8"))

def load_vault(master_password):
    if not VAULT_FILE.exists():
        return {"entries": []}
    blob = VAULT_FILE.read_bytes()
    return decrypt(master_password, blob)

def save_vault(master_password, vault):
    blob = encrypt(master_password, vault)
    VAULT_FILE.write_bytes(blob)

def add_entry(master_password, site, username, password):
    vault = load_vault(master_password)
    vault.setdefault("entries", [])
    vault["entries"].append({"site": site, "username": username, "password": password})
    save_vault(master_password, vault)

def get_entries(master_password):
    vault = load_vault(master_password)
    return vault.get("entries", [])