import os
import json
import base64
import hashlib
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.exceptions import InvalidTag

# Step 1: Key Derivation Function
def derive_key(password: str, salt: bytes) -> bytes:
    """
    Derive a cryptographic key from a password using PBKDF2 with SHA-256.
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

# Step 2: AES-GCM Encryption
def encrypt_data(data: bytes, key: bytes) -> (bytes, bytes, bytes):
    """
    Encrypt data using AES-GCM for confidentiality and integrity.
    """
    iv = os.urandom(12)  # 96-bit nonce for AES-GCM
    cipher = Cipher(
        algorithms.AES(key),
        modes.GCM(iv),
        backend=default_backend()
    )
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(data) + encryptor.finalize()
    return iv, ciphertext, encryptor.tag

# Step 3: AES-GCM Decryption
def decrypt_data(ciphertext: bytes, key: bytes, iv: bytes, tag: bytes) -> bytes:
    """
    Decrypt data using AES-GCM.
    """
    cipher = Cipher(
        algorithms.AES(key),
        modes.GCM(iv, tag),
        backend=default_backend()
    )
    decryptor = cipher.decryptor()
    try:
        return decryptor.update(ciphertext) + decryptor.finalize()
    except InvalidTag:
        raise ValueError("Decryption failed: data has been tampered with or key is incorrect.")

# Step 4: Archiving System
def archive_data(data: str, password: str, archive_name: str) -> None:
    """
    Archive critical data by encrypting and storing in a secure location.
    """
    salt = os.urandom(16)  # Generate a new salt for each password-based key derivation
    key = derive_key(password, salt)
    iv, encrypted_data, tag = encrypt_data(data.encode(), key)

    # Prepare data for storage
    archive_content = {
        "salt": base64.b64encode(salt).decode(),
        "iv": base64.b64encode(iv).decode(),
        "ciphertext": base64.b64encode(encrypted_data).decode(),
        "tag": base64.b64encode(tag).decode(),
    }

    # Write to file
    with open(f"{archive_name}.json", "w") as archive_file:
        json.dump(archive_content, archive_file)

    print(f"Data archived securely in {archive_name}.json.")

# Step 5: Restore Data
def restore_data(archive_name: str, password: str) -> str:
    """
    Restore data from archive by decrypting.
    """
    with open(f"{archive_name}.json", "r") as archive_file:
        archive_content = json.load(archive_file)

    # Decode base64
    salt = base64.b64decode(archive_content["salt"])
    iv = base64.b64decode(archive_content["iv"])
    ciphertext = base64.b64decode(archive_content["ciphertext"])
    tag = base64.b64decode(archive_content["tag"])

    # Derive key and decrypt
    key = derive_key(password, salt)
    decrypted_data = decrypt_data(ciphertext, key, iv, tag)

    return decrypted_data.decode()

# Example usage
if __name__ == "__main__":
    user_data = "Sensitive information that needs encryption."
    user_password = "strong_password123"

    archive_data(user_data, user_password, "user_archive")
    restored_data = restore_data("user_archive", user_password)
    print(f"Restored data: {restored_data}")