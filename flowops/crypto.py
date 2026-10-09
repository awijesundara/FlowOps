"""Settings encryption, password hashing and the encryption-at-rest helpers."""
from __future__ import annotations

import base64
import hashlib
import hmac
import os
import secrets
import subprocess



class InvalidToken(ValueError):
    """Raised when an encrypted administrator setting fails authentication."""

class SettingsCipher:
    """Small OpenSSL-backed authenticated cipher for portable secret storage."""

    VERSION = b"FO1"

    def __init__(self, encoded_key: str):
        try:
            self.master_key = base64.urlsafe_b64decode(encoded_key.encode())
        except (ValueError, TypeError) as exc:
            raise ValueError("invalid encryption key") from exc
        if len(self.master_key) != 32:
            raise ValueError("invalid encryption key")
        self.encryption_key = hmac.new(self.master_key, b"flowops:encryption", hashlib.sha256).digest()
        self.authentication_key = hmac.new(self.master_key, b"flowops:authentication", hashlib.sha256).digest()

    def _crypt(self, payload: bytes, nonce: bytes, decrypt: bool = False) -> bytes:
        command = ["openssl", "enc", "-aes-256-ctr", "-K", self.encryption_key.hex(), "-iv", nonce.hex()]
        if decrypt:
            command.append("-d")
        try:
            return subprocess.run(command, input=payload, capture_output=True, check=True).stdout
        except (OSError, subprocess.CalledProcessError) as exc:
            raise RuntimeError("OpenSSL credential encryption failed") from exc

    def encrypt(self, plaintext: bytes) -> bytes:
        nonce = secrets.token_bytes(16)
        ciphertext = self._crypt(plaintext, nonce)
        authenticated = self.VERSION + nonce + ciphertext
        tag = hmac.new(self.authentication_key, authenticated, hashlib.sha256).digest()
        return base64.urlsafe_b64encode(authenticated + tag)

    def decrypt(self, token: bytes) -> bytes:
        try:
            decoded = base64.urlsafe_b64decode(token)
        except (ValueError, TypeError) as exc:
            raise InvalidToken("invalid credential encoding") from exc
        if len(decoded) < 51 or decoded[:3] != self.VERSION:
            raise InvalidToken("invalid credential format")
        authenticated, supplied_tag = decoded[:-32], decoded[-32:]
        expected_tag = hmac.new(self.authentication_key, authenticated, hashlib.sha256).digest()
        if not hmac.compare_digest(supplied_tag, expected_tag):
            raise InvalidToken("credential authentication failed")
        return self._crypt(authenticated[19:], authenticated[3:19], decrypt=True)

def password_hash(password: str, salt: bytes | None=None) -> str:
    salt=salt or secrets.token_bytes(16); digest=hashlib.pbkdf2_hmac("sha256",password.encode(),salt,240_000)
    return f"pbkdf2_sha256$240000${salt.hex()}${digest.hex()}"

def password_valid(password: str, encoded: str) -> bool:
    try: _,rounds,salt,digest=encoded.split("$"); actual=hashlib.pbkdf2_hmac("sha256",password.encode(),bytes.fromhex(salt),int(rounds)).hex()
    except (ValueError,TypeError): return False
    return hmac.compare_digest(actual,digest)

def settings_cipher() -> SettingsCipher:
    key=os.getenv("FLOWOPS_SETTINGS_ENCRYPTION_KEY","").strip()
    if not key: raise RuntimeError("FLOWOPS_SETTINGS_ENCRYPTION_KEY is required for administrator-managed credentials")
    try:return SettingsCipher(key)
    except (ValueError,TypeError) as exc:raise RuntimeError("FLOWOPS_SETTINGS_ENCRYPTION_KEY is invalid") from exc
