# secrets_store.py
from __future__ import annotations

import base64
import os
from typing import Tuple

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet


_KDF_ITERS = 200_000
_SALT_LEN = 16  # bytes


def _derive_key(password: str, salt: bytes) -> bytes:
    if not isinstance(password, str) or not password:
        raise ValueError("Password must be a non-empty string.")
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=_KDF_ITERS,
    )
    key = kdf.derive(password.encode("utf-8"))
    return base64.urlsafe_b64encode(key)


def encrypt_secret(plaintext: str, password: str) -> str:
    """
    Encrypts plaintext with password. Returns a token string:
      v1:<base64url(salt)>:<fernet_token>
    """
    if plaintext is None:
        plaintext = ""
    salt = os.urandom(_SALT_LEN)
    key = _derive_key(password, salt)
    token = Fernet(key).encrypt(plaintext.encode("utf-8"))
    return "v1:" + base64.urlsafe_b64encode(salt).decode("ascii") + ":" + token.decode("ascii")


def decrypt_secret(token: str, password: str) -> str:
    """
    Decrypts token produced by encrypt_secret.
    """
    if not token or ":" not in token:
        raise ValueError("Invalid token format.")
    parts = token.split(":")
    if parts[0] != "v1" or len(parts) != 3:
        raise ValueError("Unsupported token format/version.")
    salt_b = base64.urlsafe_b64decode(parts[1].encode("ascii"))
    fern_b = parts[2].encode("ascii")
    key = _derive_key(password, salt_b)
    pt = Fernet(key).decrypt(fern_b)
    return pt.decode("utf-8")
