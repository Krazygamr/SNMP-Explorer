# session_profile.py
from __future__ import annotations

import base64
import json
import os
import time
from dataclasses import dataclass, asdict, field
from typing import Any, Dict, Optional

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC  # type: ignore
from cryptography.hazmat.primitives import hashes  # type: ignore
from cryptography.hazmat.backends import default_backend  # type: ignore
from cryptography.fernet import Fernet, InvalidToken  # type: ignore


def _b64e(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode("utf-8")


def _b64d(s: str) -> bytes:
    return base64.urlsafe_b64decode(s.encode("utf-8"))


def _new_salt(n: int = 16) -> bytes:
    return os.urandom(n)


def _derive_key(password: str, salt: bytes, rounds: int = 200_000) -> bytes:
    # Derive a 32-byte key for Fernet using PBKDF2-HMAC-SHA256
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=rounds,
        backend=default_backend(),
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode("utf-8")))


@dataclass
class SessionProfile:
    # Versioning / crypto params
    version: int = 1
    kdf_rounds: int = 200_000
    salt_b64: str = field(default_factory=lambda: _b64e(_new_salt(16)))

    # Device (stored in clear — not sensitive)
    device_host: str = ""
    device_user: str = ""

    # SSH secret (encrypted)
    ssh_password_enc: str = ""  # Fernet(token) base64 string

    # Grafana settings (non-secret)
    grafana_url: str = ""            # e.g. http://localhost:3000
    grafana_ds_uid: str = ""         # Prometheus datasource UID
    grafana_folder_id: str = ""      # Folder ID to save dashboards

    # Grafana secret (encrypted)
    grafana_token_enc: str = ""      # Fernet(token) base64 string

    # Timestamps
    created_at: float = field(default_factory=lambda: time.time())
    updated_at: float = field(default_factory=lambda: time.time())

    # -------------------------------
    # File I/O
    # -------------------------------
    @staticmethod
    def load(path: str) -> "SessionProfile":
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        # backward/forwards-tolerant load
        sp = SessionProfile()
        for k, v in data.items():
            if hasattr(sp, k):
                setattr(sp, k, v)
        return sp

    def save(self, path: str) -> None:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        self.updated_at = time.time()
        with open(path, "w", encoding="utf-8") as f:
            json.dump(asdict(self), f, indent=2)

    # -------------------------------
    # Crypto helpers
    # -------------------------------
    def _fernet(self, password: str) -> Fernet:
        salt = _b64d(self.salt_b64)
        key = _derive_key(password, salt, self.kdf_rounds)
        return Fernet(key)

    def _encrypt(self, password: str, plaintext: str) -> str:
        if not plaintext:
            return ""
        t = self._fernet(password).encrypt(plaintext.encode("utf-8"))
        return t.decode("utf-8")

    def _decrypt(self, password: str, token: str) -> str:
        if not token:
            return ""
        try:
            pt = self._fernet(password).decrypt(token.encode("utf-8"))
            return pt.decode("utf-8")
        except InvalidToken as e:
            raise ValueError("Invalid profile password for decrypting this field.") from e

    # -------------------------------
    # SSH password (encrypted)
    # -------------------------------
    def set_ssh_password(self, password: str, ssh_password: str) -> None:
        self.ssh_password_enc = self._encrypt(password, ssh_password)

    def get_ssh_password(self, password: str) -> str:
        return self._decrypt(password, self.ssh_password_enc)

    # -------------------------------
    # Grafana token (encrypted)
    # -------------------------------
    def set_grafana_token(self, password: str, token: str) -> None:
        self.grafana_token_enc = self._encrypt(password, token)

    def get_grafana_token(self, password: str) -> str:
        return self._decrypt(password, self.grafana_token_enc)

    # -------------------------------
    # Non-secret setters (convenience)
    # -------------------------------
    def set_device(self, host: str, user: str) -> None:
        self.device_host = host or ""
        self.device_user = user or ""

    def set_grafana_settings(self, url: str, ds_uid: str, folder_id: str) -> None:
        self.grafana_url = url or ""
        self.grafana_ds_uid = ds_uid or ""
        self.grafana_folder_id = folder_id or ""
