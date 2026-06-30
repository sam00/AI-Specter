"""Ed25519 identities for Relay — passwordless, no shared secrets.

Each Relay client and server is identified by an Ed25519 keypair. Servers
pin an allowlist of authorized *client* public keys; clients pin the server's
public key. This gives mutual, key-based auth with zero passwords and no
long-lived bearer tokens to leak — an improvement over shared-secret schemes.

The ``cryptography`` dependency is optional (``ai-specter[relay]``); importing
this module without it raises a clear, actionable error only when used.
"""
from __future__ import annotations

import base64
from pathlib import Path


def _require_crypto():
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (  # noqa: F401
            Ed25519PrivateKey,
            Ed25519PublicKey,
        )
    except ImportError as e:  # pragma: no cover
        raise RuntimeError("pip install 'ai-specter[relay]' for Relay (cryptography)") from e
    from cryptography.hazmat.primitives.asymmetric import ed25519
    return ed25519


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


def unb64(text: str) -> bytes:
    return base64.b64decode(text.encode())


class KeyPair:
    """An Ed25519 keypair with base64 serialization helpers."""

    def __init__(self, private) -> None:
        self._private = private
        self.public = private.public_key()

    @classmethod
    def generate(cls) -> "KeyPair":
        ed = _require_crypto()
        return cls(ed.Ed25519PrivateKey.generate())

    @classmethod
    def from_seed_b64(cls, seed_b64: str) -> "KeyPair":
        ed = _require_crypto()
        return cls(ed.Ed25519PrivateKey.from_private_bytes(unb64(seed_b64)))

    def seed_b64(self) -> str:
        from cryptography.hazmat.primitives import serialization
        raw = self._private.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption())
        return b64(raw)

    def public_b64(self) -> str:
        from cryptography.hazmat.primitives import serialization
        raw = self.public.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw)
        return b64(raw)

    def sign(self, message: bytes) -> str:
        return b64(self._private.sign(message))

    def save(self, path: str | Path) -> Path:
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(self.seed_b64())
        p.chmod(0o600)
        return p

    @classmethod
    def load(cls, path: str | Path) -> "KeyPair":
        return cls.from_seed_b64(Path(path).read_text().strip())


def verify(public_b64: str, message: bytes, signature_b64: str) -> bool:
    ed = _require_crypto()
    try:
        pub = ed.Ed25519PublicKey.from_public_bytes(unb64(public_b64))
        pub.verify(unb64(signature_b64), message)
        return True
    except Exception:
        return False
