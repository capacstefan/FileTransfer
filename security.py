from __future__ import annotations

import json
import os
import secrets
import threading
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from typing import Optional, Tuple

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

import storage


_LOCK = threading.RLock()


def _trusted_peers_path() -> Path:
    # Trust-on-first-use database: peer_id -> fingerprint
    return storage.keys_dir() / "trusted_peers.json"


def _load_trusted() -> dict:
    p = _trusted_peers_path()
    if not p.exists():
        return {}
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return {}


def _save_trusted(data: dict) -> None:
    p = _trusted_peers_path()
    p.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


def fingerprint_pubkey(pub_bytes: bytes) -> str:
    return sha256(pub_bytes).hexdigest()


def _identity_key_paths() -> tuple[str, str]:
    return ("identity_private.key", "identity_public.key")


def ensure_identity_keypair() -> Tuple[bytes, bytes]:
    """
    Returns (private_bytes, public_bytes). Generates and stores if missing.
    """
    with _LOCK:
        priv_name, pub_name = _identity_key_paths()
        priv = storage.read_key_bytes(priv_name)
        pub = storage.read_key_bytes(pub_name)

        if priv and pub:
            return priv, pub

        sk = X25519PrivateKey.generate()
        pk = sk.public_key()

        priv_bytes = sk.private_bytes(
            encoding=__import__("cryptography.hazmat.primitives.serialization").hazmat.primitives.serialization.Encoding.Raw,
            format=__import__("cryptography.hazmat.primitives.serialization").hazmat.primitives.serialization.PrivateFormat.Raw,
            encryption_algorithm=__import__("cryptography.hazmat.primitives.serialization").hazmat.primitives.serialization.NoEncryption(),
        )
        pub_bytes = pk.public_bytes(
            encoding=__import__("cryptography.hazmat.primitives.serialization").hazmat.primitives.serialization.Encoding.Raw,
            format=__import__("cryptography.hazmat.primitives.serialization").hazmat.primitives.serialization.PublicFormat.Raw,
        )

        storage.write_key_bytes(priv_name, priv_bytes)
        storage.write_key_bytes(pub_name, pub_bytes)
        return priv_bytes, pub_bytes


def load_identity_private() -> X25519PrivateKey:
    priv_bytes, _ = ensure_identity_keypair()
    return X25519PrivateKey.from_private_bytes(priv_bytes)


def load_identity_public_bytes() -> bytes:
    _, pub_bytes = ensure_identity_keypair()
    return pub_bytes


@dataclass(frozen=True)
class SessionKeys:
    key: bytes  # 32 bytes AES key


def derive_session_key(shared_secret: bytes, salt: bytes, info: bytes = b"lan-file-transfer-v1") -> SessionKeys:
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=info,
    )
    key = hkdf.derive(shared_secret)
    return SessionKeys(key=key)


def aesgcm_encrypt(key: bytes, nonce12: bytes, plaintext: bytes, aad: bytes = b"") -> bytes:
    return AESGCM(key).encrypt(nonce12, plaintext, aad)


def aesgcm_decrypt(key: bytes, nonce12: bytes, ciphertext: bytes, aad: bytes = b"") -> bytes:
    return AESGCM(key).decrypt(nonce12, ciphertext, aad)


def make_nonce(counter: int) -> bytes:
    # 12 bytes nonce (safe if counter never repeats for same key)
    return counter.to_bytes(12, "big", signed=False)


def check_or_pin_peer(peer_id: str, peer_pub_bytes: bytes) -> Tuple[bool, Optional[str]]:
    """
    Returns (ok, reason). Implements TOFU:
    - If peer_id unseen -> pins its fingerprint (requires UI prompt if in prompt-mode).
    - If seen and fingerprint differs -> suspicious.
    This function does not prompt; it just checks.
    """
    with _LOCK:
        trusted = _load_trusted()
        fp = fingerprint_pubkey(peer_pub_bytes)
        if peer_id not in trusted:
            return False, "untrusted"
        if trusted[peer_id] != fp:
            return False, "key_mismatch"
        return True, None


def pin_peer(peer_id: str, peer_pub_bytes: bytes) -> None:
    with _LOCK:
        trusted = _load_trusted()
        trusted[peer_id] = fingerprint_pubkey(peer_pub_bytes)
        _save_trusted(trusted)


def generate_ephemeral() -> Tuple[X25519PrivateKey, bytes]:
    sk = X25519PrivateKey.generate()
    pk = sk.public_key().public_bytes(
        encoding=__import__("cryptography.hazmat.primitives.serialization").hazmat.primitives.serialization.Encoding.Raw,
        format=__import__("cryptography.hazmat.primitives.serialization").hazmat.primitives.serialization.PublicFormat.Raw,
    )
    return sk, pk


def compute_shared_secret(our_sk: X25519PrivateKey, their_pk_bytes: bytes) -> bytes:
    their_pk = X25519PublicKey.from_public_bytes(their_pk_bytes)
    return our_sk.exchange(their_pk)
