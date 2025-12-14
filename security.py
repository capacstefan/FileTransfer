"""
Security module - Cryptographic operations
- Ed25519 for identity (signing)
- X25519 for key exchange (ECDH)
- ChaCha20-Poly1305 for authenticated encryption
"""
from __future__ import annotations

import hashlib
import os
import secrets
from pathlib import Path
from typing import Tuple, Optional

from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from storage import KEYS_DIR

# Key file paths
IDENTITY_PRIVATE_KEY = KEYS_DIR / "identity_ed25519.pem"
IDENTITY_PUBLIC_KEY = KEYS_DIR / "identity_ed25519.pub"


# ============================================================
# Identity Keys (Ed25519) - Long-term identity
# ============================================================

def ensure_identity_keypair() -> None:
    """Generate identity keypair if not exists"""
    if IDENTITY_PRIVATE_KEY.exists():
        return
    
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    
    # Save private key
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    IDENTITY_PRIVATE_KEY.write_bytes(private_pem)
    
    # Save public key
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    IDENTITY_PUBLIC_KEY.write_bytes(public_pem)


def load_identity_private_key() -> ed25519.Ed25519PrivateKey:
    """Load identity private key"""
    ensure_identity_keypair()
    pem_data = IDENTITY_PRIVATE_KEY.read_bytes()
    return serialization.load_pem_private_key(pem_data, password=None)


def load_identity_public_key() -> ed25519.Ed25519PublicKey:
    """Load identity public key"""
    ensure_identity_keypair()
    pem_data = IDENTITY_PUBLIC_KEY.read_bytes()
    return serialization.load_pem_public_key(pem_data)


def load_identity_public_bytes() -> bytes:
    """Get raw public key bytes (32 bytes)"""
    pub = load_identity_public_key()
    return pub.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )


def sign_message(message: bytes) -> bytes:
    """Sign a message with identity key"""
    private_key = load_identity_private_key()
    return private_key.sign(message)


def verify_signature(public_key_bytes: bytes, message: bytes, signature: bytes) -> bool:
    """Verify signature from peer's public key"""
    try:
        public_key = ed25519.Ed25519PublicKey.from_public_bytes(public_key_bytes)
        public_key.verify(signature, message)
        return True
    except Exception:
        return False


# ============================================================
# Ephemeral Keys (X25519) - Per-session key exchange
# ============================================================

def generate_ephemeral() -> Tuple[x25519.X25519PrivateKey, bytes]:
    """Generate ephemeral X25519 keypair for ECDH
    Returns: (private_key, public_key_bytes)
    """
    private_key = x25519.X25519PrivateKey.generate()
    public_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    return private_key, public_bytes


def compute_shared_secret(
    our_private: x25519.X25519PrivateKey,
    their_public_bytes: bytes
) -> bytes:
    """Compute shared secret via ECDH"""
    their_public = x25519.X25519PublicKey.from_public_bytes(their_public_bytes)
    return our_private.exchange(their_public)


def derive_session_keys(shared_secret: bytes, salt: bytes) -> Tuple[bytes, bytes]:
    """Derive symmetric keys from shared secret using HKDF
    Returns: (encrypt_key, decrypt_key) - both 32 bytes
    """
    # Use HKDF to derive 64 bytes, split into two 32-byte keys
    derived = HKDF(
        algorithm=hashes.SHA256(),
        length=64,
        salt=salt,
        info=b"FIshare-session-v1",
    ).derive(shared_secret)
    
    return derived[:32], derived[32:]


# ============================================================
# Symmetric Encryption (ChaCha20-Poly1305)
# ============================================================

class SecureChannel:
    """Authenticated encryption channel using ChaCha20-Poly1305"""
    
    NONCE_SIZE = 12  # 96 bits
    TAG_SIZE = 16    # 128 bits (included in ciphertext)
    
    def __init__(self, encrypt_key: bytes, decrypt_key: bytes):
        self._encryptor = ChaCha20Poly1305(encrypt_key)
        self._decryptor = ChaCha20Poly1305(decrypt_key)
        self._encrypt_counter = 0
        self._decrypt_counter = 0
    
    def _counter_to_nonce(self, counter: int) -> bytes:
        """Convert counter to nonce"""
        return counter.to_bytes(self.NONCE_SIZE, "big")
    
    def encrypt(self, plaintext: bytes, associated_data: bytes = b"") -> bytes:
        """Encrypt data with authentication
        Returns: nonce (12 bytes) + ciphertext + tag (16 bytes)
        """
        nonce = self._counter_to_nonce(self._encrypt_counter)
        self._encrypt_counter += 1
        ciphertext = self._encryptor.encrypt(nonce, plaintext, associated_data)
        return nonce + ciphertext
    
    def decrypt(self, data: bytes, associated_data: bytes = b"") -> bytes:
        """Decrypt and verify data
        Input: nonce (12 bytes) + ciphertext + tag (16 bytes)
        """
        if len(data) < self.NONCE_SIZE + self.TAG_SIZE:
            raise ValueError("Data too short")
        
        nonce = data[:self.NONCE_SIZE]
        ciphertext = data[self.NONCE_SIZE:]
        
        plaintext = self._decryptor.decrypt(nonce, ciphertext, associated_data)
        self._decrypt_counter += 1
        return plaintext


def generate_salt() -> bytes:
    """Generate random salt for key derivation"""
    return secrets.token_bytes(32)


# ============================================================
# File Hashing
# ============================================================

def hash_file_sha256(filepath: Path, chunk_size: int = 1048576) -> str:
    """Compute SHA-256 hash of file"""
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(chunk_size):
            h.update(chunk)
    return h.hexdigest()


def hash_bytes_sha256(data: bytes) -> str:
    """Compute SHA-256 hash of bytes"""
    return hashlib.sha256(data).hexdigest()
