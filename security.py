import os
import json
import hashlib

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

from config import KEY_FILE, DATA_DIR, TRUSTED_PEERS_FILE


class AEADStream:
    def __init__(self, key: bytes):
        self._aead = ChaCha20Poly1305(key)
        self._send_nonce = 0
        self._recv_nonce = 0

    def _n2b(self, n: int) -> bytes:
        return n.to_bytes(12, "big")

    def encrypt(self, data: bytes) -> bytes:
        nonce = self._n2b(self._send_nonce)
        self._send_nonce += 1
        return self._aead.encrypt(nonce, data, b"FIshare")

    def decrypt(self, data: bytes) -> bytes:
        nonce = self._n2b(self._recv_nonce)
        self._recv_nonce += 1
        return self._aead.decrypt(nonce, data, b"FIshare")


class Identity:
    def __init__(self):
        self._priv = None
        self._pub = None

    def load_or_create(self):
        os.makedirs(DATA_DIR, exist_ok=True)
        if os.path.exists(KEY_FILE):
            with open(KEY_FILE, "rb") as f:
                self._priv = serialization.load_pem_private_key(f.read(), password=None)
        else:
            self._priv = ed25519.Ed25519PrivateKey.generate()
            pem = self._priv.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
            with open(KEY_FILE, "wb") as f:
                f.write(pem)
        self._pub = self._priv.public_key()

    def sign(self, data: bytes) -> bytes:
        return self._priv.sign(data)

    def public_bytes(self) -> bytes:
        return self._pub.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )


class TrustedPeers:
    def __init__(self):
        self._path = TRUSTED_PEERS_FILE
        self._peers = {}
        self._load()

    def _load(self):
        try:
            with open(self._path, "r", encoding="utf-8") as f:
                self._peers = json.load(f)
        except Exception:
            self._peers = {}

    def save(self):
        try:
            with open(self._path, "w", encoding="utf-8") as f:
                json.dump(self._peers, f, indent=2)
        except Exception:
            pass

    def get_peer_key(self, peer_id: str) -> bytes | None:
        hex_key = self._peers.get(peer_id)
        if not hex_key:
            return None
        return bytes.fromhex(hex_key)

    def remember_peer(self, peer_id: str, pub_key: bytes):
        self._peers[peer_id] = pub_key.hex()
        self.save()


def key_agree(sock, identity: Identity, trusted_peers: TrustedPeers, peer_id: str | None) -> AEADStream:
    """
    Handshake:
    - fiecare parte trimite: ephemeral_x25519_pub, identity_ed25519_pub, signature(ed25519, ephemeral)
    - dacă avem cheie salvată pentru peer_id, verificăm că identity_pub corespunde (pinning)
    - derivăm cheia de sesiune din ECDH (X25519 + HKDF)
    """
    # generate local ephemeral
    eph_priv = X25519PrivateKey.generate()
    eph_pub_bytes = eph_priv.public_key().public_bytes_raw()
    id_pub_bytes = identity.public_bytes()
    sig = identity.sign(eph_pub_bytes)

    def send_block(b: bytes):
        sock.sendall(len(b).to_bytes(2, "big") + b)

    def recv_block() -> bytes:
        ln = int.from_bytes(sock.recv(2), "big")
        buf = b""
        while len(buf) < ln:
            chunk = sock.recv(ln - len(buf))
            if not chunk:
                break
            buf += chunk
        return buf

    # send
    send_block(eph_pub_bytes)
    send_block(id_pub_bytes)
    send_block(sig)

    # recv
    peer_eph_pub = recv_block()
    peer_id_pub = recv_block()
    peer_sig = recv_block()

    # pinning: dacă avem cheie pentru peer_id, trebuie să coincidă
    if peer_id:
        saved = trusted_peers.get_peer_key(peer_id)
        if saved and saved != peer_id_pub:
            raise ValueError("Peer identity changed (possible MITM)")

    # verify signature
    ed25519.Ed25519PublicKey.from_public_bytes(peer_id_pub).verify(peer_sig, peer_eph_pub)

    # dacă nu aveam peer salvat, îl salvăm acum
    if peer_id and not trusted_peers.get_peer_key(peer_id):
        trusted_peers.remember_peer(peer_id, peer_id_pub)

    peer_eph_key = X25519PublicKey.from_public_bytes(peer_eph_pub)
    shared = eph_priv.exchange(peer_eph_key)

    key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"FIshare-key-v2",
    ).derive(shared)

    return AEADStream(key)


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()
