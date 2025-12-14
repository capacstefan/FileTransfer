"""
Network module - Discovery and Transfer services
Uses ThreadPoolExecutor for optimal performance
Completely separated from UI
"""
from __future__ import annotations

import json
import os
import socket
import struct
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple, Any

import security
from core import Core, TransferDirection, TransferStatus, FileInfo, Event, EventType, Peer


# ============================================================
# Protocol Helpers
# ============================================================

def send_json(sock: socket.socket, msg: dict) -> None:
    """Send length-prefixed JSON message"""
    data = json.dumps(msg, ensure_ascii=False).encode("utf-8")
    sock.sendall(struct.pack("!I", len(data)) + data)


def recv_exact(sock: socket.socket, n: int) -> bytes:
    """Receive exactly n bytes"""
    chunks = []
    received = 0
    while received < n:
        chunk = sock.recv(n - received)
        if not chunk:
            raise ConnectionError("Connection closed")
        chunks.append(chunk)
        received += len(chunk)
    return b"".join(chunks)


def recv_json(sock: socket.socket) -> dict:
    """Receive length-prefixed JSON message"""
    length_data = recv_exact(sock, 4)
    length = struct.unpack("!I", length_data)[0]
    if length > 100 * 1024 * 1024:  # 100MB limit for JSON
        raise ValueError("Message too large")
    data = recv_exact(sock, length)
    return json.loads(data.decode("utf-8"))


def send_bytes(sock: socket.socket, data: bytes) -> None:
    """Send length-prefixed binary data"""
    sock.sendall(struct.pack("!I", len(data)) + data)


def recv_bytes(sock: socket.socket) -> bytes:
    """Receive length-prefixed binary data"""
    length_data = recv_exact(sock, 4)
    length = struct.unpack("!I", length_data)[0]
    return recv_exact(sock, length)


# ============================================================
# Discovery Service (UDP multicast/broadcast)
# ============================================================

class DiscoveryService:
    """Peer discovery using UDP multicast with broadcast fallback"""
    
    def __init__(self, core: Core):
        self.core = core
        self._stop = threading.Event()
        self._threads: List[threading.Thread] = []
        self._local_ips = self._get_local_ips()

    @staticmethod
    def _get_local_ips() -> set:
        """Collect local interface IPs to avoid skipping peers with same username"""
        import socket
        ips = set()
        try:
            hostname = socket.gethostname()
            try:
                ips.add(socket.gethostbyname(hostname))
            except Exception:
                pass
            try:
                for info in socket.getaddrinfo(hostname, None):
                    ips.add(info[4][0])
            except Exception:
                pass
        except Exception:
            pass
        ips.discard("127.0.0.1")
        ips.discard("::1")
        return ips
    
    def start(self) -> None:
        """Start discovery service"""
        self._stop.clear()
        
        # Announcer thread
        t1 = threading.Thread(target=self._announce_loop, daemon=True, name="Discovery-TX")
        t1.start()
        self._threads.append(t1)
        
        # Listener thread
        t2 = threading.Thread(target=self._listen_loop, daemon=True, name="Discovery-RX")
        t2.start()
        self._threads.append(t2)
        
        # Pruner thread
        t3 = threading.Thread(target=self._prune_loop, daemon=True, name="Discovery-Prune")
        t3.start()
        self._threads.append(t3)
    
    def stop(self) -> None:
        """Stop discovery service"""
        self._stop.set()
    
    def _announce_loop(self) -> None:
        """Periodically announce our presence"""
        cfg = self.core.cfg
        udp_port = cfg.get("discovery", "udp_port", default=49221)
        multicast_group = cfg.get("discovery", "multicast_group", default="239.255.255.250")
        interval = cfg.get("discovery", "announce_interval_sec", default=1.5)
        tcp_port = cfg.get("network", "tcp_port", default=49222)
        
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        
        while not self._stop.is_set():
            try:
                profile = self.core.get_profile()
                message = {
                    "type": "ANNOUNCE",
                    "version": 1,
                    "username": profile["username"],
                    "availability": profile["availability"],
                    "tcp_port": tcp_port,
                    "timestamp": time.time(),
                }
                data = json.dumps(message).encode("utf-8")
                
                # Try multicast first
                try:
                    sock.sendto(data, (multicast_group, udp_port))
                except Exception:
                    pass
                
                # Also broadcast for compatibility
                try:
                    sock.sendto(data, ("255.255.255.255", udp_port))
                except Exception:
                    pass
                
            except Exception:
                pass
            
            self._stop.wait(interval)
        
        sock.close()
    
    def _listen_loop(self) -> None:
        """Listen for peer announcements"""
        cfg = self.core.cfg
        udp_port = cfg.get("discovery", "udp_port", default=49221)
        multicast_group = cfg.get("discovery", "multicast_group", default="239.255.255.250")
        my_tcp_port = cfg.get("network", "tcp_port", default=49222)
        
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        try:
            sock.bind(("", udp_port))
        except Exception:
            sock.bind(("0.0.0.0", udp_port))
        
        # Join multicast group
        try:
            mreq = struct.pack("=4sl", socket.inet_aton(multicast_group), socket.INADDR_ANY)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
        except Exception:
            pass
        
        sock.settimeout(0.5)
        
        while not self._stop.is_set():
            try:
                data, addr = sock.recvfrom(65536)
                ip = addr[0]
                
                try:
                    msg = json.loads(data.decode("utf-8"))
                except Exception:
                    continue
                
                if msg.get("type") != "ANNOUNCE":
                    continue
                
                username = str(msg.get("username", "Unknown"))
                availability = str(msg.get("availability", "available"))
                tcp_port = int(msg.get("tcp_port", 49222))
                
                # Ignore our own announcements (match by local IP + port)
                if ip in self._local_ips and tcp_port == my_tcp_port:
                    continue
                
                peer_id = f"{username}@{ip}:{tcp_port}"
                self.core.upsert_peer(peer_id, username, ip, tcp_port, availability)
                
            except socket.timeout:
                continue
            except Exception:
                continue
        
        sock.close()
    
    def _prune_loop(self) -> None:
        """Periodically remove stale peers"""
        timeout = self.core.cfg.get("discovery", "peer_timeout_sec", default=6.0)
        
        while not self._stop.is_set():
            self._stop.wait(2.0)
            try:
                self.core.prune_stale_peers(timeout)
            except Exception:
                pass


# ============================================================
# Incoming Transfer Offer
# ============================================================

@dataclass
class IncomingOffer:
    """Represents an incoming transfer request"""
    offer_id: str
    sender_name: str
    sender_ip: str
    sender_port: int
    files: List[dict]  # [{"name": ..., "size": ...}, ...]
    total_bytes: int
    sock: socket.socket  # Keep alive for accept/reject
    sender_pub: bytes


# ============================================================
# Transfer Service
# ============================================================

class TransferService:
    """
    Handles all file transfers using ThreadPoolExecutor.
    Supports multiple concurrent transfers with controlled thread usage.
    """
    
    def __init__(self, core: Core, on_incoming: Optional[Callable[[IncomingOffer], None]] = None):
        self.core = core
        self.on_incoming = on_incoming
        
        self._stop = threading.Event()
        self._server_sock: Optional[socket.socket] = None
        
        # Thread pool for all transfer operations
        max_workers = core.cfg.get("network", "max_concurrent_transfers", default=8) * 2
        self._pool = ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="Transfer")
        
        # Track active operations
        self._active_lock = threading.RLock()
        self._active_offers: Dict[str, IncomingOffer] = {}
    
    def set_on_incoming(self, callback: Callable[[IncomingOffer], None]) -> None:
        """Set callback for incoming transfer offers"""
        self.on_incoming = callback
    
    def start(self) -> None:
        """Start transfer server"""
        self._stop.clear()
        self._pool.submit(self._server_loop)
    
    def stop(self) -> None:
        """Stop transfer service"""
        self._stop.set()
        if self._server_sock:
            try:
                self._server_sock.close()
            except Exception:
                pass
        self._pool.shutdown(wait=False)
    
    def _server_loop(self) -> None:
        """Accept incoming connections"""
        port = self.core.cfg.get("network", "tcp_port", default=49222)
        
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("0.0.0.0", port))
        srv.listen(50)
        srv.settimeout(0.5)
        self._server_sock = srv
        
        while not self._stop.is_set():
            try:
                client, addr = srv.accept()
                self._pool.submit(self._handle_incoming_connection, client, addr)
            except socket.timeout:
                continue
            except Exception:
                if not self._stop.is_set():
                    continue
                break
        
        srv.close()
    
    def _handle_incoming_connection(self, sock: socket.socket, addr: Tuple[str, int]) -> None:
        """Handle incoming connection (runs in thread pool)"""
        sock.settimeout(30.0)
        sender_ip = addr[0]
        
        try:
            # Receive HELLO message
            hello = recv_json(sock)
            if hello.get("type") != "HELLO":
                sock.close()
                return
            
            sender_name = str(hello.get("username", "Unknown"))
            sender_port = int(hello.get("tcp_port", 0))
            sender_pub_hex = hello.get("identity_pub", "")
            sender_pub = bytes.fromhex(sender_pub_hex) if sender_pub_hex else b""
            
            # Check if we're busy
            if self.core.is_busy():
                send_json(sock, {"type": "BUSY"})
                sock.close()
                return
            
            # Send our identity
            our_pub = security.load_identity_public_bytes()
            send_json(sock, {"type": "HELLO_OK", "identity_pub": our_pub.hex()})
            
            # Receive transfer offer
            offer_msg = recv_json(sock)
            if offer_msg.get("type") != "OFFER":
                sock.close()
                return
            
            offer_id = str(offer_msg.get("offer_id", ""))
            files = offer_msg.get("files", [])
            total_bytes = int(offer_msg.get("total_bytes", 0))
            
            # Create offer object
            offer = IncomingOffer(
                offer_id=offer_id,
                sender_name=sender_name,
                sender_ip=sender_ip,
                sender_port=sender_port,
                files=files,
                total_bytes=total_bytes,
                sock=sock,
                sender_pub=sender_pub,
            )
            
            with self._active_lock:
                self._active_offers[offer_id] = offer
            
            # Notify UI to show accept/reject dialog
            if self.on_incoming:
                self.on_incoming(offer)
            else:
                # No callback set, auto-reject
                self.reject_offer(offer, "No handler configured")
            
        except Exception:
            try:
                sock.close()
            except Exception:
                pass
    
    def reject_offer(self, offer: IncomingOffer, reason: str = "rejected") -> None:
        """Reject an incoming transfer offer"""
        try:
            send_json(offer.sock, {"type": "REJECTED", "reason": reason})
        except Exception:
            pass
        
        try:
            offer.sock.close()
        except Exception:
            pass
        
        with self._active_lock:
            self._active_offers.pop(offer.offer_id, None)
    
    def accept_offer(self, offer: IncomingOffer) -> None:
        """Accept an incoming transfer offer"""
        try:
            send_json(offer.sock, {"type": "ACCEPTED"})
            
            # Start receiving in thread pool
            self._pool.submit(self._receive_files, offer)
            
        except Exception:
            try:
                offer.sock.close()
            except Exception:
                pass
            with self._active_lock:
                self._active_offers.pop(offer.offer_id, None)
    
    def _receive_files(self, offer: IncomingOffer) -> None:
        """Receive files from sender (runs in thread pool)"""
        sock = offer.sock
        transfer_id = offer.offer_id
        
        # Create file infos
        file_infos = [FileInfo(name=f["name"], path="", size=f["size"]) for f in offer.files]
        
        # Register transfer in core
        self.core.create_transfer(
            direction=TransferDirection.RECEIVE,
            peer_id=f"{offer.sender_name}@{offer.sender_ip}:{offer.sender_port}",
            peer_name=offer.sender_name,
            files=file_infos,
            total_bytes=offer.total_bytes,
        )
        
        self.core.update_transfer(transfer_id, status=TransferStatus.CONNECTING)
        
        try:
            # Key exchange
            recv_eph_sk, recv_eph_pk = security.generate_ephemeral()
            send_json(sock, {"type": "KEY_EXCHANGE", "eph_pub": recv_eph_pk.hex()})
            
            ke_response = recv_json(sock)
            if ke_response.get("type") != "KEY_EXCHANGE_OK":
                raise ConnectionError("Key exchange failed")
            
            sender_eph_pub = bytes.fromhex(ke_response["eph_pub"])
            salt = bytes.fromhex(ke_response["salt"])
            
            # Derive session keys
            shared = security.compute_shared_secret(recv_eph_sk, sender_eph_pub)
            # Receiver uses keys in reverse order
            decrypt_key, encrypt_key = security.derive_session_keys(shared, salt)
            channel = security.SecureChannel(encrypt_key, decrypt_key)
            
            self.core.update_transfer(transfer_id, status=TransferStatus.TRANSFERRING)
            
            # Receive files
            download_dir = Path(self.core.get_download_dir())
            download_dir.mkdir(parents=True, exist_ok=True)
            
            total_received = 0
            chunk_size = self.core.cfg.get("network", "chunk_size", default=1048576)
            
            for file_idx, file_info in enumerate(offer.files):
                file_name = file_info["name"]
                file_size = file_info["size"]
                file_path = download_dir / file_name
                
                # Handle duplicate names
                counter = 1
                while file_path.exists():
                    stem = Path(file_name).stem
                    suffix = Path(file_name).suffix
                    file_path = download_dir / f"{stem}_{counter}{suffix}"
                    counter += 1
                
                # Receive file
                with open(file_path, "wb") as f:
                    remaining = file_size
                    while remaining > 0:
                        # Receive encrypted chunk
                        encrypted = recv_bytes(sock)
                        plaintext = channel.decrypt(encrypted)
                        f.write(plaintext)
                        
                        remaining -= len(plaintext)
                        total_received += len(plaintext)
                        
                        self.core.update_transfer(
                            transfer_id,
                            transferred_bytes=total_received,
                            current_file_index=file_idx,
                        )
                
                # Send ACK for this file
                send_json(sock, {"type": "FILE_ACK", "file_index": file_idx})
            
            # Send completion
            send_json(sock, {"type": "DONE"})
            
            self.core.complete_transfer(transfer_id, TransferStatus.COMPLETED)
            
        except Exception as e:
            self.core.complete_transfer(transfer_id, TransferStatus.ERROR, str(e))
        
        finally:
            try:
                sock.close()
            except Exception:
                pass
            with self._active_lock:
                self._active_offers.pop(offer.offer_id, None)
    
    def send_to_peers(self, peers: List[Peer], file_paths: List[str]) -> None:
        """Send files to multiple peers (each in separate thread)"""
        for peer in peers:
            self._pool.submit(self._send_to_peer, peer, file_paths)
    
    def _send_to_peer(self, peer: Peer, file_paths: List[str]) -> None:
        """Send files to a single peer (runs in thread pool)"""
        import uuid
        
        # Prepare file infos
        file_infos = []
        total_bytes = 0
        for path in file_paths:
            p = Path(path)
            if p.exists() and p.is_file():
                size = p.stat().st_size
                file_infos.append(FileInfo(name=p.name, path=str(p), size=size))
                total_bytes += size
        
        if not file_infos:
            return
        
        offer_id = str(uuid.uuid4())[:8]
        
        # Register transfer
        transfer_id = self.core.create_transfer(
            direction=TransferDirection.SEND,
            peer_id=peer.peer_id,
            peer_name=peer.username,
            files=file_infos,
            total_bytes=total_bytes,
        )
        
        self.core.update_transfer(transfer_id, status=TransferStatus.CONNECTING)
        
        sock = None
        try:
            # Connect to peer
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(30.0)
            sock.connect((peer.ip, peer.port))
            
            # Send HELLO
            our_pub = security.load_identity_public_bytes()
            my_profile = self.core.get_profile()
            send_json(sock, {
                "type": "HELLO",
                "username": my_profile["username"],
                "tcp_port": self.core.cfg.get("network", "tcp_port", default=49222),
                "identity_pub": our_pub.hex(),
            })
            
            # Receive response
            response = recv_json(sock)
            if response.get("type") == "BUSY":
                self.core.complete_transfer(transfer_id, TransferStatus.REJECTED, "Peer is busy")
                sock.close()
                return
            
            if response.get("type") != "HELLO_OK":
                raise ConnectionError("Invalid handshake response")
            
            # Send offer
            files_meta = [{"name": f.name, "size": f.size} for f in file_infos]
            send_json(sock, {
                "type": "OFFER",
                "offer_id": offer_id,
                "files": files_meta,
                "total_bytes": total_bytes,
            })
            
            # Wait for accept/reject
            decision = recv_json(sock)
            if decision.get("type") == "REJECTED":
                reason = decision.get("reason", "rejected")
                self.core.complete_transfer(transfer_id, TransferStatus.REJECTED, reason)
                sock.close()
                return
            
            if decision.get("type") != "ACCEPTED":
                raise ConnectionError("Invalid decision response")
            
            # Key exchange
            ke_msg = recv_json(sock)
            if ke_msg.get("type") != "KEY_EXCHANGE":
                raise ConnectionError("Key exchange failed")
            
            receiver_eph_pub = bytes.fromhex(ke_msg["eph_pub"])
            sender_eph_sk, sender_eph_pk = security.generate_ephemeral()
            salt = security.generate_salt()
            
            send_json(sock, {
                "type": "KEY_EXCHANGE_OK",
                "eph_pub": sender_eph_pk.hex(),
                "salt": salt.hex(),
            })
            
            # Derive session keys
            shared = security.compute_shared_secret(sender_eph_sk, receiver_eph_pub)
            encrypt_key, decrypt_key = security.derive_session_keys(shared, salt)
            channel = security.SecureChannel(encrypt_key, decrypt_key)
            
            self.core.update_transfer(transfer_id, status=TransferStatus.TRANSFERRING)
            
            # Send files
            chunk_size = self.core.cfg.get("network", "chunk_size", default=1048576)
            total_sent = 0
            
            for file_idx, file_info in enumerate(file_infos):
                with open(file_info.path, "rb") as f:
                    remaining = file_info.size
                    while remaining > 0:
                        chunk = f.read(min(chunk_size, remaining))
                        if not chunk:
                            break
                        
                        encrypted = channel.encrypt(chunk)
                        send_bytes(sock, encrypted)
                        
                        total_sent += len(chunk)
                        remaining -= len(chunk)
                        
                        self.core.update_transfer(
                            transfer_id,
                            transferred_bytes=total_sent,
                            current_file_index=file_idx,
                        )
                
                # Wait for file ACK
                ack = recv_json(sock)
                if ack.get("type") != "FILE_ACK":
                    raise ConnectionError("File acknowledgment failed")
            
            # Wait for DONE
            done = recv_json(sock)
            if done.get("type") != "DONE":
                raise ConnectionError("Transfer completion failed")
            
            self.core.complete_transfer(transfer_id, TransferStatus.COMPLETED)
            
        except Exception as e:
            self.core.complete_transfer(transfer_id, TransferStatus.ERROR, str(e))
        
        finally:
            if sock:
                try:
                    sock.close()
                except Exception:
                    pass
