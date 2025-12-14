from __future__ import annotations

import threading
import time
from typing import Dict, List, Optional

import storage
import security
from core import Core, Event, Peer, TransferProgress
from network import DiscoveryService, TransferService, IncomingOffer
from ui import AppUI, UIHooks


class App:
    def __init__(self, root) -> None:
        self.core = Core()

        # services
        self.discovery = DiscoveryService(self.core)
        self.transfer_service = TransferService(self.core, self._on_incoming_offer)

        # UI hooks
        hooks = UIHooks(
            on_send_clicked=self.send_files_to_peers,
            on_toggle_availability=self.toggle_availability,
            on_change_username=self.change_username,
            on_change_download_dir=self.change_download_dir,
            on_refresh_history=self.refresh_history,
        )
        self.ui = AppUI(root, hooks)

        # incoming offers waiting user decision
        self._offers_lock = threading.RLock()
        self._pending_offers: Dict[str, IncomingOffer] = {}

        self._running = True

    def start(self) -> None:
        # ensure identity exists
        security.ensure_identity_keypair()

        # start services
        self.discovery.start()
        self.transfer_service.start()

        # initial UI state
        prof = self.core.get_profile()
        self.ui.set_profile_label(prof["username"], prof["availability"], prof["download_dir"])
        self.ui.update_peers(self.core.list_peers())
        self.refresh_history()

        # periodic UI polling
        self.ui.root.after(200, self._tick)

    def stop(self) -> None:
        self._running = False
        self.discovery.stop()
        self.transfer_service.stop()

    # ---------------- UI actions ----------------

    def toggle_availability(self) -> None:
        prof = self.core.get_profile()
        new = "busy" if prof["availability"] == "available" else "available"
        self.core.set_availability(new)

    def change_username(self, username: str) -> None:
        self.core.set_username(username)

    def change_download_dir(self, download_dir: str) -> None:
        self.core.set_download_dir(download_dir)

    def refresh_history(self) -> None:
        self.ui.render_history(self.core.load_history())

    def send_files_to_peers(self, peer_ids: List[str], file_paths: List[str]) -> None:
        # enforce limits: max receivers per transfer and max parallel transfers.
        limits = self.core.limits
        peer_ids = peer_ids[: int(limits["max_receivers_per_transfer"])]

        peers_map = {p.peer_id: p for p in self.core.list_peers()}
        peers = [peers_map[pid] for pid in peer_ids if pid in peers_map]
        if not peers:
            return

        transfer_id = self.core.new_transfer_id()

        # compute total bytes (best-effort)
        total = 0
        good_files: List[str] = []
        for p in file_paths:
            try:
                st = __import__("os").stat(p)
                total += int(st.st_size)
                good_files.append(p)
            except Exception:
                pass

        # init in core for all receivers
        self.core.init_transfer(
            transfer_id,
            "send",
            [(p.peer_id, p.username) for p in peers],
            total,
        )

        # send to each receiver in own thread (service does it), but keep count modest
        # if too many, later we can add a scheduler queue; for now config keeps it safe.
        for p in peers:
            self.transfer_service.send_files(transfer_id, p.ip, p.tcp_port, p.peer_id, p.username, good_files)

    # ---------------- Incoming offers (UI prompt) ----------------

    def _on_incoming_offer(self, offer: IncomingOffer) -> None:
        # store and signal UI via core event
        with self._offers_lock:
            self._pending_offers[offer.transfer_id] = offer
        self.core.events.put(Event("incoming_offer", {
            "transfer_id": offer.transfer_id,
            "sender_name": offer.sender_name,
            "file_count": len(offer.files),
            "total_bytes": offer.total_bytes,
        }))

    def _prompt_accept_reject(self, offer: IncomingOffer) -> None:
        import tkinter.messagebox as mb

        cfg = self.core.cfg
        trust_mode = cfg["security"]["trust_mode"]

        # Trust checks (TOFU)
        ok, reason = security.check_or_pin_peer(offer.sender_peer_id, offer.sender_pub) if offer.sender_pub else (False, "untrusted")

        if trust_mode == "deny_unknown" and not ok:
            self.transfer_service.reject_offer(offer, reason="untrusted")
            return

        if trust_mode == "prompt" and not ok:
            fp = security.fingerprint_pubkey(offer.sender_pub) if offer.sender_pub else "unknown"
            ans = mb.askyesno(
                "Trust new peer?",
                f"Peer '{offer.sender_name}' is not trusted yet.\n"
                f"Fingerprint: {fp[:16]}...\n\nTrust and continue?",
            )
            if not ans:
                self.transfer_service.reject_offer(offer, reason="untrusted")
                return
            if offer.sender_pub:
                security.pin_peer(offer.sender_peer_id, offer.sender_pub)

        files_kb = int(offer.total_bytes / 1024)
        ans = mb.askyesno(
            "Incoming transfer",
            f"'{offer.sender_name}' wants to send {len(offer.files)} file(s)\n"
            f"Total size: {files_kb} KB\n\nAccept?",
        )
        if not ans:
            self.transfer_service.reject_offer(offer, reason="rejected_by_user")
            return

        # If we are busy, auto reject (as requested)
        if self.core.get_profile()["availability"] == "busy":
            self.transfer_service.reject_offer(offer, reason="receiver_busy")
            return

        self.transfer_service.accept_offer(offer)

    # ---------------- Main tick (UI thread) ----------------

    def _tick(self) -> None:
        if not self._running:
            return

        # prune stale peers
        self.core.prune_peers()
        self.ui.update_peers(self.core.list_peers())

        # process events
        while True:
            try:
                ev = self.core.events.get_nowait()
            except Exception:
                break

            if ev.type == "profile_changed":
                prof = ev.data["profile"]
                self.ui.set_profile_label(prof["username"], prof["availability"], prof["download_dir"])

            elif ev.type == "transfer_added":
                transfer_id = ev.data["transfer_id"]
                items = ev.data["items"]
                self.ui.add_transfer_rows(transfer_id, items)

            elif ev.type == "transfer_progress":
                tid = ev.data["transfer_id"]
                pid = ev.data["peer_id"]
                t = self.core.transfers.get(tid, {})
                pr = t.get(pid)
                if pr:
                    self.ui.update_transfer_progress(pr)

            elif ev.type == "history_updated":
                self.refresh_history()

            elif ev.type == "incoming_offer":
                tid = ev.data["transfer_id"]
                with self._offers_lock:
                    offer = self._pending_offers.pop(tid, None)
                if offer:
                    self._prompt_accept_reject(offer)

        # next tick
        self.ui.root.after(200, self._tick)
