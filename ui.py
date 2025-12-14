from __future__ import annotations

import os
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional

from core import Peer, TransferProgress


@dataclass
class UIHooks:
    on_send_clicked: Callable[[List[str], List[str]], None]   # (peer_ids, file_paths)
    on_toggle_availability: Callable[[], None]
    on_change_username: Callable[[str], None]
    on_change_download_dir: Callable[[str], None]
    on_refresh_history: Callable[[], None]


class AppUI:
    def __init__(self, root: tk.Tk, hooks: UIHooks) -> None:
        self.root = root
        self.hooks = hooks

        self.root.title("LAN File Transfer")
        self.root.geometry("980x620")

        self.peers: Dict[str, Peer] = {}
        self.selected_peers: List[str] = []
        self.selected_files: List[str] = []
        self.transfer_rows: Dict[str, Dict[str, ttk.Progressbar]] = {}  # transfer_id -> peer_id -> bar

        self._build()

    def _build(self) -> None:
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)

        main = ttk.Frame(self.root, padding=10)
        main.grid(row=0, column=0, sticky="nsew")
        main.columnconfigure(0, weight=1)
        main.columnconfigure(1, weight=2)
        main.rowconfigure(1, weight=1)

        # Top bar
        top = ttk.Frame(main)
        top.grid(row=0, column=0, columnspan=2, sticky="ew")
        top.columnconfigure(6, weight=1)

        self.lbl_profile = ttk.Label(top, text="Profile: -")
        self.lbl_profile.grid(row=0, column=0, sticky="w", padx=(0, 12))

        ttk.Button(top, text="Toggle Busy/Available", command=self.hooks.on_toggle_availability).grid(row=0, column=1, padx=6)
        ttk.Button(top, text="Change Username", command=self._prompt_username).grid(row=0, column=2, padx=6)
        ttk.Button(top, text="Change Download Folder", command=self._pick_download_dir).grid(row=0, column=3, padx=6)
        ttk.Button(top, text="History Refresh", command=self.hooks.on_refresh_history).grid(row=0, column=4, padx=6)

        # Left: peers + files
        left = ttk.Frame(main)
        left.grid(row=1, column=0, sticky="nsew", padx=(0, 10))
        left.rowconfigure(1, weight=1)
        left.rowconfigure(3, weight=1)
        left.columnconfigure(0, weight=1)

        ttk.Label(left, text="Peers in LAN").grid(row=0, column=0, sticky="w")
        self.peers_list = tk.Listbox(left, height=10)
        self.peers_list.grid(row=1, column=0, sticky="nsew")
        self.peers_list.bind("<<ListboxSelect>>", self._on_peer_click)
        self.peers_list.bind("<Double-Button-1>", self._on_peer_double)

        btns = ttk.Frame(left)
        btns.grid(row=2, column=0, sticky="ew", pady=6)
        ttk.Button(btns, text="Send to selected", command=self._send).pack(side="left")
        ttk.Button(btns, text="Clear selection", command=self._clear_peer_selection).pack(side="left", padx=6)

        ttk.Label(left, text="Files to send").grid(row=3, column=0, sticky="w", pady=(10, 0))
        self.files_list = tk.Listbox(left, height=10)
        self.files_list.grid(row=4, column=0, sticky="nsew")
        self.files_list.bind("<Double-Button-1>", self._on_file_double)

        fbtns = ttk.Frame(left)
        fbtns.grid(row=5, column=0, sticky="ew", pady=6)
        ttk.Button(fbtns, text="Add files", command=self._add_files).pack(side="left")
        ttk.Button(fbtns, text="Add folder", command=self._add_folder).pack(side="left", padx=6)
        ttk.Button(fbtns, text="Clear files", command=self._clear_files).pack(side="left", padx=6)

        # Right: transfers + history
        right = ttk.Frame(main)
        right.grid(row=1, column=1, sticky="nsew")
        right.rowconfigure(1, weight=1)
        right.rowconfigure(3, weight=1)
        right.columnconfigure(0, weight=1)

        ttk.Label(right, text="Active Transfers").grid(row=0, column=0, sticky="w")
        self.transfers_frame = ttk.Frame(right)
        self.transfers_frame.grid(row=1, column=0, sticky="nsew")
        self.transfers_frame.columnconfigure(0, weight=1)

        ttk.Separator(right, orient="horizontal").grid(row=2, column=0, sticky="ew", pady=8)

        ttk.Label(right, text="History").grid(row=3, column=0, sticky="w")
        self.history = tk.Text(right, height=10, wrap="word")
        self.history.grid(row=4, column=0, sticky="nsew")
        self.history.configure(state="disabled")

    # ---------------- UI actions ----------------

    def _prompt_username(self) -> None:
        win = tk.Toplevel(self.root)
        win.title("Change Username")
        win.geometry("320x120")
        win.transient(self.root)
        win.grab_set()

        ttk.Label(win, text="New username:").pack(pady=10)
        ent = ttk.Entry(win)
        ent.pack(fill="x", padx=10)

        def ok():
            name = ent.get().strip()
            if not name:
                messagebox.showwarning("Invalid", "Username cannot be empty.")
                return
            self.hooks.on_change_username(name)
            win.destroy()

        ttk.Button(win, text="OK", command=ok).pack(pady=10)

    def _pick_download_dir(self) -> None:
        d = filedialog.askdirectory(title="Choose download folder")
        if d:
            self.hooks.on_change_download_dir(d)

    def _on_peer_click(self, _evt) -> None:
        # single click selects peer (multi-select via ctrl/shift works too)
        sel = self.peers_list.curselection()
        self.selected_peers = [self._peer_id_by_index(i) for i in sel]

    def _on_peer_double(self, _evt) -> None:
        # double click unselect that peer
        i = self.peers_list.curselection()
        if not i:
            return
        idx = i[0]
        pid = self._peer_id_by_index(idx)
        try:
            self.selected_peers.remove(pid)
        except ValueError:
            pass
        self.peers_list.selection_clear(idx)

    def _peer_id_by_index(self, idx: int) -> str:
        # listbox item text starts with [A/B] name (ip) -> map by stable ordering
        ids = list(self.peers.keys())
        if idx < 0 or idx >= len(ids):
            return ""
        return ids[idx]

    def _add_files(self) -> None:
        paths = filedialog.askopenfilenames(title="Select files")
        for p in paths:
            if p and p not in self.selected_files:
                self.selected_files.append(p)
        self._render_files()

    def _add_folder(self) -> None:
        d = filedialog.askdirectory(title="Select folder")
        if not d:
            return
        for root, _dirs, files in os.walk(d):
            for f in files:
                p = os.path.join(root, f)
                if p not in self.selected_files:
                    self.selected_files.append(p)
        self._render_files()

    def _on_file_double(self, _evt) -> None:
        sel = self.files_list.curselection()
        if not sel:
            return
        idx = sel[0]
        if 0 <= idx < len(self.selected_files):
            del self.selected_files[idx]
        self._render_files()

    def _clear_files(self) -> None:
        self.selected_files = []
        self._render_files()

    def _clear_peer_selection(self) -> None:
        self.selected_peers = []
        self.peers_list.selection_clear(0, "end")

    def _send(self) -> None:
        if not self.selected_peers:
            messagebox.showinfo("No peers", "Select at least one peer.")
            return
        if not self.selected_files:
            messagebox.showinfo("No files", "Add at least one file.")
            return
        self.hooks.on_send_clicked(self.selected_peers, list(self.selected_files))

    # ---------------- UI updates from App ----------------

    def set_profile_label(self, username: str, availability: str, download_dir: str) -> None:
        self.lbl_profile.configure(text=f"Profile: {username} | {availability} | download: {download_dir}")

    def update_peers(self, peers: List[Peer]) -> None:
        # stable ordering by peer_id to map indices -> peer_id
        self.peers = {p.peer_id: p for p in sorted(peers, key=lambda x: x.peer_id)}
        self.peers_list.delete(0, "end")
        for p in self.peers.values():
            flag = "A" if p.availability == "available" else "B"
            self.peers_list.insert("end", f"[{flag}] {p.username} ({p.ip}:{p.tcp_port})")

    def add_transfer_rows(self, transfer_id: str, items: Dict[str, TransferProgress]) -> None:
        # A simple stacked view: one row per peer progress in the transfer
        row = ttk.LabelFrame(self.transfers_frame, text=f"Transfer {transfer_id[:8]}")
        row.pack(fill="x", pady=6)

        self.transfer_rows.setdefault(transfer_id, {})

        for peer_id, pr in items.items():
            line = ttk.Frame(row)
            line.pack(fill="x", pady=2)
            ttk.Label(line, text=f"{pr.direction.upper()} -> {pr.peer_name}", width=30).pack(side="left")

            bar = ttk.Progressbar(line, maximum=100)
            bar.pack(side="left", fill="x", expand=True, padx=6)

            lbl = ttk.Label(line, text="0% | 0 KB/s")
            lbl.pack(side="left")

            # store both bar and label
            self.transfer_rows[transfer_id][peer_id] = bar
            bar._status_label = lbl  # type: ignore[attr-defined]

    def update_transfer_progress(self, pr: TransferProgress) -> None:
        bars = self.transfer_rows.get(pr.transfer_id, {})
        bar = bars.get(pr.peer_id)
        if not bar:
            return
        pct = 0.0
        if pr.total_bytes > 0:
            pct = (pr.done_bytes / pr.total_bytes) * 100.0
        bar["value"] = max(0.0, min(100.0, pct))

        kbps = pr.avg_speed_bps / 1024.0
        status = pr.status
        label = getattr(bar, "_status_label", None)
        if label:
            label.configure(text=f"{pct:5.1f}% | {kbps:,.0f} KB/s | {status}")

    def render_history(self, rows: List[dict]) -> None:
        self.history.configure(state="normal")
        self.history.delete("1.0", "end")
        for r in reversed(rows[-200:]):
            line = (
                f"{r.get('timestamp_utc','')}  "
                f"{r.get('direction','')}  "
                f"{r.get('status','')}  "
                f"peers={r.get('peer_names',[])}  "
                f"files={r.get('file_count',0)}  "
                f"bytes={r.get('total_bytes',0)}  "
                f"avg={int(float(r.get('avg_speed_bps',0))/1024)}KB/s"
            )
            if r.get("error"):
                line += f"  err={r.get('error')}"
            self.history.insert("end", line + "\n")
        self.history.configure(state="disabled")

    def _render_files(self) -> None:
        self.files_list.delete(0, "end")
        for p in self.selected_files:
            self.files_list.insert("end", p)
