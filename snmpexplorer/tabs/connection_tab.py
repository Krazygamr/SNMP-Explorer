from __future__ import annotations

import os
import tkinter as tk
from tkinter import ttk, messagebox

from common.context import AppState
from common.yaml_rt import yaml_load
from common.sshio import ssh_exec, sftp_read

# Optional profile helpers
try:
    from profile_integration import (
        merge_save_device_to_profile,
        load_device_from_profile,
    )
    _HAS_PROFILE_HELPERS = True
except Exception:
    _HAS_PROFILE_HELPERS = False


class ConnectionTab(ttk.Frame):
    """
    Connection / Pull Tab

    - Binds to AppState (self.state) and edits self.state.ssh fields.
    - Pulls /etc/snmp_exporter/snmp.yml and /etc/prometheus/prometheus.yml.
    - Loads parsed YAML into self.state.snmp_doc / self.state.prom_doc.
    - Writes workspace copies and updates self.state.snmp_yml_path / prom_yml_path.
    - Emits <<ConfigsPulled>> on success.
    - Session profile support (host/user/password).
    """

    def __init__(self, parent, state: AppState):
        super().__init__(parent)
        self.state = state

        s = self.state.ssh
        self.var_host = tk.StringVar(value=getattr(s, "host", ""))
        self.var_user = tk.StringVar(value=getattr(s, "username", ""))
        self.var_pass = tk.StringVar(value=getattr(s, "password", ""))
        self.var_key  = tk.StringVar(value=getattr(s, "key_path", ""))

        self.var_snmp = tk.StringVar(value=getattr(s, "snmp_path", "/etc/snmp_exporter/snmp.yml"))
        self.var_prom = tk.StringVar(value=getattr(s, "prom_path", "/etc/prometheus/prometheus.yml"))
        self.var_svc_snmp = tk.StringVar(value=getattr(s, "snmp_service", "snmp_exporter"))
        self.var_svc_prom = tk.StringVar(value=getattr(s, "prom_service", "prometheus"))

        # Workspace where pulled files are written for other tabs to read
        self._workspace = os.path.join(os.path.expanduser("~"), ".snmpexplorer", "workspace")
        os.makedirs(self._workspace, exist_ok=True)

        # Profile JSON path (used for saving/loading SSH creds)
        self.var_profile_path = tk.StringVar(
            value=os.path.join(os.path.expanduser("~"), ".snmpexplorer", "session.json")
        )

        self._build()

    # ---------------------------------------------------------------------
    # UI
    # ---------------------------------------------------------------------
    def _build(self):
        outer = ttk.Frame(self)
        outer.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        ttk.Label(outer, text="1) Connect & Pull SNMP/Prometheus Configs", font=("Segoe UI", 12, "bold")).pack(
            anchor="w", pady=(0, 8)
        )

        row1 = ttk.Frame(outer); row1.pack(fill=tk.X, pady=(0, 6))
        ttk.Label(row1, text="Host").pack(side=tk.LEFT)
        ttk.Entry(row1, textvariable=self.var_host, width=24).pack(side=tk.LEFT, padx=(4, 12))

        ttk.Label(row1, text="User").pack(side=tk.LEFT)
        ttk.Entry(row1, textvariable=self.var_user, width=18).pack(side=tk.LEFT, padx=(4, 12))

        ttk.Label(row1, text="Password").pack(side=tk.LEFT)
        ttk.Entry(row1, textvariable=self.var_pass, show="•", width=18).pack(side=tk.LEFT, padx=(4, 12))

        ttk.Label(row1, text="Key").pack(side=tk.LEFT)
        ttk.Entry(row1, textvariable=self.var_key, width=28).pack(side=tk.LEFT, padx=(4, 0))

        row2 = ttk.Frame(outer); row2.pack(fill=tk.X, pady=(6, 6))
        ttk.Label(row2, text="snmp.yml").pack(side=tk.LEFT)
        ttk.Entry(row2, textvariable=self.var_snmp, width=48).pack(side=tk.LEFT, padx=(4, 12))

        ttk.Label(row2, text="prometheus.yml").pack(side=tk.LEFT)
        ttk.Entry(row2, textvariable=self.var_prom, width=48).pack(side=tk.LEFT, padx=(4, 0))

        row3 = ttk.Frame(outer); row3.pack(fill=tk.X, pady=(0, 6))
        ttk.Label(row3, text="snmp_exporter service").pack(side=tk.LEFT)
        ttk.Entry(row3, textvariable=self.var_svc_snmp, width=24).pack(side=tk.LEFT, padx=(4, 12))

        ttk.Label(row3, text="prometheus service").pack(side=tk.LEFT)
        ttk.Entry(row3, textvariable=self.var_svc_prom, width=24).pack(side=tk.LEFT, padx=(4, 0))

        row_btns = ttk.Frame(outer); row_btns.pack(fill=tk.X, pady=(8, 6))
        ttk.Button(row_btns, text="Test SSH", command=self.on_test_ssh).pack(side=tk.LEFT)
        ttk.Button(row_btns, text="Pull snmp.yml", command=self.on_pull_snmp).pack(side=tk.LEFT, padx=(8, 0))
        ttk.Button(row_btns, text="Pull both (snmp.yml + prometheus.yml)", command=self.on_pull_both).pack(side=tk.LEFT, padx=(8, 0))

        row_prof = ttk.Frame(outer); row_prof.pack(fill=tk.X, pady=(10, 6))
        ttk.Label(row_prof, text="Profile File").pack(side=tk.LEFT)
        ttk.Entry(row_prof, textvariable=self.var_profile_path, width=60).pack(side=tk.LEFT, padx=(4, 8))
        ttk.Button(row_prof, text="Load Device From Profile", command=self._on_load_device_from_profile).pack(side=tk.LEFT)
        ttk.Button(row_prof, text="Save Device To Profile", command=self._on_save_device_to_profile).pack(side=tk.LEFT, padx=(8,0))

        self._lbl_status = ttk.Label(outer, text="", foreground="#227722")
        self._lbl_status.pack(anchor="w", pady=(8, 4))

        self._txt_snmp = tk.Text(outer, height=10); self._txt_snmp.pack(fill=tk.BOTH, expand=True, pady=(0, 6))
        self._txt_prom = tk.Text(outer, height=10); self._txt_prom.pack(fill=tk.BOTH, expand=True, pady=(0, 0))

    # ---------------------------------------------------------------------
    # Profile actions
    # ---------------------------------------------------------------------
    def _on_load_device_from_profile(self):
        """
        Load host/user/password from the profile file.
        Tries profile_integration first; if no password returned,
        falls back to reading our JSON keys.
        """
        path = (self.var_profile_path.get() or "").strip()
        if not path or not os.path.exists(path):
            messagebox.showwarning("Profile", "No profile file found at the given path.")
            return

        host = user = pwd = None

        # Try helper first (may return tuple or dict; some builds omit password)
        if _HAS_PROFILE_HELPERS:
            try:
                data = load_device_from_profile(path)
                if isinstance(data, dict):
                    host = data.get("host") or data.get("device_host") or host
                    user = data.get("user") or data.get("device_user") or user
                    # Many helper versions DO NOT return password; keep pwd=None here
                    pwd  = data.get("password") or data.get("ssh_password") or pwd
                elif isinstance(data, (list, tuple)):
                    if len(data) > 0: host = data[0] or host
                    if len(data) > 1: user = data[1] or user
                    if len(data) > 2: pwd  = data[2] or pwd
            except Exception as e:
                # Non-fatal — we’ll try JSON fallback next
                messagebox.showwarning("Profile", f"Encrypted load failed, trying JSON fallback:\n{e}")

        # If we still lack anything (especially password), use the JSON fallback
        try:
            import json
            with open(path, "r", encoding="utf-8") as f:
                j = json.load(f) or {}
            sec = j.get("device") or j.get("ssh") or j
            host = host or sec.get("host")
            user = user or sec.get("user") or sec.get("username")
            pwd  = pwd  or sec.get("ssh_password") or sec.get("password")
        except Exception:
            # Ignore JSON read errors here; we might already have enough from helper
            pass

        # Apply to UI + state
        if host: self.var_host.set(host);   self.state.ssh.host = host
        if user: self.var_user.set(user);   self.state.ssh.username = user
        if pwd:  self.var_pass.set(pwd);    self.state.ssh.password = pwd

        if not (host or user or pwd):
            messagebox.showwarning("Profile", "No device credentials found in profile.")
        else:
            messagebox.showinfo("Profile", "Device fields loaded from profile.")
            self._emit_profile_changed()


    def _on_save_device_to_profile(self):
        """
        Save host/user/password into the profile file via profile_integration,
        and also write a simple JSON fallback so password can be re-loaded.
        """
        path = (self.var_profile_path.get() or "").strip()
        if not path:
            messagebox.showwarning("Profile", "Provide a profile path.")
            return

        # First: try helper (encrypted/profile-managed)
        if _HAS_PROFILE_HELPERS:
            try:
                # Ask for the profile password so helper can write
                merge_save_device_to_profile(
                    parent_widget=self,
                    profile_path=path,
                    device_host=(self.var_host.get() or "").strip(),
                    device_user=(self.var_user.get() or "").strip(),
                    ask_password=True,            # IMPORTANT: allow helper to prompt
                    ssh_password=self.var_pass.get() or "",
                )
            except Exception as e:
                messagebox.showwarning("Profile", f"Encrypted save failed, will still write JSON fallback:\n{e}")

        # Second: always write a plain JSON fallback so we can load reliably later
        try:
            import json
            os.makedirs(os.path.dirname(path), exist_ok=True)
            # Merge/update existing file (if any) without clobbering other sections
            existing = {}
            if os.path.exists(path):
                try:
                    with open(path, "r", encoding="utf-8") as f:
                        existing = json.load(f) or {}
                except Exception:
                    existing = {}

            existing.setdefault("device", {})
            existing["device"].update({
                "host": (self.var_host.get() or "").strip(),
                "user": (self.var_user.get() or "").strip(),
                "ssh_password": self.var_pass.get() or "",
            })

            with open(path, "w", encoding="utf-8") as f:
                json.dump(existing, f, indent=2)
            messagebox.showinfo("Profile", f"Device host/user/password saved to:\n{path}")
        except Exception as e:
            messagebox.showerror("Profile", f"Failed to write JSON fallback:\n{e}")

    # ---------------------------------------------------------------------
    # SSH actions
    # ---------------------------------------------------------------------
    def _sync_state_from_ui(self) -> None:
        s = self.state.ssh
        s.host = (self.var_host.get() or "").strip()
        s.username = (self.var_user.get() or "").strip()
        s.password = self.var_pass.get()
        s.key_path = (self.var_key.get() or "").strip()
        s.snmp_path = (self.var_snmp.get() or "").strip()
        s.prom_path = (self.var_prom.get() or "").strip()
        s.snmp_service = (self.var_svc_snmp.get() or "").strip()
        s.prom_service = (self.var_svc_prom.get() or "").strip()

        # Share host for other tabs if they want to prefill anything
        self.state.last_host = s.host
        # Notify other tabs that SSH profile fields changed
        self.event_generate("<<SshProfileChanged>>", when="tail")

    def _emit_profile_changed(self):
        self.event_generate("<<SshProfileChanged>>", when="tail")

    def on_test_ssh(self):
        try:
            self._sync_state_from_ui()
            code, out, err = ssh_exec(self.state.ssh, "echo ok && whoami && hostname")
            if code == 0 and "ok" in out:
                messagebox.showinfo("SSH OK", out)
            else:
                messagebox.showerror("SSH Error", err or out or "SSH test failed.")
        except Exception as e:
            messagebox.showerror("SSH Error", str(e))

    # ---------------------------------------------------------------------
    # Pull logic + workspace handoff
    # ---------------------------------------------------------------------
    def _workspace_write(self, filename: str, text: str) -> str:
        path = os.path.join(self._workspace, filename)
        with open(path, "w", encoding="utf-8") as f:
            f.write(text or "")
        return path

    def _post_pull_common(self, snmp_text: str, prom_text: str | None):
        """
        After pulling, write local copies, update state paths and docs,
        update preview text boxes, and notify other tabs.
        """
        # Write local workspace copies other tabs can read
        snmp_local = self._workspace_write("snmp.yml", snmp_text)
        self.state.snmp_yml_path = snmp_local

        prom_local = None
        if prom_text is not None:
            prom_local = self._workspace_write("prometheus.yml", prom_text)
            self.state.prom_yml_path = prom_local

        # Parse YAML into state docs
        try:
            self.state.snmp_doc = yaml_load(snmp_text)
        except Exception:
            self.state.snmp_doc = None
        try:
            if prom_text:
                self.state.prom_doc = yaml_load(prom_text)
            else:
                self.state.prom_doc = None
        except Exception:
            self.state.prom_doc = None

        # Update preview UI
        self._txt_snmp.delete("1.0", tk.END); self._txt_snmp.insert(tk.END, snmp_text)
        self._txt_prom.delete("1.0", tk.END)
        if prom_text:
            self._txt_prom.insert(tk.END, prom_text)

        # Notify other tabs *after* files exist and state is set
        self.event_generate("<<ConfigsPulled>>", when="tail")

    def on_pull_snmp(self):
        try:
            self._sync_state_from_ui()
            # Pull snmp.yml
            snmp_text = sftp_read(self.state.ssh, self.state.ssh.snmp_path)
            self.state.orig_snmp_text = snmp_text

            self._lbl_status.config(text="Pulled snmp.yml successfully.")
            self._post_pull_common(snmp_text=snmp_text, prom_text=None)
        except Exception as e:
            messagebox.showerror("Pull Error", str(e))

    def on_pull_both(self):
        try:
            self._sync_state_from_ui()
            # Pull snmp.yml
            snmp_text = sftp_read(self.state.ssh, self.state.ssh.snmp_path)
            self.state.orig_snmp_text = snmp_text
            # Pull prometheus.yml (best-effort)
            try:
                prom_text = sftp_read(self.state.ssh, self.state.ssh.prom_path)
            except Exception:
                prom_text = ""
            self.state.orig_prom_text = prom_text

            self._lbl_status.config(text="Pulled snmp.yml and prometheus.yml.")
            self._post_pull_common(snmp_text=snmp_text, prom_text=prom_text)
        except Exception as e:
            messagebox.showerror("Pull Error", str(e))
