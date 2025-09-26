# tabs/installation_tab.py
import threading
import tkinter as tk
from tkinter import ttk, messagebox
from types import SimpleNamespace
import time, os, json, re
# add this near your other imports
from typing import Optional

from common.remote_install import (
    RemoteInstaller, InstallMode, OverwriteMode, SanityLevel,
    DEFAULT_PORTS, DEFAULT_PATHS, ResultTableModel
)
from common.context import AppState
from common.sshio import ssh_exec, sftp_write, _sudo_wrap

try:
    import yaml  # used locally to parse remote yml blobs we fetch via ssh
except Exception:
    yaml = None


def _resolve_profile_from_state(state: AppState):
    ssh = getattr(state, "ssh", None)
    if ssh and (getattr(ssh, "host", None) or getattr(ssh, "username", None)):
        return SimpleNamespace(
            name=getattr(state, "profile_name", "default"),
            host=getattr(ssh, "host", None),
            port=int(getattr(ssh, "port", 22)),
            username=getattr(ssh, "username", None),
            password=getattr(ssh, "password", None),
            key_path=getattr(ssh, "key_path", None),
            key_passphrase=getattr(ssh, "key_passphrase", None),
            disable_sudo=bool(getattr(ssh, "disable_sudo", False)),
        )
    candidates = ("get_active_profile", "get_profile", "active_profile",
                  "profile", "session", "session_profile", "current_profile")
    for cand in candidates:
        if hasattr(state, cand):
            val = getattr(state, cand)
            prof = val() if callable(val) else val
            if prof:
                if isinstance(prof, dict):
                    return SimpleNamespace(
                        name=prof.get("name") or "default",
                        host=prof.get("host"),
                        port=int(prof.get("port", 22)),
                        username=prof.get("username"),
                        password=prof.get("password"),
                        key_path=prof.get("key_path"),
                        key_passphrase=prof.get("key_passphrase"),
                        disable_sudo=bool(prof.get("disable_sudo", False)),
                    )
                return SimpleNamespace(
                    name=getattr(prof, "name", "default"),
                    host=getattr(prof, "host", None),
                    port=int(getattr(prof, "port", 22)),
                    username=getattr(prof, "username", None),
                    password=getattr(prof, "password", None),
                    key_path=getattr(prof, "key_path", None),
                    key_passphrase=getattr(prof, "key_passphrase", None),
                    disable_sudo=bool(getattr(prof, "disable_sudo", False)),
                )
    return SimpleNamespace(
        name=getattr(state, "profile_name", "default"),
        host=getattr(state, "host", None) or getattr(state, "ssh_host", None),
        port=int(getattr(state, "port", 22) or getattr(state, "ssh_port", 22)),
        username=getattr(state, "username", None) or getattr(state, "ssh_user", None),
        password=getattr(state, "password", None) or getattr(state, "ssh_password", None),
        key_path=getattr(state, "key_path", None) or getattr(state, "ssh_key_path", None),
        key_passphrase=getattr(state, "key_passphrase", None) or getattr(state, "ssh_key_passphrase", None),
        disable_sudo=bool(getattr(state, "disable_sudo", False)),
    )


class InstallationTab(ttk.Frame):
    def __init__(self, master, app_state: AppState):
        super().__init__(master)
        self.app_state = app_state
        self.installer = RemoteInstaller(app_state, profile_resolver=_resolve_profile_from_state)

        self._build_ui()
        self._wire_events()
        self.refresh()

    # ---------- public ----------
    def refresh(self):
        prof = _resolve_profile_from_state(self.app_state)
        if prof and prof.host:
            self.lbl_profile.configure(text=f"{prof.name}  {prof.username}@{prof.host}:{prof.port}")
        else:
            self.lbl_profile.configure(text="(no profile selected)")

    # ---------- UI ----------
    def _build_ui(self):
        self.columnconfigure(0, weight=1)
        self.rowconfigure(3, weight=1)

        # Session/Profile
        ctx = ttk.LabelFrame(self, text="Session Profile")
        ctx.grid(row=0, column=0, sticky="ew", padx=8, pady=(8, 4))
        ctx.columnconfigure(1, weight=1)
        ttk.Label(ctx, text="Active profile:").grid(row=0, column=0, sticky="w", padx=8, pady=6)
        self.lbl_profile = ttk.Label(ctx, text="(none)")
        self.lbl_profile.grid(row=0, column=1, sticky="w", padx=8, pady=6)
        self.btn_switch_profile = ttk.Button(ctx, text="Switch Profile (Connection tab)")
        self.btn_switch_profile.grid(row=0, column=2, sticky="e", padx=8, pady=6)

        # Action row
        cards = ttk.Frame(self)
        cards.grid(row=1, column=0, sticky="ew", padx=8, pady=4)
        cards.columnconfigure(0, weight=1)
        cards.columnconfigure(1, weight=1)

        # Verify card
        verify = ttk.LabelFrame(cards, text="Verify Installation")
        verify.grid(row=0, column=0, sticky="nsew", padx=(0, 4), pady=4)
        verify.columnconfigure(1, weight=1)

        self.var_sanity_level = tk.StringVar(value=SanityLevel.SANITY_SUITE.value)
        ttk.Label(verify, text="Checks:").grid(row=0, column=0, sticky="w", padx=8, pady=(8, 2))
        self.cbo_sanity = ttk.Combobox(verify, textvariable=self.var_sanity_level, state="readonly",
                                       values=[e.value for e in SanityLevel])
        self.cbo_sanity.grid(row=0, column=1, sticky="ew", padx=8, pady=(8, 2))

        # Additional system checks (dropdowns)
        add = ttk.LabelFrame(verify, text="Additional system checks")
        add.grid(row=1, column=0, columnspan=2, sticky="ew", padx=8, pady=(2, 6))
        add.columnconfigure(1, weight=1)

        self.var_chk_snmp = tk.StringVar(value="Enable")
        self.var_chk_stage = tk.StringVar(value="Enable")
        self.var_chk_sudo = tk.StringVar(value="Enable")
        self.var_chk_prom = tk.StringVar(value="Enable")     # NEW: Prometheus targets health
        self.var_chk_forti = tk.StringVar(value="Enable")    # NEW: FortiGate reachability

        for r, (label, var) in enumerate((
            ("SNMP writeability", self.var_chk_snmp),
            ("Staging directory", self.var_chk_stage),
            ("Sudo (non-interactive)", self.var_chk_sudo),
            ("Prometheus targets health", self.var_chk_prom),
            ("FortiGate SNMP reachability", self.var_chk_forti),
        )):
            ttk.Label(add, text=label + ":").grid(row=r, column=0, sticky="w", padx=6, pady=2)
            ttk.Combobox(add, textvariable=var, state="readonly",
                         values=("Enable", "Skip")).grid(row=r, column=1, sticky="ew", padx=6, pady=2)

        self.btn_verify = ttk.Button(verify, text="Run Verification")
        self.btn_verify.grid(row=2, column=0, sticky="w", padx=8, pady=(4, 6))
        self.btn_verify_dry = ttk.Button(verify, text="Dry-run")
        self.btn_verify_dry.grid(row=2, column=1, sticky="e", padx=8, pady=(4, 6))

        # Fixers
        self.btn_fix_snmp_perms = ttk.Button(verify, text="Fix SNMP write permissions")
        self.btn_fix_snmp_perms.grid(row=3, column=0, columnspan=2, sticky="w", padx=8, pady=(2, 6))

        self.btn_fix_stage = ttk.Button(verify, text="Fix staging dir")
        self.btn_fix_stage.grid(row=4, column=0, columnspan=2, sticky="w", padx=8, pady=(0, 6))

        self.btn_fix_unit = ttk.Button(verify, text="Repair snmp_exporter unit (config flag)")  # NEW
        self.btn_fix_unit.grid(row=5, column=0, columnspan=2, sticky="w", padx=8, pady=(0, 8))

        self.btn_test_forti = ttk.Button(verify, text="Test FortiGate SNMP now")  # NEW
        self.btn_test_forti.grid(row=6, column=0, columnspan=2, sticky="w", padx=8, pady=(0, 8))

        # Install/Upgrade card
        install = ttk.LabelFrame(cards, text="Install / Upgrade")
        install.grid(row=0, column=1, sticky="nsew", padx=(4, 0), pady=4)
        install.columnconfigure(1, weight=1)

        self.var_install_mode = tk.StringVar(value=InstallMode.INSTALL_UPGRADE.value)
        ttk.Label(install, text="Mode:").grid(row=0, column=0, sticky="w", padx=8, pady=(8, 2))
        self.cbo_install_mode = ttk.Combobox(install, textvariable=self.var_install_mode, state="readonly",
                                             values=[e.value for e in InstallMode])
        self.cbo_install_mode.grid(row=0, column=1, sticky="ew", padx=8, pady=(8, 2))

        self.var_overwrite = tk.StringVar(value=OverwriteMode.PRESERVE.value)
        self.lbl_overwrite = ttk.Label(install, text="Overwrite Options:")
        self.cbo_overwrite = ttk.Combobox(install, textvariable=self.var_overwrite, state="readonly",
                                          values=[e.value for e in OverwriteMode])

        self.var_node_exporter = tk.BooleanVar(value=True)
        ttk.Checkbutton(install, text="Also install Node Exporter",
                        variable=self.var_node_exporter).grid(row=2, column=0, columnspan=2, sticky="w", padx=8, pady=2)
        self.var_pin_versions = tk.BooleanVar(value=False)
        ttk.Checkbutton(install, text="Pin versions",
                        variable=self.var_pin_versions).grid(row=3, column=0, columnspan=2, sticky="w", padx=8, pady=2)
        self.var_enable_boot = tk.BooleanVar(value=True)
        ttk.Checkbutton(install, text="Enable services at boot",
                        variable=self.var_enable_boot).grid(row=4, column=0, columnspan=2, sticky="w", padx=8, pady=2)
        self.var_open_firewall = tk.BooleanVar(value=False)
        ttk.Checkbutton(install, text="Open firewall ports (ufw)",
                        variable=self.var_open_firewall).grid(row=5, column=0, columnspan=2, sticky="w", padx=8, pady=2)

        self.btn_plan = ttk.Button(install, text="Plan (Dry-run)")
        self.btn_plan.grid(row=6, column=0, sticky="w", padx=8, pady=6)
        self.btn_execute = ttk.Button(install, text="Execute")
        self.btn_execute.grid(row=6, column=1, sticky="e", padx=8, pady=6)

        # Advanced
        adv = ttk.LabelFrame(self, text="Advanced (paths, ports)")
        adv.grid(row=2, column=0, sticky="ew", padx=8, pady=4)
        adv.columnconfigure(1, weight=1)

        ttk.Label(adv, text="SNMP Exporter config path:").grid(row=0, column=0, sticky="w", padx=8, pady=2)
        self.ent_snmp_path = ttk.Entry(adv); self.ent_snmp_path.grid(row=0, column=1, sticky="ew", padx=8, pady=2)

        ttk.Label(adv, text="Prometheus config path:").grid(row=1, column=0, sticky="w", padx=8, pady=2)
        self.ent_prom_path = ttk.Entry(adv); self.ent_prom_path.grid(row=1, column=1, sticky="ew", padx=8, pady=2)

        ttk.Label(adv, text="Grafana ini path:").grid(row=2, column=0, sticky="w", padx=8, pady=2)
        self.ent_graf_ini = ttk.Entry(adv); self.ent_graf_ini.grid(row=2, column=1, sticky="ew", padx=8, pady=2)

        ttk.Label(adv, text="Staging dir:").grid(row=3, column=0, sticky="w", padx=8, pady=2)
        self.ent_stage_dir = ttk.Entry(adv); self.ent_stage_dir.grid(row=3, column=1, sticky="ew", padx=8, pady=2)

        ttk.Label(adv, text="Ports (3000/9090/9116/9100):").grid(row=4, column=0, sticky="w", padx=8, pady=2)
        self.ent_ports = ttk.Entry(adv); self.ent_ports.grid(row=4, column=1, sticky="ew", padx=8, pady=2)

        # Defaults
        snmp_default = getattr(getattr(self.app_state, "ssh", SimpleNamespace()), "snmp_path", DEFAULT_PATHS["snmp_yml"])
        self.ent_snmp_path.insert(0, snmp_default)
        self.ent_prom_path.insert(0, DEFAULT_PATHS["prom_yml"])
        self.ent_graf_ini.insert(0, DEFAULT_PATHS["grafana_ini"])
        self.ent_stage_dir.insert(0, "/var/lib/snmptool")
        self.ent_ports.insert(0, ",".join(str(DEFAULT_PORTS[k]) for k in ("grafana", "prom", "snmp", "node")))

        # Results + Log
        bottom = ttk.Panedwindow(self, orient="vertical")
        bottom.grid(row=3, column=0, sticky="nsew", padx=8, pady=(4, 8))
        self.rowconfigure(3, weight=1)

        tbl_frame = ttk.LabelFrame(bottom, text="Results")
        tbl_frame.columnconfigure(0, weight=1); tbl_frame.rowconfigure(0, weight=1)

        self.tree = ttk.Treeview(
            tbl_frame, columns=("component", "check", "status", "detail"),
            show="headings", height=10
        )
        for c, w in (("component", 180), ("check", 360), ("status", 90), ("detail", 900)):
            self.tree.heading(c, text=c.title()); self.tree.column(c, width=w, anchor="w", stretch=(c == "detail"))
        ysb = ttk.Scrollbar(tbl_frame, orient="vertical", command=self.tree.yview)
        xsb = ttk.Scrollbar(tbl_frame, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscroll=ysb.set, xscroll=xsb.set)
        self.tree.grid(row=0, column=0, sticky="nsew"); ysb.grid(row=0, column=1, sticky="ns"); xsb.grid(row=1, column=0, sticky="ew")

        # Show detail in Activity Log when you click/activate a row
        self.tree.bind("<<TreeviewSelect>>", self._on_result_select)
        self.tree.bind("<Double-1>", self._on_result_activate)
        self.tree.bind("<Return>", self._on_result_activate)

        log_frame = ttk.LabelFrame(bottom, text="Activity Log")
        log_frame.columnconfigure(0, weight=1); log_frame.rowconfigure(0, weight=1)
        self.txt_log = tk.Text(log_frame, height=10, wrap="word"); self.txt_log.grid(row=0, column=0, sticky="nsew")
        ysb2 = ttk.Scrollbar(log_frame, orient="vertical", command=self.txt_log.yview)
        self.txt_log.configure(yscrollcommand=ysb2.set); ysb2.grid(row=0, column=1, sticky="ns")

        bottom.add(tbl_frame, weight=3); bottom.add(log_frame, weight=2)

        # Export row
        exp = ttk.Frame(self); exp.grid(row=4, column=0, sticky="ew", padx=8, pady=(0, 8))
        self.btn_save_txt = ttk.Button(exp, text="Save Transcript (.txt)", command=self._save_txt); self.btn_save_txt.pack(side="left")
        self.btn_save_json = ttk.Button(exp, text="Download Report (.json)", command=self._save_json); self.btn_save_json.pack(side="left", padx=8)

    def _wire_events(self):
        self.cbo_install_mode.bind("<<ComboboxSelected>>", self._toggle_overwrite_controls)
        self.btn_switch_profile.configure(command=self._goto_connection_tab)
        self.btn_verify.configure(command=lambda: self._thread(self._run_verify, dry=False))
        self.btn_verify_dry.configure(command=lambda: self._thread(self._run_verify, dry=True))
        self.btn_plan.configure(command=lambda: self._thread(self._run_install, plan_only=True))
        self.btn_execute.configure(command=lambda: self._thread(self._run_install, plan_only=False))
        self.btn_fix_snmp_perms.configure(command=lambda: self._thread(self._fix_snmp_permissions))
        self.btn_fix_stage.configure(command=lambda: self._thread(self._fix_staging_dir))
        self.btn_fix_unit.configure(command=lambda: self._thread(self._fix_snmp_unit))     # NEW
        self.btn_test_forti.configure(command=lambda: self._thread(self._quick_test_fortigate))  # NEW

    # ---------- actions ----------
    def _goto_connection_tab(self):
        try:
            nb = self.master
            if hasattr(nb, "tabs") and "Connection" in nb.tabs:
                nb.select(nb.tabs["Connection"])
            else:
                nb.select(0)
        except Exception:
            messagebox.showinfo("Switch Profile", "Open the Connection tab to change profiles.")

    def _toggle_overwrite_controls(self, *_):
        if self.var_install_mode.get() == InstallMode.OVERWRITE.value:
            self.lbl_overwrite.grid(row=1, column=0, sticky="w", padx=8, pady=2)
            self.cbo_overwrite.grid(row=1, column=1, sticky="ew", padx=8, pady=2)
        else:
            self.lbl_overwrite.grid_forget(); self.cbo_overwrite.grid_forget()

    def _thread(self, fn, **kwargs):
        t = threading.Thread(target=fn, kwargs=kwargs, daemon=True); t.start()

    def _run_verify(self, dry: bool):
        self._clear_results(); self._log("== Verification started ==")
        opts = self._gather_opts(); level = SanityLevel(self.var_sanity_level.get())

        res = self.installer.verify_stack(opts, level=level, dry_run=dry, log_cb=self._log, table_cb=self._add_rows)

        # Extra checks
        if self.var_chk_snmp.get() == "Enable":
            ok_w, _detail_w, rows_w = self._check_snmp_writable(opts["paths"]["snmp_yml"])
            for r in rows_w: self._add_row(r.component, r.check, r.status, r.detail)
            # Quiet service-active row
            svc = getattr(getattr(self.app_state, "ssh", None), "snmp_service", "snmp_exporter")
            rows_q, _ = self._check_service_active_quiet(svc)
            for r in rows_q: self._add_row(r.component, r.check, r.status, r.detail)
            # Unit arg sanity
            rows_unit = self._check_snmp_unit_has_configflag()
            for r in rows_unit: self._add_row(r.component, r.check, r.status, r.detail)
        else:
            self._add_row("SNMP Exporter", "Writeability", "SKIP", "Skipped by user")

        if self.var_chk_stage.get() == "Enable":
            ok_s, _detail_s, rows_s = self._check_staging_dir(opts["paths"]["staging"])
            for r in rows_s: self._add_row(r.component, r.check, r.status, r.detail)
        else:
            self._add_row("Staging", "Dir checks", "SKIP", "Skipped by user")

        if self.var_chk_sudo.get() == "Enable":
            ok_sudo, _detail_sd, rows_sd = self._check_sudo_nopass()
            for r in rows_sd: self._add_row(r.component, r.check, r.status, r.detail)
        else:
            self._add_row("Sudo", "Non-interactive", "SKIP", "Skipped by user")

        if self.var_chk_prom.get() == "Enable":
            for r in self._check_prom_targets(): self._add_row(r.component, r.check, r.status, r.detail)

        if self.var_chk_forti.get() == "Enable":
            for r in self._check_fortigate_snmp(): self._add_row(r.component, r.check, r.status, r.detail)

        self._log("== Verification complete ==")
        overall_ok = res["ok"]
        self._render_final_toast(overall_ok, context="Verification")

    def _run_install(self, plan_only: bool):
        self._clear_results(); self._log("== Install/Upgrade started ==")
        opts = self._gather_opts()
        mode = InstallMode(self.var_install_mode.get())
        overwrite = OverwriteMode(self.var_overwrite.get() if mode == InstallMode.OVERWRITE else OverwriteMode.PRESERVE.value)

        plan = self.installer.plan_install(
            opts, mode=mode, overwrite=overwrite,
            include_node=self.var_node_exporter.get(),
            pin_versions=self.var_pin_versions.get(),
            enable_boot=self.var_enable_boot.get(),
            open_firewall=self.var_open_firewall.get(),
            log_cb=self._log
        )
        if plan_only:
            self._log("-- Plan (dry-run) complete. No changes were applied.")
            self._render_final_toast(True, context="Plan"); return

        res = self.installer.execute_install(plan, log_cb=self._log, table_cb=self._add_rows)

        # Post-install advisory checks
        if self.var_chk_snmp.get() == "Enable":
            ok_w, _detail_w, rows_w = self._check_snmp_writable(self.ent_snmp_path.get().strip() or DEFAULT_PATHS["snmp_yml"])
            for r in rows_w: self._add_row(r.component, r.check, r.status, r.detail)
            svc = getattr(getattr(self.app_state, "ssh", None), "snmp_service", "snmp_exporter")
            rows_q, _ = self._check_service_active_quiet(svc)
            for r in rows_q: self._add_row(r.component, r.check, r.status, r.detail)
            rows_unit = self._check_snmp_unit_has_configflag()
            for r in rows_unit: self._add_row(r.component, r.check, r.status, r.detail)

        if self.var_chk_stage.get() == "Enable":
            ok_s, _detail_s, rows_s = self._check_staging_dir(self.ent_stage_dir.get().strip() or "/var/lib/snmptool")
            for r in rows_s: self._add_row(r.component, r.check, r.status, r.detail)

        if self.var_chk_sudo.get() == "Enable":
            ok_sudo, _detail_sd, rows_sd = self._check_sudo_nopass()
            for r in rows_sd: self._add_row(r.component, r.check, r.status, r.detail)

        if self.var_chk_prom.get() == "Enable":
            for r in self._check_prom_targets(): self._add_row(r.component, r.check, r.status, r.detail)

        if self.var_chk_forti.get() == "Enable":
            for r in self._check_fortigate_snmp(): self._add_row(r.component, r.check, r.status, r.detail)

        self._log("== Install/Upgrade complete ==")
        self._render_final_toast(res["ok"], context="Install")

    # ---------- helpers ----------
    def _gather_opts(self):
        def _int_or(s, dv):
            try: return int(s)
            except: return dv

        ports_str = self.ent_ports.get().strip()
        pvals = [s.strip() for s in ports_str.split(",")] if ports_str else []
        ports = {
            "grafana": _int_or(pvals[0], DEFAULT_PORTS["grafana"]) if len(pvals) > 0 else DEFAULT_PORTS["grafana"],
            "prom":    _int_or(pvals[1], DEFAULT_PORTS["prom"])    if len(pvals) > 1 else DEFAULT_PORTS["prom"],
            "snmp":    _int_or(pvals[2], DEFAULT_PORTS["snmp"])    if len(pvals) > 2 else DEFAULT_PORTS["snmp"],
            "node":    _int_or(pvals[3], DEFAULT_PORTS["node"])    if len(pvals) > 3 else DEFAULT_PORTS["node"],
        }
        snmp_path = (self.ent_snmp_path.get().strip() or DEFAULT_PATHS["snmp_yml"])
        if not snmp_path.startswith("/"): snmp_path = DEFAULT_PATHS["snmp_yml"]
        staging = (self.ent_stage_dir.get().strip() or "/var/lib/snmptool")
        if not staging.startswith("/"): staging = "/var/lib/snmptool"

        return {
            "paths": {
                "snmp_yml": snmp_path,
                "prom_yml": self.ent_prom_path.get().strip() or DEFAULT_PATHS["prom_yml"],
                "grafana_ini": self.ent_graf_ini.get().strip() or DEFAULT_PATHS["grafana_ini"],
                "staging": staging,
            },
            "ports": ports
        }

    def _add_rows(self, rows: list[ResultTableModel]):
        for r in rows:
            self._add_row(r.component, r.check, r.status, r.detail)

    # ----- scrubber & quiet service check -----
    def _clean_systemd_noise(self, s: str) -> str:
        if not s:
            return s
        BAD = ("Wi-Fi is currently blocked by rfkill.", "raspi-config to set the country before use.")
        lines = []
        for ln in s.splitlines():
            if any(b in ln for b in BAD):
                continue
            lines.append(ln)
        return "\n".join(lines).strip()

    def _check_service_active_quiet(self, service: str):
        rows = []
        ssh = getattr(self.app_state, "ssh", None)
        if not ssh:
            rows.append(ResultTableModel("Systemd", f"{service} active", "ERROR", "No SSH session in state."))
            return rows, False
        code, _, _ = ssh_exec(ssh, _sudo_wrap(ssh, f"systemctl is-active --quiet {service} || true"))
        active = (code == 0)
        rows.append(ResultTableModel("Systemd", f"{service} active", "OK" if active else "WARN",
                                     "active" if active else "inactive"))
        return rows, active

    def _add_row(self, component: str, check: str, status: str, detail: str):
        detail = self._clean_systemd_noise(detail)
        self.tree.insert("", "end", values=(component, check, status, detail))

    def _clear_results(self):
        self.tree.delete(*self.tree.get_children()); self.txt_log.delete("1.0", "end")

    def _log(self, line: str):
        self.txt_log.insert("end", line.rstrip() + "\n"); self.txt_log.see("end")

    def _render_final_toast(self, ok: bool, context: str):
        if ok: messagebox.showinfo(f"{context} Finished", f"{context} completed successfully.")
        else:  messagebox.showerror(f"{context} Failed", f"{context} encountered errors. See Activity Log.")

    def _save_txt(self):
        from tkinter.filedialog import asksaveasfilename
        p = asksaveasfilename(defaultextension=".txt", filetypes=[("Text", "*.txt")])
        if not p: return
        with open(p, "w", encoding="utf-8") as f: f.write(self.txt_log.get("1.0", "end"))
        messagebox.showinfo("Saved", "Transcript saved.")

    def _save_json(self):
        from tkinter.filedialog import asksaveasfilename
        p = asksaveasfilename(defaultextension=".json", filetypes=[("JSON", "*.json")])
        if not p: return
        data = self.installer.export_last_report()
        import json as _json; open(p, "w", encoding="utf-8").write(_json.dumps(data, indent=2))
        messagebox.showinfo("Saved", "Report saved.")

    # ---------- EXTRA CHECKS ----------
    def _ssh(self):
        return getattr(self.app_state, "ssh", None)

    def _read_remote(self, path: str) -> str:
        ssh = self._ssh()
        if not ssh: return ""
        code, out, err = ssh_exec(ssh, _sudo_wrap(ssh, f"cat {path} 2>/dev/null || true"))
        return (out or "").strip()

    def _parse_yaml_remote(self, path: str):
        try:
            txt = self._read_remote(path)
            if not txt or not yaml:
                return None
            return yaml.safe_load(txt)
        except Exception:
            return None

    def _extract_snmp_targets(self, prom_doc) -> list[str]:
        targets = []
        if not isinstance(prom_doc, dict):
            return targets
        sc = prom_doc.get("scrape_configs") or []
        for job in sc:
            job_name = job.get("job_name")
            if job_name != "snmp":
                continue
            # static targets
            for scfg in (job.get("static_configs") or []):
                for t in (scfg.get("targets") or []):
                    # normalize to host (strip :port if present)
                    host = t.split(":")[0]
                    if host not in targets:
                        targets.append(host)
        return targets

    def _extract_snmp_community(self, snmp_doc) -> Optional[str]:
        if not isinstance(snmp_doc, dict):
            return None
        auths = snmp_doc.get("auths") or {}
        # prefer a fortigate auth if present
        for name, a in auths.items():
            if "forti" in name.lower() and a.get("version") in (2, "2", "2c", "v2", "v2c"):
                return a.get("community")
        # else first v2c community
        for _, a in auths.items():
            if a.get("version") in (2, "2", "2c", "v2", "v2c"):
                return a.get("community")
        return None

    def _check_snmp_unit_has_configflag(self) -> list[ResultTableModel]:
        rows: list[ResultTableModel] = []
        ssh = self._ssh()
        if not ssh:
            rows.append(ResultTableModel("SNMP Exporter", "Unit args", "ERROR", "No SSH session"))
            return rows
        code, out, err = ssh_exec(ssh, _sudo_wrap(ssh, "systemctl show snmp_exporter -p ExecStart 2>/dev/null || true"))
        line = (out or "").strip()
        has_flag = "--config.file=/etc/snmp_exporter/snmp.yml" in line
        rows.append(ResultTableModel("SNMP Exporter", "Unit config flag",
                                     "OK" if has_flag else "WARN",
                                     ("present" if has_flag else "missing: will use drop-in if you click the repair button")))
        return rows

    def _prom_url_local(self) -> str:
        # We probe Prometheus locally on the Pi
        return "http://127.0.0.1:9090"

    def _prom_api(self, rel_path: str) -> tuple[int, str, str]:
        ssh = self._ssh()
        if not ssh: return 1, "", "no ssh"
        url = f"{self._prom_url_local()}{rel_path}"
        cmd = f"curl -sS --max-time 3 {url} || true"
        return ssh_exec(ssh, cmd)

    def _check_prom_targets(self) -> list[ResultTableModel]:
        rows: list[ResultTableModel] = []
        code, out, err = self._prom_api("/api/v1/targets")
        if not out:
            rows.append(ResultTableModel("Prometheus", "Targets API", "WARN", err or "no response"))
            return rows
        try:
            data = json.loads(out)
        except Exception as e:
            rows.append(ResultTableModel("Prometheus", "Targets API", "ERROR", f"json parse error: {e}"))
            return rows

        active = data.get("data", {}).get("activeTargets", []) or []
        if not active:
            rows.append(ResultTableModel("Prometheus", "Active targets", "WARN", "none"))
            return rows

        snmp_targets = [t for t in active if t.get("labels", {}).get("job") == "snmp"]
        if not snmp_targets:
            rows.append(ResultTableModel("Prometheus", "SNMP job", "WARN", "no snmp targets found"))
        else:
            downs = []
            for t in snmp_targets:
                hs = t.get("health")
                lab = t.get("labels", {})
                inst = lab.get("instance") or lab.get("target") or t.get("discoveredLabels", {}).get("__address__")
                if hs != "up":
                    downs.append((inst, t.get("lastError", "")))
            if downs:
                for inst, errm in downs:
                    rows.append(ResultTableModel("Prometheus", "SNMP target DOWN", "WARN", f"{inst}: {errm}"))
            else:
                rows.append(ResultTableModel("Prometheus", "SNMP targets", "OK", f"{len(snmp_targets)} up"))

        # Instant vector for 'up{job="snmp"}'
        code2, out2, err2 = self._prom_api('/api/v1/query?query=' + 'up%7Bjob%3D%22snmp%22%7D')
        if out2:
            rows.append(ResultTableModel("Prometheus", 'Query up{job="snmp"}', "INFO", out2[:900]))
        else:
            rows.append(ResultTableModel("Prometheus", 'Query up{job="snmp"}', "WARN", err2 or "no response"))

        return rows

    def _check_fortigate_snmp(self) -> list[ResultTableModel]:
        rows: list[ResultTableModel] = []
        ssh = self._ssh()
        if not ssh:
            rows.append(ResultTableModel("FortiGate", "SNMP reachability", "ERROR", "No SSH session"))
            return rows

        prom_doc = self._parse_yaml_remote(self.ent_prom_path.get().strip() or DEFAULT_PATHS["prom_yml"])
        snmp_doc = self._parse_yaml_remote(self.ent_snmp_path.get().strip() or DEFAULT_PATHS["snmp_yml"])
        targets = self._extract_snmp_targets(prom_doc)
        community = self._extract_snmp_community(snmp_doc) or "public"

        # Tools present?
        code_w, out_w, _ = ssh_exec(ssh, "command -v snmpget >/dev/null 2>&1 && echo ok || true")
        has_snmp = "ok" in (out_w or "")
        if not targets:
            rows.append(ResultTableModel("FortiGate", "Targets", "WARN", "No SNMP targets found in prometheus.yml"))
            return rows

        # Try sysName.0 on each target (fast timeout)
        for host in targets:
            if has_snmp:
                cmd = f"snmpget -v2c -c {community} -t 2 -r 1 {host} 1.3.6.1.2.1.1.5.0 2>&1 || true"
                code, out, err = ssh_exec(ssh, cmd)
                out_clean = (out or err or "").strip()
                ok = ("sysName" in out_clean) or ("= STRING:" in out_clean)
                rows.append(ResultTableModel("FortiGate", f"SNMP sysName {host}", "OK" if ok else "WARN",
                                             out_clean[:900] if out_clean else "(no response)"))
            else:
                rows.append(ResultTableModel("FortiGate", f"SNMP {host}", "WARN",
                                             "snmpget not installed; install 'snmp' package (net-snmp)."))

        return rows

    # ---------- FIXERS ----------
    def _fix_snmp_permissions(self):
        ssh = self._ssh()
        if not ssh:
            messagebox.showerror("Fix permissions", "No SSH session available."); return
        conf_file = (self.ent_snmp_path.get() or "").strip()
        if not conf_file or not conf_file.startswith("/"): conf_file = "/etc/snmp_exporter/snmp.yml"
        conf_dir = os.path.dirname(conf_file) or "/etc/snmp_exporter"
        ssh_user = getattr(ssh, "username", "pi")
        cmds = [
            "set -e",
            "groupadd -f snmpexp",
            f"mkdir -p {conf_dir}",
            f"chgrp -R snmpexp {conf_dir}",
            f"chmod 2775 {conf_dir}",
            f"[ -f {conf_file} ] && chgrp snmpexp {conf_file} || true",
            f"[ -f {conf_file} ] && chmod 664 {conf_file} || true",
            f"usermod -aG snmpexp {ssh_user}",
        ]
        script = " && ".join(cmds)
        code, out, err = ssh_exec(ssh, _sudo_wrap(ssh, script))
        if code != 0:
            messagebox.showerror("Fix permissions", (err or out or f"Exit {code}")); return
        ok_w, _detail_w, rows_w = self._check_snmp_writable(conf_file)
        for r in rows_w: self._add_row(r.component, r.check, r.status, r.detail)
        messagebox.showinfo("Fix permissions",
                            "Permissions adjusted.\nOpen a NEW SSH/SFTP session so group membership applies, then re-run verification.")

    def _fix_staging_dir(self):
        ssh = self._ssh()
        if not ssh:
            messagebox.showerror("Fix staging dir", "No SSH session available."); return
        staging = (self.ent_stage_dir.get().strip() or "/var/lib/snmptool")
        if not staging.startswith("/"): staging = "/var/lib/snmptool"
        ssh_user = getattr(ssh, "username", "pi")
        cmds = [
            "set -e",
            "groupadd -f snmptool",
            f"mkdir -p {staging}",
            f"chgrp -R snmptool {staging}",
            f"chmod 2775 {staging}",
            f"usermod -aG snmptool {ssh_user}",
        ]
        script = " && ".join(cmds)
        code, out, err = ssh_exec(ssh, _sudo_wrap(ssh, script))
        if code != 0:
            messagebox.showerror("Fix staging dir", (err or out or f"Exit {code}")); return
        ok_s, _detail_s, rows_s = self._check_staging_dir(staging)
        for r in rows_s: self._add_row(r.component, r.check, r.status, r.detail)
        messagebox.showinfo("Fix staging dir",
                            "Staging dir prepared.\nOpen a NEW SSH/SFTP session so group membership applies, then re-run verification.")

    def _fix_snmp_unit(self):
        """Create a systemd drop-in that enforces --config.file=/etc/snmp_exporter/snmp.yml, then verify."""
        ssh = self._ssh()
        if not ssh:
            messagebox.showerror("Repair unit", "No SSH session available.")
            return

        dropin_dir = "/etc/systemd/system/snmp_exporter.service.d"
        dropin = f"{dropin_dir}/override.conf"
        listen = getattr(getattr(self.app_state, "ssh", None), "snmp_port", 9116)

        # Quote-safe, heredoc-free writer; stderr noise from rfkill is expected and ignored.
        cmd = (
            "set -e; "
            "tmp=$(mktemp); "
            f'printf "[Service]\\nExecStart=\\nExecStart=/usr/local/bin/snmp_exporter --config.file=/etc/snmp_exporter/snmp.yml --web.listen-address=0.0.0.0:{listen}\\n" > "$tmp"; '
            f'install -d -m 0755 "{dropin_dir}"; '
            f'install -m 0644 "$tmp" "{dropin}"; '
            'rm -f "$tmp"; '
            "systemctl daemon-reload; "
            "systemctl restart snmp_exporter || true"
        )

        code, out, err = ssh_exec(ssh, _sudo_wrap(ssh, cmd))

        # Always gather post-state and scrub rfkill noise
        _exec_code, exec_out, _ = ssh_exec(ssh, _sudo_wrap(ssh, "systemctl show snmp_exporter -p ExecStart || true"))
        _act_code, _, _ = ssh_exec(ssh, _sudo_wrap(ssh, "systemctl is-active --quiet snmp_exporter || true"))
        _listen_code, listen_out, _ = ssh_exec(ssh, _sudo_wrap(ssh, "ss -lntp | grep 9116 || true"))

        # Update the Results table with clean info
        for r in self._check_snmp_unit_has_configflag():
            self._add_row(r.component, r.check, r.status, r.detail)
        self._add_row("Systemd", "ExecStart (after repair)", "INFO", self._clean_systemd_noise((exec_out or "").strip()))
        self._add_row("Systemd", "Active status", "OK" if _act_code == 0 else "WARN", "active" if _act_code == 0 else "inactive")
        self._add_row("Sockets", "Listening on :9116", "OK" if (listen_out or "").strip() else "WARN",
                    "YES" if (listen_out or "").strip() else "NO")

        # If restart failed AND service isn't active, show a real error (scrub rfkill). Otherwise, success.
        if code != 0 and _act_code != 0:
            detail = self._clean_systemd_noise((err or out or f"exit {code}").strip())
            messagebox.showerror("Repair unit", detail or "Repair failed.")
        else:
            messagebox.showinfo("Repair unit", "Applied drop-in and verified snmp_exporter is running.")



    def _quick_test_fortigate(self):
        """Manual button: run sysName.0 against each SNMP target."""
        rows = self._check_fortigate_snmp()
        for r in rows: self._add_row(r.component, r.check, r.status, r.detail)
        if not rows:
            messagebox.showinfo("FortiGate", "No SNMP targets found to test.")

    # ---------- Original extra checks ----------
    def _check_snmp_writable(self, conf_file: str):
        rows: list[ResultTableModel] = []
        ssh = self._ssh()
        if not ssh:
            rows.append(ResultTableModel("SNMP Exporter", "SSH session", "ERROR", "No SSH session in state."))
            return False, "No SSH session.", rows

        conf_file = conf_file or "/etc/snmp_exporter/snmp.yml"
        if not conf_file.startswith("/"): conf_file = "/etc/snmp_exporter/snmp.yml"
        conf_dir = os.path.dirname(conf_file) or "/etc/snmp_exporter"

        code, out, _ = ssh_exec(ssh, "ps aux | grep -v grep | grep snmp_exporter || true")
        want_flag = f"--config.file={conf_file}"
        uses_expected = any(want_flag in (ln or "") for ln in (out or "").splitlines())
        rows.append(ResultTableModel("SNMP Exporter", "Service config path", "OK" if uses_expected else "WARN",
                                     (out or "(no process)").strip() or "(no output)"))

        code_d, out_d, _ = ssh_exec(ssh, _sudo_wrap(ssh, f"stat -c '%U:%G %a %n' {conf_dir} || true"))
        code_f, out_f, _ = ssh_exec(ssh, _sudo_wrap(ssh, f"stat -c '%U:%G %a %n' {conf_file} || true"))
        rows.append(ResultTableModel("SNMP Exporter", "Directory stat", "INFO", (out_d or "").strip()))
        rows.append(ResultTableModel("SNMP Exporter", "Config stat", "INFO", (out_f or '').strip() or "not found"))

        tmpname = f"{conf_dir}/.writetest_{int(time.time())}_{os.getpid()}"
        sftp_ok, err_msg = False, ""
        try:
            sftp_write(ssh, tmpname, "ok\n"); sftp_ok = True
        except Exception as e:
            err_msg = str(e)
        finally:
            ssh_exec(ssh, _sudo_wrap(ssh, f"rm -f {tmpname} || true"))
        rows.append(ResultTableModel("SNMP Exporter", "Direct SFTP write to config dir",
                                     "OK" if sftp_ok else "WARN",
                                     "OK" if sftp_ok else f"{err_msg}"))

        return (uses_expected and sftp_ok), "", rows

    def _check_staging_dir(self, staging: str):
        rows: list[ResultTableModel] = []
        ssh = self._ssh()
        if not ssh:
            rows.append(ResultTableModel("Staging", "SSH session", "ERROR", "No SSH session in state."))
            return False, "No SSH session.", rows

        if not staging or not staging.startswith("/"):
            staging = "/var/lib/snmptool"

        code_mk, out_mk, err_mk = ssh_exec(ssh, _sudo_wrap(ssh, f"mkdir -p {staging} && ls -ld {staging} || true"))
        rows.append(ResultTableModel("Staging", "Directory exists", "OK" if code_mk == 0 else "WARN",
                                     (out_mk or err_mk or "").strip()))

        tmpfile = f"{staging}/.writetest_{int(time.time())}_{os.getpid()}"
        sftp_ok, err_msg = False, ""
        try:
            sftp_write(ssh, tmpfile, "ok\n"); sftp_ok = True
        except Exception as e:
            err_msg = str(e)
        finally:
            ssh_exec(ssh, _sudo_wrap(ssh, f"rm -f {tmpfile} || true"))

        rows.append(ResultTableModel("Staging", "SFTP write", "OK" if sftp_ok else "WARN",
                                     "OK" if sftp_ok else err_msg))

        return (code_mk == 0 and sftp_ok), "", rows

    def _check_sudo_nopass(self):
        rows: list[ResultTableModel] = []
        ssh = self._ssh()
        if not ssh:
            rows.append(ResultTableModel("Sudo", "SSH session", "ERROR", "No SSH session in state."))
            return False, "No SSH session.", rows

        code, out, err = ssh_exec(ssh, _sudo_wrap(ssh, "true"))
        ok = (code == 0)
        rows.append(ResultTableModel("Sudo", "Non-interactive sudo", "OK" if ok else "WARN",
                                     "OK" if ok else (err or out or "sudo failed")))
        return ok, "", rows

    # ----- Results → Activity Log plumbing -----
    def _emit_detail_to_log(self, item_id: str):
        if not item_id:
            return
        vals = (self.tree.item(item_id, "values") or ("", "", "", ""))
        comp, chk, status, detail = (list(vals) + ["", "", "", ""])[:4]
        detail = self._clean_systemd_noise(detail)
        self._log(f">> {comp} / {chk} [{status}]\n{detail}\n")

    def _on_result_select(self, _evt=None):
        sel = self.tree.selection()
        if sel:
            self._emit_detail_to_log(sel[0])

    def _on_result_activate(self, _evt=None):
        sel = self.tree.selection()
        if sel:
            self._emit_detail_to_log(sel[0])
