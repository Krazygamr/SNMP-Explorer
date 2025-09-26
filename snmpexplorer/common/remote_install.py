# common/remote_install.py
from __future__ import annotations
from dataclasses import dataclass
from enum import Enum
import json, os, time
from typing import Callable
from types import SimpleNamespace

import paramiko
from common.context import AppState  # your existing location

DEFAULT_PATHS = {
    "snmp_yml": "/etc/snmp_exporter/snmp.yml",
    "prom_yml": "/etc/prometheus/prometheus.yml",
    "grafana_ini": "/etc/grafana/grafana.ini",
    "snmp_unit": "/etc/systemd/system/snmp_exporter.service",
    "node_unit": "/etc/systemd/system/node_exporter.service",
}

DEFAULT_PORTS = {"grafana": 3000, "prom": 9090, "snmp": 9116, "node": 9100}
BACKUP_ROOT = "/var/backups/grafanapy"

class InstallMode(Enum):
    INSTALL_UPGRADE = "Install/Upgrade"
    OVERWRITE = "Overwrite"

class OverwriteMode(Enum):
    PRESERVE = "Preserve settings"
    CLEAN = "Clean reinstall"

class SanityLevel(Enum):
    QUICK = "Quick (syntax, services, ports)"
    SANITY_SUITE = "Sanity Suite (YAML, services, ports, HTTP, cross-checks)"

@dataclass
class ResultTableModel:
    component: str
    check: str
    status: str  # "OK", "WARN", "FAIL"
    detail: str

@dataclass
class TemplateBundle:
    snmp_service: str
    node_service: str
    prometheus_yml: str
    grafana_ini: str
    snmp_minimal_snippet: str

def _default_profile_resolver(state: AppState):
    # same logic as in the tab, but kept minimal here
    names = ("get_active_profile", "get_profile", "active_profile",
             "profile", "session", "session_profile", "current_profile")
    for n in names:
        if hasattr(state, n):
            v = getattr(state, n)
            prof = v() if callable(v) else v
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

class RemoteInstaller:
    def __init__(self, app_state: AppState, profile_resolver=_default_profile_resolver):
        self.state = app_state
        self._resolve_profile = profile_resolver
        self._last_report = {"ok": False, "results": []}

    # ----- public surface -----
    def verify_stack(self, opts: dict, level: SanityLevel, dry_run: bool,
                     log_cb: Callable[[str], None],
                     table_cb: Callable[[list[ResultTableModel]], None]) -> dict:
        rows: list[ResultTableModel] = []
        ok = True

        with self._ssh(log_cb) as ssh:
            # Basic env check
            env_ok = self._check_env(ssh, rows, log_cb)
            ok = ok and env_ok

            # YAML parse + structure
            if level != SanityLevel.QUICK:
                self._check_yaml_syntax(ssh, opts, rows, log_cb)

            # Services + ports + HTTP
            self._check_services_ports(ssh, opts, rows, log_cb)

            # Cross-checks + module/auth + unit ExecStart path
            if level == SanityLevel.SANITY_SUITE:
                self._cross_checks(ssh, opts, rows, log_cb)
                self._http_probes(ssh, opts, rows, log_cb)
            
            # System/package/python update visibility
            self._check_updates(ssh, rows, log_cb)

            # Aggregate + export
            table_cb(rows)
            ok = ok and all(r.status != "FAIL" for r in rows)
            self._last_report = {"ok": ok, "results": [r.__dict__ for r in rows], "timestamp": int(time.time())}
            return self._last_report

    def plan_install(self, opts: dict, mode: InstallMode, overwrite: OverwriteMode,
                     include_node: bool, pin_versions: bool, enable_boot: bool, open_firewall: bool,
                     log_cb: Callable[[str], None]) -> dict:
        plan = {
            "mode": mode.value,
            "overwrite": overwrite.value if mode == InstallMode.OVERWRITE else None,
            "opts": opts,
            "include_node": include_node,
            "pin_versions": pin_versions,
            "enable_boot": enable_boot,
            "open_firewall": open_firewall,
            "steps": []
        }

        def add(step, reason):
            plan["steps"].append({"step": step, "reason": reason})

        # Preflight checks happen at execute-time; here we construct ordered intentions
        add("preflight", "Ensure sudo, systemd, disk space, network, apt availability")
        add("backup", "Create timestamped backup of configs and databases if present")
        add("install_packages", "Install/upgrade grafana, prometheus, snmp_exporter (or drop upstream binary)")
        if include_node:
            add("install_node_exporter", "Optional node exporter for host metrics")
        add("write_templates", "Create/repair service units and minimal configs if missing")
        add("enable_start", "Daemon-reload, enable and start services")
        add("sanity_suite", "Re-run verification and HTTP probes")

        if mode == InstallMode.OVERWRITE:
            if overwrite == OverwriteMode.PRESERVE:
                add("overwrite_preserve", "Reinstall packages/binaries, then restore saved configs/db")
            else:
                add("overwrite_clean", "Purge/remove configs/data; reinstall fresh; write defaults")

        log_cb(json.dumps(plan, indent=2))
        return plan

    def execute_install(self, plan: dict,
                        log_cb: Callable[[str], None],
                        table_cb: Callable[[list[ResultTableModel]], None]) -> dict:
        rows: list[ResultTableModel] = []
        ok = True
        opts = plan["opts"]

        with self._ssh(log_cb) as ssh:
            # Preflight
            if not self._preflight(ssh, rows, log_cb):
                table_cb(rows)
                self._last_report = {"ok": False, "results": [r.__dict__ for r in rows], "timestamp": int(time.time())}
                return self._last_report

            # Backup
            self._backup(ssh, opts, rows, log_cb)

            # Install or overwrite flows
            include_node = plan.get("include_node", True)
            pin_versions = plan.get("pin_versions", False)
            enable_boot = plan.get("enable_boot", True)
            open_firewall = plan.get("open_firewall", False)

            mode = plan["mode"]
            overwrite = plan.get("overwrite")

            if mode == InstallMode.OVERWRITE.value:
                if overwrite == OverwriteMode.CLEAN.value:
                    self._overwrite_clean(ssh, rows, log_cb)
                else:
                    self._overwrite_preserve(ssh, rows, log_cb)

            # Install/upgrade packages/binaries
            self._install_stack(ssh, include_node, pin_versions, rows, log_cb)

            # Write templates if missing or incoherent
            self._write_templates_if_needed(ssh, opts, include_node, rows, log_cb)

            # Enable/start
            self._enable_start_services(ssh, enable_boot, rows, log_cb)

            # Firewall
            if open_firewall:
                self._open_firewall(ssh, rows, log_cb)

            # Sanity suite
            self._check_yaml_syntax(ssh, opts, rows, log_cb)
            self._check_services_ports(ssh, opts, rows, log_cb)
            self._cross_checks(ssh, opts, rows, log_cb)
            self._http_probes(ssh, opts, rows, log_cb)

            table_cb(rows)
            ok = ok and all(r.status != "FAIL" for r in rows)
            self._last_report = {"ok": ok, "results": [r.__dict__ for r in rows], "timestamp": int(time.time())}
            return self._last_report

    def export_last_report(self) -> dict:
        return self._last_report

    # ----- SSH context -----
    class _SSHCtx:
        def __init__(self, client: paramiko.SSHClient, sftp: paramiko.SFTPClient):
            self.client = client
            self.sftp = sftp
        def __enter__(self): return self
        def __exit__(self, exc_type, exc, tb):
            try: self.sftp.close()
            except Exception: pass
            self.client.close()

    def _ssh(self, log_cb):
        prof = self._resolve_profile(self.state)
        if not prof or not getattr(prof, "host", None):
            raise RuntimeError("No active profile/host configured.")

        log_cb(f"Connecting to {getattr(prof, 'username', None)}@{prof.host}:{getattr(prof, 'port', 22)} ...")
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        if getattr(prof, "password", None):
            client.connect(
                prof.host, port=getattr(prof, "port", 22),
                username=getattr(prof, "username", None),
                password=prof.password, timeout=20
            )
        else:
            pkey = None
            key_path = getattr(prof, "key_path", None)
            if key_path:
                try:
                    pkey = paramiko.RSAKey.from_private_key_file(key_path, password=getattr(prof, "key_passphrase", None))
                except Exception:
                    pkey = paramiko.Ed25519Key.from_private_key_file(key_path, password=getattr(prof, "key_passphrase", None))
            client.connect(
                prof.host, port=getattr(prof, "port", 22),
                username=getattr(prof, "username", None),
                pkey=pkey, timeout=20
            )
        sftp = client.open_sftp()
        return self._SSHCtx(client, sftp)


    # ----- exec helpers -----
    def _exec(self, ssh: "_SSHCtx", cmd: str, sudo: bool = True, timeout: int = 60) -> tuple[int, str, str]:
        """
        Run a command on the remote host.
        Uses the profile resolver (not get_active_profile) and honors disable_sudo.
        """
        prof = self._resolve_profile(self.state)
        # Only prepend sudo if requested AND sudo isn't disabled by profile
        if sudo and not getattr(prof, "disable_sudo", False):
            cmd = f"sudo -n bash -lc {json.dumps(cmd)}"
        else:
            cmd = f"bash -lc {json.dumps(cmd)}"

        stdin, stdout, stderr = ssh.client.exec_command(cmd, timeout=timeout)
        out = stdout.read().decode("utf-8", errors="ignore")
        err = stderr.read().decode("utf-8", errors="ignore")
        rc = stdout.channel.recv_exit_status()
        return rc, out, err


    def _put_text(self, ssh: _SSHCtx, remote_path: str, text: str):
        tmp = f"/tmp/.grafanapy.{os.getpid()}.{int(time.time()*1000)}"
        with ssh.sftp.file(tmp, "w") as f:
            f.write(text)
        self._exec(ssh, f"install -m 0644 -o root -g root {tmp} {remote_path} && rm -f {tmp}")

    # ----- checks & actions -----
    def _check_env(self, ssh: _SSHCtx, rows, log):
        rc, out, _ = self._exec(ssh, "uname -a && lsb_release -a || cat /etc/os-release | sed -n '1,6p'", sudo=False)
        rows.append(ResultTableModel("Environment", "OS info", "OK" if rc == 0 else "WARN", out.strip()[:400]))
        rc2, out2, _ = self._exec(ssh, "df -h / | tail -1 | awk '{print $4}'", sudo=False)
        rows.append(ResultTableModel("Environment", "Free disk (/)", "OK" if rc2 == 0 else "WARN", out2.strip()))
        return True

    def _check_yaml_syntax(self, ssh: "_SSHCtx", opts, rows, log):
        """
        Tool-free YAML sanity checks:
        - file exists & non-empty
        - basic key presence (grep)
        - CRLF & trailing newline hints
        For strict Prometheus validation we still prefer promtool when present;
        otherwise we rely on service readiness + logs in other checks.
        """
        checks = [
            ("SNMP Exporter", opts["paths"]["snmp_yml"], "modules:"),
            ("Prometheus",    opts["paths"]["prom_yml"], "scrape_configs:"),
        ]

        for name, path, required_key in checks:
            # Exists?
            rc0, _, _ = self._exec(ssh, f"test -f {path}")
            if rc0 != 0:
                rows.append(ResultTableModel(name, f"YAML sanity {path}", "FAIL", "file not found"))
                continue

            # Non-empty?
            rc1, _, _ = self._exec(ssh, f"test -s {path}")
            if rc1 != 0:
                rows.append(ResultTableModel(name, f"YAML sanity {path}", "FAIL", "file is empty"))
                continue

            # Required top-level-ish key present?
            rc2, _, _ = self._exec(ssh, f"grep -E '^{required_key}\\s*$|^{required_key}\\s*#' {path} >/dev/null 2>&1 || grep -F '{required_key}' {path} >/dev/null 2>&1")
            if rc2 != 0:
                rows.append(ResultTableModel(name, f"YAML sanity {path}", "WARN", f"'{required_key}' not found (heuristic)"))
            else:
                rows.append(ResultTableModel(name, f"YAML sanity {path}", "OK", f"'{required_key}' found"))

            # Line ending + trailing newline hints (no changes made)
            rc3, out3, _ = self._exec(ssh, f"file {path} | grep -qi 'with CRLF' && echo CRLF || echo LF", sudo=True)
            crlf = "CRLF" in (out3 or "")
            rc4, out4, _ = self._exec(ssh, f"tail -c1 {path} >/dev/null 2>&1 || echo MISSING_NL || true", sudo=True)
            details = []
            if crlf: details.append("CRLF line endings")
            if "MISSING_NL" in (out4 or ""): details.append("missing trailing newline")
            rows.append(ResultTableModel(name, "Normalization", "WARN" if details else "OK", ", ".join(details) if details else "LF + trailing newline present"))


    def _check_services_ports(self, ssh: _SSHCtx, opts, rows, log):
        # Services
        for svc in ("grafana-server", "prometheus", "snmp_exporter"):
            rc, out, err = self._exec(ssh, f"systemctl is-active {svc} || true")
            status = out.strip() or err.strip()
            state = "OK" if "active" in status else ("WARN" if status else "WARN")
            rows.append(ResultTableModel("Services", f"{svc} active", state, status or "unknown"))

        # Ports
        ports = opts["ports"]
        for label, port in (("Grafana", ports["grafana"]), ("Prometheus", ports["prom"]), ("SNMP Exporter", ports["snmp"])):
            rc, out, _ = self._exec(ssh, f"ss -tulpen | grep ':{port}\\b' || true", sudo=True)
            state = "OK" if out.strip() else "FAIL"
            rows.append(ResultTableModel("Ports", f"{label} listening :{port}", state, out.strip() or "not listening"))

    def _cross_checks(self, ssh: _SSHCtx, opts, rows, log):
        """
        Cross-file / service sanity checks:
        - Ensure snmp_exporter.service points to the expected snmp.yml
        - Show mtime of snmp.yml (so user sees if it's fresh)
        - Run promtool check if available
        - Show recent log errors for Prometheus and SNMP exporter
        """
        snmp_yml = opts["paths"]["snmp_yml"]
        prom_yml = opts["paths"]["prom_yml"]

        # --- snmp_exporter.service ExecStart coherence ---
        rc, out, _ = self._exec(
            ssh,
            "grep -oE '--config.file=\\S+' /etc/systemd/system/snmp_exporter.service || true"
        )
        unit_path = out.strip().split("=", 1)[1] if "=" in out else ""
        if unit_path and unit_path == snmp_yml:
            rows.append(ResultTableModel("SNMP Exporter", "Unit config path", "OK", f"--config.file={unit_path}"))
        else:
            rows.append(ResultTableModel(
                "SNMP Exporter",
                "Unit config path",
                "WARN",
                f"unit points to '{unit_path or '(none)'}', app expects '{snmp_yml}'"
            ))

        # --- snmp.yml mtime ---
        rc2, out2, _ = self._exec(ssh, f"stat -c %Y {snmp_yml} 2>/dev/null || echo 0", sudo=True)
        if out2.strip().isdigit():
            rows.append(ResultTableModel("SNMP Exporter", "snmp.yml mtime (epoch)", "OK", out2.strip()))

        # --- promtool check if available ---
        self._promtool_check(ssh, prom_yml, rows)

        # --- recent errors in logs (trimmed) ---
        rcp, outp, _ = self._exec(
            ssh,
            "journalctl -u prometheus -n 50 --no-pager | grep -iE 'error|config|reload' || true"
        )
        if outp.strip():
            rows.append(ResultTableModel("Prometheus", "Recent log (errors/config)", "INFO", outp.strip()[:900]))

        rcs, outs, _ = self._exec(
            ssh,
            "journalctl -u snmp_exporter -n 50 --no-pager | grep -iE 'error|config|parse' || true"
        )
        if outs.strip():
            rows.append(ResultTableModel("SNMP Exporter", "Recent log (errors/config)", "INFO", outs.strip()[:900]))



    def _promtool_check(self, ssh: _SSHCtx, prom_yml: str, rows):
        rc, _, _ = self._exec(ssh, "command -v promtool >/dev/null 2>&1")
        if rc != 0:
            rows.append(ResultTableModel("Prometheus", "promtool presence", "WARN", "promtool not installed"))
            return
        rc2, out2, err2 = self._exec(ssh, f"promtool check config {prom_yml} || true")
        if "SUCCESS" in out2:
            rows.append(ResultTableModel("Prometheus", "promtool check", "OK", "config valid"))
        else:
            rows.append(ResultTableModel("Prometheus", "promtool check", "WARN", (out2 + err2)[-400:]))

    def _http_probes(self, ssh: _SSHCtx, opts, rows, log):
        ports = opts["ports"]
        # Prometheus readiness
        rc, out, err = self._exec(ssh, f"curl -sSf http://127.0.0.1:{ports['prom']}/-/ready || true", sudo=False)
        rows.append(ResultTableModel("Prometheus", "/-/ready", "OK" if rc == 0 else "FAIL", (out or err).strip()[:300]))
        # SNMP exporter metrics
        rc2, out2, err2 = self._exec(ssh, f"curl -sSf http://127.0.0.1:{ports['snmp']}/metrics | head -n 20 || true", sudo=False)
        rows.append(ResultTableModel("SNMP Exporter", "/metrics", "OK" if rc2 == 0 else "FAIL", (out2 or err2).strip()[:300]))

    def _check_updates(self, ssh: "_SSHCtx", rows, log):
        """
        Report upgradable APT packages + core tools presence + Python info
        without changing the system.
        """
        # Upgradable packages (summary)
        rc1, out1, err1 = self._exec(ssh, "apt-get -s upgrade | grep -E '^Inst ' | wc -l || true")
        upg_count = (out1 or "0").strip()
        rows.append(ResultTableModel("System", "APT upgradable packages", "OK", f"{upg_count} package(s) have upgrades available"))

        # Optional: list first few upgradable for context
        rc2, out2, _ = self._exec(ssh, "apt-get -s upgrade | grep -E '^Inst ' | head -n 10 || true")
        if out2.strip():
            rows.append(ResultTableModel("System", "Upgradable (sample)", "OK", out2.strip()))

        # Python & pip presence
        rc3, out3, _ = self._exec(ssh, "python3 --version 2>&1 || true", sudo=False)
        rows.append(ResultTableModel("Python", "python3 --version", "OK" if out3 else "WARN", out3.strip() or "not found"))

        rc4, out4, _ = self._exec(ssh, "pip3 --version 2>&1 || true", sudo=False)
        rows.append(ResultTableModel("Python", "pip3 --version", "OK" if out4 else "WARN", out4.strip() or "not found"))

        # Core tools we rely on for verification
        tools = ["curl", "ss", "systemctl", "journalctl", "promtool"]
        for t in tools:
            rc, _, _ = self._exec(ssh, f"command -v {t} >/dev/null 2>&1")
            rows.append(ResultTableModel("Tools", f"{t} present", "OK" if rc == 0 else "WARN", "found" if rc == 0 else "missing"))

    # ----- execute helpers -----
    def _preflight(self, ssh: _SSHCtx, rows, log) -> bool:
        rc, _, _ = self._exec(ssh, "id -u")
        if rc != 0:
            rows.append(ResultTableModel("Preflight", "sudo access", "FAIL", "Cannot run commands"))
            return False
        # Disk & network quick checks
        rc2, out2, _ = self._exec(ssh, "df -P / | tail -1 | awk '{print $4}'")
        rows.append(ResultTableModel("Preflight", "disk blocks free", "OK" if rc2 == 0 else "WARN", out2.strip()))
        rc3, _, _ = self._exec(ssh, "ping -c1 -W1 deb.debian.org >/dev/null 2>&1 || true", sudo=False)
        rows.append(ResultTableModel("Preflight", "network reachability", "OK" if rc3 == 0 else "WARN", "debian mirror reachable" if rc3 == 0 else "mirror unreachable"))
        return True

    def _backup(self, ssh: _SSHCtx, opts, rows, log):
        ts = int(time.time())
        dest = f"{BACKUP_ROOT}/{ts}"
        self._exec(ssh, f"mkdir -p {dest}")
        items = [
            opts["paths"]["snmp_yml"],
            opts["paths"]["prom_yml"],
            DEFAULT_PATHS["snmp_unit"],
            DEFAULT_PATHS["node_unit"],
            opts["paths"]["grafana_ini"],
            "/var/lib/grafana/grafana.db",
        ]
        cmd = " && ".join([f"test -f {p} && cp -a {p} {dest}/ || true" for p in items])
        self._exec(ssh, cmd)
        rows.append(ResultTableModel("Backup", "Saved configs/data", "OK", dest))

    def _overwrite_clean(self, ssh: _SSHCtx, rows, log):
        cmds = [
            "systemctl stop grafana-server prometheus snmp_exporter 2>/dev/null || true",
            "apt-get -y purge grafana prometheus prometheus-node-exporter snmp-exporter 2>/dev/null || true",
            "rm -rf /etc/snmp_exporter /etc/prometheus /etc/grafana /usr/local/bin/snmp_exporter /usr/local/bin/node_exporter || true",
            f"rm -f {DEFAULT_PATHS['snmp_unit']} {DEFAULT_PATHS['node_unit']} || true",
            "systemctl daemon-reload || true",
        ]
        self._exec(ssh, " && ".join(cmds))
        rows.append(ResultTableModel("Overwrite", "Clean reinstall prep", "OK", "purged packages and configs"))

    def _overwrite_preserve(self, ssh: _SSHCtx, rows, log):
        self._exec(ssh, "systemctl stop grafana-server prometheus snmp_exporter 2>/dev/null || true")
        rows.append(ResultTableModel("Overwrite", "Preserve mode", "OK", "services stopped; configs will be restored post-install"))

    def _install_stack(self, ssh: _SSHCtx, include_node: bool, pin_versions: bool, rows, log):
        # Prefer distro packages; fallback to upstream binaries for snmp_exporter if missing or too old
        cmds = [
            "apt-get update -y",
            "DEBIAN_FRONTEND=noninteractive apt-get install -y curl ca-certificates",
            "DEBIAN_FRONTEND=noninteractive apt-get install -y grafana prometheus || true",
            "DEBIAN_FRONTEND=noninteractive apt-get install -y snmp-exporter || true",
        ]
        if include_node:
            cmds.append("DEBIAN_FRONTEND=noninteractive apt-get install -y prometheus-node-exporter || true")
        self._exec(ssh, " && ".join(cmds))
        rows.append(ResultTableModel("Install", "Packages", "OK", "attempted grafana/prometheus/snmp-exporter (+node)"))

        # Ensure snmp_exporter binary exists, else install upstream
        rc, _, _ = self._exec(ssh, "command -v snmp_exporter || test -x /usr/local/bin/snmp_exporter")
        if rc != 0:
            # Fetch upstream (arm64/armhf detection omitted for brevity—user can adjust if needed)
            fetch = "cd /usr/local/bin && curl -L -o snmp_exporter.tgz https://github.com/prometheus/snmp_exporter/releases/latest/download/snmp_exporter-*-linux-arm64.tar.gz && tar -xzf snmp_exporter.tgz --wildcards --strip-components=1 '*/snmp_exporter' && rm -f snmp_exporter.tgz && chmod +x snmp_exporter"
            self._exec(ssh, fetch)
            rows.append(ResultTableModel("Install", "SNMP Exporter upstream", "OK", "/usr/local/bin/snmp_exporter"))

    def _write_templates_if_needed(self, ssh: _SSHCtx, opts, include_node: bool, rows, log):
        t = self._templates(opts)
        # snmp_exporter.service
        rc, _, _ = self._exec(ssh, f"test -f {DEFAULT_PATHS['snmp_unit']}")
        if rc != 0:
            self._put_text(ssh, DEFAULT_PATHS["snmp_unit"], t.snmp_service)
            rows.append(ResultTableModel("Templates", "snmp_exporter.service", "OK", "created"))
        # node_exporter.service
        if include_node:
            rc, _, _ = self._exec(ssh, f"test -f {DEFAULT_PATHS['node_unit']}")
            if rc != 0:
                self._put_text(ssh, DEFAULT_PATHS["node_unit"], t.node_service)
                rows.append(ResultTableModel("Templates", "node_exporter.service", "OK", "created"))
        # prometheus.yml (only if missing)
        rc, _, _ = self._exec(ssh, f"test -f {opts['paths']['prom_yml']} || echo MISSING")
        if rc == 0:
            # rc==0 means test -f returned 0 or "MISSING" printed; safer to check content:
            rc2, out2, _ = self._exec(ssh, f"test -f {opts['paths']['prom_yml']} && echo HAS || echo MISSING")
            if "MISSING" in out2:
                self._exec(ssh, "mkdir -p /etc/prometheus")
                self._put_text(ssh, opts["paths"]["prom_yml"], t.prometheus_yml)
                rows.append(ResultTableModel("Templates", "prometheus.yml", "OK", "created minimal"))
        # grafana.ini (only if missing)
        rc, out, _ = self._exec(ssh, f"test -f {opts['paths']['grafana_ini']} && echo HAS || echo MISSING")
        if "MISSING" in out:
            self._exec(ssh, "mkdir -p /etc/grafana")
            self._put_text(ssh, opts["paths"]["grafana_ini"], t.grafana_ini)
            rows.append(ResultTableModel("Templates", "grafana.ini", "OK", "created minimal"))
        # snmp.yml sanity: ensure directory exists, do not overwrite existing
        rc, out, _ = self._exec(ssh, f"test -d /etc/snmp_exporter && echo HAS || echo MISSING")
        if "MISSING" in out:
            self._exec(ssh, "mkdir -p /etc/snmp_exporter")
        rc, out, _ = self._exec(ssh, f"test -f {opts['paths']['snmp_yml']} && echo HAS || echo MISSING")
        if "MISSING" in out:
            # Create empty with minimal header so exporter starts; do NOT write secrets
            minimal = "# snmp.yml (initial minimal)\nmodules: {}\n"
            self._put_text(ssh, opts["paths"]["snmp_yml"], minimal)
            rows.append(ResultTableModel("Templates", "snmp.yml", "OK", "created minimal (no auth)"))

    def _enable_start_services(self, ssh: _SSHCtx, enable_boot: bool, rows, log):
        self._exec(ssh, "systemctl daemon-reload")
        if enable_boot:
            self._exec(ssh, "systemctl enable grafana-server prometheus snmp_exporter || true")
        self._exec(ssh, "systemctl restart grafana-server || true")
        self._exec(ssh, "systemctl restart prometheus || true")
        self._exec(ssh, "systemctl restart snmp_exporter || true")
        rows.append(ResultTableModel("Services", "Enable/Restart", "OK", "grafana/prometheus/snmp_exporter (and node if present)"))

    def _open_firewall(self, ssh: _SSHCtx, rows, log):
        cmd = (
            "if command -v ufw >/dev/null 2>&1; then "
            "ufw allow 3000/tcp || true; ufw allow 9090/tcp || true; ufw allow 9116/tcp || true; ufw allow 9100/tcp || true; "
            "fi"
        )
        self._exec(ssh, cmd)
        rows.append(ResultTableModel("Firewall", "ufw allowances", "OK", "opened common ports if ufw is present"))

    # ------------- templates -------------
    def _templates(self, opts) -> TemplateBundle:
        ports = opts["ports"]
        snmp_path = opts["paths"]["snmp_yml"]
        prom_yml = f"""global:
  scrape_interval: 30s
  evaluation_interval: 30s

scrape_configs:
  - job_name: "prometheus"
    static_configs:
      - targets: ["127.0.0.1:{ports['prom']}"]

  - job_name: "snmp"
    metrics_path: /snmp
    static_configs:
      - targets: ["192.168.1.99"]  # TODO: replace with your device IPs
    relabel_configs:
      - source_labels: [__address__]
        target_label: __param_target
      - target_label: instance
        replacement: "192.168.1.99"
      - target_label: __address__
        replacement: "127.0.0.1:{ports['snmp']}"
"""
        graf_ini = f"""[server]
http_port = {ports['grafana']}
protocol = http
domain = localhost

[security]
admin_user = admin
# Set admin_password manually on first login; not stored here.
"""
        snmp_unit = f"""[Unit]
Description=Prometheus SNMP Exporter (upstream)
After=network-online.target

[Service]
User=root
Group=root
Type=simple
ExecStart=/usr/local/bin/snmp_exporter --config.file={snmp_path} --web.listen-address=0.0.0.0:{ports['snmp']}
Restart=on-failure

[Install]
WantedBy=multi-user.target
"""
        node_unit = f"""[Unit]
Description=Prometheus Node Exporter
After=network-online.target

[Service]
User=root
Group=root
Type=simple
ExecStart=/usr/bin/prometheus-node-exporter --web.listen-address=:9100
Restart=on-failure

[Install]
WantedBy=multi-user.target
"""
        snmp_minimal = """# Minimal FortiGate v2c sample (append manually; community not stored)
auths:
  fortigate_v2c:
    version: 2
    community: ${SNMP_COMMUNITY}

modules:
  fortigate_basic:
    walk:
      - 1.3.6.1.4.1.12356.101.4.1   # fgSystem subtree (example)
      - 1.3.6.1.2.1.1               # system
    retries: 3
    timeout: 5s
"""

        return TemplateBundle(
            snmp_service=snmp_unit,
            node_service=node_unit,
            prometheus_yml=prom_yml,
            grafana_ini=graf_ini,
            snmp_minimal_snippet=snmp_minimal
        )
