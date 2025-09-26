from __future__ import annotations

import json
import os
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from typing import Any, Dict, List, Optional, Tuple, Callable
import re

# Optional imports from your project; keep them optional to avoid hard crashes.
try:
    from common.yaml_rt import yaml_load
except Exception:
    def yaml_load(text: str):
        import yaml  # type: ignore
        return yaml.safe_load(text) if text else None

# ---- Robust builder import with diagnostics ---------------------------------
from typing import Optional, Dict, Any, List, Tuple
import os, sys, importlib, importlib.util, traceback

_HAS_BUILDER = False
_build_dashboard_model = None  # type: ignore
_last_builder_error = ""

def _record_err(prefix: str, exc: BaseException):
    global _last_builder_error
    _last_builder_error = f"{prefix}: {exc.__class__.__name__}: {exc}\n" + "".join(
        traceback.format_exception_only(type(exc), exc)
    ).strip()

def _try_import_pkg():
    """Try package-style imports (requires __init__.py files)."""
    global _HAS_BUILDER, _build_dashboard_model
    try:
        mod = importlib.import_module("tabs.dashboard.builder")
    except Exception as e:
        _record_err("tabs.dashboard.builder", e)
        try:
            mod = importlib.import_module("builder")  # next to dashboard_tab.py
        except Exception as e2:
            _record_err("builder (same dir)", e2)
            return False
    if hasattr(mod, "build_dashboard_model"):
        _build_dashboard_model = getattr(mod, "build_dashboard_model")
        _HAS_BUILDER = True
        return True
    _record_err("missing symbol", RuntimeError("build_dashboard_model not found"))
    return False

def _try_import_by_path():
    """Try loading builder.py by absolute path (no packages needed)."""
    global _HAS_BUILDER, _build_dashboard_model
    here = os.path.dirname(os.path.abspath(__file__))
    candidates = [
        os.path.join(here, "builder.py"),
        os.path.join(here, "dashboard", "builder.py"),
    ]
    for path in candidates:
        if not os.path.isfile(path):
            continue
        try:
            spec = importlib.util.spec_from_file_location("snmp_dash_builder", path)
            if not spec or not spec.loader:
                continue
            mod = importlib.util.module_from_spec(spec)
            sys.modules[spec.name] = mod
            spec.loader.exec_module(mod)  # type: ignore[attr-defined]
            if hasattr(mod, "build_dashboard_model"):
                _build_dashboard_model = getattr(mod, "build_dashboard_model")
                _HAS_BUILDER = True
                return True
            _record_err(f"{path}", RuntimeError("build_dashboard_model not found"))
        except Exception as e:
            _record_err(path, e)
    return False

_HAS_BUILDER = _try_import_pkg() or _try_import_by_path()
# -----------------------------------------------------------------------------




# ---------- Tiny tooltip helper ----------
class _Tooltip:
    def __init__(self, widget: tk.Widget, text: str, delay_ms: int = 350):
        self.widget = widget
        self.text = text
        self.delay_ms = delay_ms
        self._id = None
        self._tw: Optional[tk.Toplevel] = None
        widget.bind("<Enter>", self._enter, add="+")
        widget.bind("<Leave>", self._leave, add="+")
        widget.bind("<ButtonPress>", self._leave, add="+")
    def _enter(self, _e=None):
        self._schedule()
    def _leave(self, _e=None):
        self._unschedule()
        self._hide()
    def _schedule(self):
        self._unschedule()
        self._id = self.widget.after(self.delay_ms, self._show)
    def _unschedule(self):
        if self._id:
            self.widget.after_cancel(self._id)
            self._id = None
    def _show(self):
        if self._tw: return
        x, y, cx, cy = self.widget.bbox("insert") if hasattr(self.widget, "bbox") else (0, 0, 0, 0)
        x += self.widget.winfo_rootx() + 10
        y += self.widget.winfo_rooty() + cy + 12
        self._tw = tk.Toplevel(self.widget)
        self._tw.wm_overrideredirect(True)
        self._tw.wm_geometry(f"+{x}+{y}")
        lbl = tk.Label(self._tw, text=self.text, justify=tk.LEFT,
                       background="#ffffe0", relief=tk.SOLID, borderwidth=1,
                       font=("Segoe UI", 9))
        lbl.pack(ipadx=6, ipady=3)
    def _hide(self):
        if self._tw:
            self._tw.destroy()
            self._tw = None


class DashboardTab(ttk.Frame):
    """
    Dashboard builder tab.

    Supports two wiring modes (constructor overloading):
    - DashboardTab(parent, state) where `state` has .snmp_doc / .orig_snmp_text / .snmp_yml_path and .ssh.host
    - DashboardTab(parent, snmp_yml_path_getter: Callable[[], str|None])

    Listens for <<ConfigsPulled>> (from Connection tab) and refreshes modules/metrics.
    """

    DEFAULT_GRAFANA_PORT = 3000

    def __init__(self, parent, arg2):
        super().__init__(parent)

        # Wiring: state or path-getter
        self._state = None
        self._snmp_path_getter: Optional[Callable[(), Optional[str]]] = None

        if callable(arg2):
            self._snmp_path_getter = arg2
        else:
            self._state = arg2

        # Selections and caches
        self.modules: List[str] = []
        self.metrics_by_module: Dict[str, List[str]] = {}
        self.selected_pairs: List[Tuple[str, str]] = []

        # UI Vars
        self.var_title = tk.StringVar(value="SNMP Dashboard")
        self.var_job = tk.StringVar(value="snmp")
        self.var_prom_uid = tk.StringVar(value="")    # Optional default datasource UID

        # API-related
        self.var_api_url = tk.StringVar(value="")
        self.var_api_token = tk.StringVar(value="")
        self.var_api_folder = tk.StringVar(value="")  # kept for forward-compat
        self.var_api_tls_skip = tk.BooleanVar(value=False)
        self.var_api_overwrite = tk.BooleanVar(value=True)

        # Session profile path (for saving/loading Grafana URL & API token)
        self.var_profile_path = tk.StringVar(
            value=os.path.join(os.path.expanduser("~"), ".snmpexplorer", "session.json")
        )

        # Build UI
        self._build_ui()

        # Receive event from Connection tab when files are pulled
        self.bind_all("<<ConfigsPulled>>", self._on_configs_pulled, add="+")

    # ---------------------------------------------------------------------
    # UI
    # ---------------------------------------------------------------------
    def _build_ui(self):
        root = ttk.Frame(self)
        root.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Header
        hdr = ttk.Frame(root); hdr.pack(fill=tk.X, pady=(0, 8))
        ttk.Label(hdr, text="5) Grafana Dashboard Builder", font=("Segoe UI", 12, "bold")).pack(side=tk.LEFT)

        # Top controls
        row0 = ttk.Frame(root); row0.pack(fill=tk.X, pady=(4, 10))
        ttk.Label(row0, text="Title").pack(side=tk.LEFT)
        ttk.Entry(row0, textvariable=self.var_title, width=36).pack(side=tk.LEFT, padx=(4, 12))
        ttk.Label(row0, text="Job").pack(side=tk.LEFT)
        ttk.Entry(row0, textvariable=self.var_job, width=18).pack(side=tk.LEFT, padx=(4, 12))
        ttk.Label(row0, text="Prometheus DS UID (optional)").pack(side=tk.LEFT)
        ttk.Entry(row0, textvariable=self.var_prom_uid, width=24).pack(side=tk.LEFT, padx=(4, 0))

        # Load/refresh area
        row1 = ttk.Frame(root); row1.pack(fill=tk.X, pady=(0, 6))
        ttk.Button(row1, text="Load metrics from current snmp.yml", command=self._load_from_current_snmp).pack(side=tk.LEFT)
        ttk.Label(row1, text="  ← uses the snmp.yml you pulled on the Connection tab", foreground="#666").pack(side=tk.LEFT)

        # Session profile controls (save/load Grafana URL & API token)
        row_prof = ttk.Frame(root); row_prof.pack(fill=tk.X, pady=(4, 6))
        ttk.Label(row_prof, text="Session profile").pack(side=tk.LEFT)
        ttk.Entry(row_prof, textvariable=self.var_profile_path, width=60).pack(side=tk.LEFT, padx=(4, 8))
        ttk.Button(row_prof, text="Load", command=self._on_load_profile).pack(side=tk.LEFT)
        ttk.Button(row_prof, text="Save", command=self._on_save_profile).pack(side=tk.LEFT, padx=(6, 0))

        # Selection area: modules -> metrics -> selected
        body = ttk.Frame(root); body.pack(fill=tk.BOTH, expand=True)

        # Modules
        col_mod = ttk.Labelframe(body, text="Modules"); col_mod.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 8))
        self.lst_modules = tk.Listbox(col_mod, exportselection=False)
        self.lst_modules.pack(fill=tk.BOTH, expand=True, padx=6, pady=6)
        self.lst_modules.bind("<<ListboxSelect>>", self._on_module_select)

        # Metrics
        col_met = ttk.Labelframe(body, text="Metrics in selected module"); col_met.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 8))
        self.lst_metrics = tk.Listbox(col_met, exportselection=False, selectmode=tk.EXTENDED)
        self.lst_metrics.pack(fill=tk.BOTH, expand=True, padx=6, pady=6)

        # Actions between metrics and selected
        col_act = ttk.Frame(body); col_act.pack(side=tk.LEFT, fill=tk.Y, padx=(0, 8))
        ttk.Button(col_act, text="Add ▶", command=self._on_add_selected).pack(fill=tk.X, pady=(40, 6))
        ttk.Button(col_act, text="Add all of module ▶▶", command=self._on_add_all_of_module).pack(fill=tk.X, pady=(0, 6))
        ttk.Button(col_act, text="◀ Remove", command=self._on_remove_selected).pack(fill=tk.X, pady=(16, 6))
        ttk.Button(col_act, text="⟲ Clear", command=self._on_clear_all).pack(fill=tk.X, pady=(0, 6))

        # Selected
        col_sel = ttk.Labelframe(body, text="Selected (module → metric)"); col_sel.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.lst_selected = tk.Listbox(col_sel, exportselection=False, selectmode=tk.EXTENDED)
        self.lst_selected.pack(fill=tk.BOTH, expand=True, padx=6, pady=6)

        # API / export row
        api = ttk.Labelframe(root, text="Export / API"); api.pack(fill=tk.X, pady=(8, 0))
        row_api1 = ttk.Frame(api); row_api1.pack(fill=tk.X, pady=(6, 4))
        ttk.Label(row_api1, text="Grafana URL").pack(side=tk.LEFT)

        ent_url = ttk.Entry(row_api1, textvariable=self.var_api_url, width=32)
        ent_url.pack(side=tk.LEFT, padx=(4, 12))

        # Tooltip: defaulting and port hint
        _Tooltip(ent_url,
                 "If left blank, I'll use the SSH destination IP and default port.\n"
                 f"Default: http://<ssh-host>:{self.DEFAULT_GRAFANA_PORT}")

        ttk.Label(row_api1, text="API Token").pack(side=tk.LEFT)
        ttk.Entry(row_api1, textvariable=self.var_api_token, show="•", width=40).pack(side=tk.LEFT, padx=(4, 12))
        ttk.Label(row_api1, text="Folder ID").pack(side=tk.LEFT)
        ttk.Entry(row_api1, textvariable=self.var_api_folder, width=8).pack(side=tk.LEFT, padx=(4, 12))
        ttk.Checkbutton(row_api1, text="TLS Skip Verify", variable=self.var_api_tls_skip).pack(side=tk.LEFT, padx=(0, 12))
        ttk.Checkbutton(row_api1, text="Overwrite", variable=self.var_api_overwrite).pack(side=tk.LEFT)

        row_api2 = ttk.Frame(api); row_api2.pack(fill=tk.X, pady=(0, 8))
        ttk.Button(row_api2, text="💾 Save dashboard JSON…", command=self._on_save_json).pack(side=tk.LEFT)
        ttk.Button(row_api2, text="⇪ Send to Grafana API", command=self._on_send_api).pack(side=tk.LEFT, padx=(8, 0))
        ttk.Label(api, text="Tip: Import the saved JSON in Grafana (Dashboards → New → Import), or use API.", foreground="#666").pack(anchor="w", pady=(0, 6), padx=2)

        # Help
        ttk.Label(root, text="How it works:", font=("Segoe UI", 10, "bold")).pack(anchor="w", pady=(8, 0))
        help_text = (
            "1) Click “Load metrics from current snmp.yml”.\n"
            "2) Select a module to see its metrics. Add specific metrics, or add the entire module.\n"
            "3) Choose a Job name (must match Prometheus job label), and optionally a Prometheus datasource UID.\n"
            "4) Save the dashboard JSON or push to Grafana API.\n\n"
            "Note: If you include interface octet metrics (ifIn/ifOut or ifHCIn/ifHCOut),\n"
            "the dashboard auto-adds IF-MIB panels (health, totals, top-k, interface table)."
        )
        ttk.Label(root, text=help_text, foreground="#555").pack(anchor="w")

    # ---------------------------------------------------------------------
    # Event handlers
    # ---------------------------------------------------------------------
    def _on_configs_pulled(self, _evt=None):
        self._load_from_current_snmp(silent=True)
        # If token is already present but URL is empty, prefill a sane default
        if not (self.var_api_url.get() or "").strip() and (self.var_api_token.get() or "").strip():
            self.var_api_url.set(self._default_grafana_url())

    # ---------------------------------------------------------------------
    # Loading/parsing snmp.yml
    # ---------------------------------------------------------------------
    def _resolve_snmp_text(self) -> Optional[str]:
        # Preferred: state has the original text already
        if self._state is not None:
            text = getattr(self._state, "orig_snmp_text", None)
            if text:
                return text
            # fallback: path stored on state
            path = getattr(self._state, "snmp_yml_path", None)
            if path and os.path.exists(path):
                try:
                    return open(path, "r", encoding="utf-8").read()
                except Exception:
                    pass

        # Older wiring: a path getter function
        if self._snmp_path_getter:
            try:
                p = self._snmp_path_getter() or ""
            except Exception:
                p = ""
            if p and os.path.exists(p):
                try:
                    return open(p, "r", encoding="utf-8").read()
                except Exception:
                    pass

        # Final fallback: default workspace copy written by ConnectionTab
        default_ws = os.path.join(os.path.expanduser("~"), ".snmpexplorer", "workspace", "snmp.yml")
        if os.path.exists(default_ws):
            try:
                return open(default_ws, "r", encoding="utf-8").read()
            except Exception:
                pass
        return None

    def _load_from_current_snmp(self, silent: bool = False):
        text = self._resolve_snmp_text()
        if not text:
            if not silent:
                messagebox.showwarning("No snmp.yml", "I couldn't find the current snmp.yml. Pull it on the Connection tab first.")
            return

        try:
            doc = yaml_load(text) or {}
            modules = (doc.get("modules") or {})
            # Build maps
            self.modules = sorted(list(modules.keys()))
            self.metrics_by_module = {}
            for mname, mconf in modules.items():
                metrics = []
                for item in (mconf.get("metrics") or []):
                    n = item.get("name")
                    if n:
                        metrics.append(n)
                self.metrics_by_module[mname] = sorted(metrics)
        except Exception as e:
            if not silent:
                messagebox.showerror("Parse error", f"Failed to parse snmp.yml:\n{e}")
            return

        # Refresh lists
        self._populate_module_list()
        self._clear_metrics_list()
        if not silent:
            messagebox.showinfo("Loaded", "Modules & metrics loaded from snmp.yml.")

    # ---------------------------------------------------------------------
    # Lists management
    # ---------------------------------------------------------------------
    def _populate_module_list(self):
        self.lst_modules.delete(0, tk.END)
        for name in self.modules:
            self.lst_modules.insert(tk.END, name)

    def _clear_metrics_list(self):
        self.lst_metrics.delete(0, tk.END)

    def _on_module_select(self, _evt=None):
        sel = self._get_single_selection(self.lst_modules, self.modules)
        self.lst_metrics.delete(0, tk.END)
        if not sel:
            return
        for met in self.metrics_by_module.get(sel, []):
            self.lst_metrics.insert(tk.END, met)

    def _on_add_selected(self):
        mod = self._get_single_selection(self.lst_modules, self.modules)
        if not mod:
            return
        metric_names = self._get_multi_selection(self.lst_metrics, self.metrics_by_module.get(mod, []))
        for m in metric_names:
            pair = (mod, m)
            if pair not in self.selected_pairs:
                self.selected_pairs.append(pair)
                self.lst_selected.insert(tk.END, f"{mod} → {m}")

    def _on_add_all_of_module(self):
        mod = self._get_single_selection(self.lst_modules, self.modules)
        if not mod:
            return
        for m in self.metrics_by_module.get(mod, []):
            pair = (mod, m)
            if pair not in self.selected_pairs:
                self.selected_pairs.append(pair)
                self.lst_selected.insert(tk.END, f"{mod} → {m}")

    def _on_remove_selected(self):
        idxs = list(self.lst_selected.curselection())
        if not idxs:
            return
        for i in reversed(idxs):
            self.lst_selected.delete(i)
            try:
                del self.selected_pairs[i]
            except Exception:
                pass

    def _on_clear_all(self):
        self.lst_selected.delete(0, tk.END)
        self.selected_pairs.clear()

    # ---------------------------------------------------------------------
    # Export / API
    # ---------------------------------------------------------------------
    def _collect_build_inputs(self) -> Tuple[str, str, str, List[Tuple[str, str]]]:
        title = (self.var_title.get() or "SNMP Dashboard").strip()
        job   = (self.var_job.get() or "snmp").strip()
        ds    = (self.var_prom_uid.get() or "").strip()
        pairs = list(self.selected_pairs)
        return title, job, ds, pairs

    def _ensure_builder(self) -> bool:
        if not _HAS_BUILDER or _build_dashboard_model is None:
            messagebox.showerror(
                "Builder not found",
                "I couldn't import builder.py.\n\n"
                "Looked in:\n"
                " • tabs/dashboard/builder.py (package: tabs.dashboard.builder)\n"
                " • builder.py next to this file\n\n"
                f"Details:\n{_last_builder_error or '(no details)'}"
            )
            return False
        return True

    def _on_save_json(self):
        if not self._ensure_builder():
            return
        title, job, ds, pairs = self._collect_build_inputs()
        if not pairs:
            messagebox.showwarning("Select metrics", "Please add at least one metric.")
            return

        model = _build_dashboard_model(
            title=title,
            datasource_name="prometheus",
            datasource_uid=ds or None,
            refresh="10s",
            time_from="now-6h",
            time_to="now",
            job_default=job,
            pairs=pairs,
            export_mode="ui",
        )
        path = filedialog.asksaveasfilename(
            title="Save dashboard JSON",
            defaultextension=".json",
            filetypes=[("JSON", "*.json")],
            initialfile=f"snmp_dashboard.json",
        )
        if not path:
            return
        with open(path, "w", encoding="utf-8") as f:
            json.dump(model, f, indent=2)
        messagebox.showinfo("Saved", f"Dashboard JSON written to:\n{path}")

    def _on_send_api(self):
        if not self._ensure_builder():
            return
        title, job, ds, pairs = self._collect_build_inputs()
        if not pairs:
            messagebox.showwarning("Select metrics", "Please add at least one metric.")
            return

        payload = _build_dashboard_model(
            title=title,
            datasource_name="prometheus",
            datasource_uid=ds or None,
            refresh="10s",
            time_from="now-6h",
            time_to="now",
            job_default=job,
            pairs=pairs,
            export_mode="api",
        )

        # Normalize/auto-default URL
        url = self._normalize_or_default_url((self.var_api_url.get() or "").strip())
        token = (self.var_api_token.get() or "").strip()
        if not token:
            messagebox.showwarning("Missing API token", "Enter a Grafana API token.")
            return
        if not url:
            # If we couldn't construct a default, we must ask explicitly
            messagebox.showwarning("Missing Grafana URL", "Enter Grafana URL, or ensure SSH host is set so I can default it.")
            return

        try:
            import urllib.request, ssl
            data = json.dumps(payload).encode("utf-8")
            req = urllib.request.Request(
                f"{url}/api/dashboards/db",
                data=data,
                headers={
                    "Authorization": f"Bearer {token}",
                    "Content-Type": "application/json",
                },
                method="POST",
            )
            ctx = None
            if self.var_api_tls_skip.get() and url.lower().startswith("https://"):
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
            with urllib.request.urlopen(req, context=ctx) as resp:
                body = resp.read().decode("utf-8")
            messagebox.showinfo("Grafana", f"Dashboard pushed.\nResponse:\n{body[:800]}")
        except Exception as e:
            messagebox.showerror("Grafana API error", str(e))

    # ---------------------------------------------------------------------
    # Session profile save/load (JSON at ~/.snmpexplorer/session.json)
    # ---------------------------------------------------------------------
    def _profile_read(self, path: str) -> Dict[str, Any]:
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except FileNotFoundError:
            return {}
        except Exception as e:
            messagebox.showerror("Profile", f"Failed to read profile:\n{e}")
            return {}

    def _profile_write(self, path: str, data: Dict[str, Any]) -> None:
        try:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            messagebox.showerror("Profile", f"Failed to write profile:\n{e}")

    def _on_load_profile(self) -> None:
        path = (self.var_profile_path.get() or "").strip()
        if not path:
            messagebox.showwarning("Profile", "Provide a profile path.")
            return
        data = self._profile_read(path)
        g = data.get("grafana", {})
        if g.get("url"):         self.var_api_url.set(g["url"])
        if g.get("api_token"):   self.var_api_token.set(g["api_token"])
        if g.get("ds_uid"):      self.var_prom_uid.set(g["ds_uid"])
        if g.get("job_default"): self.var_job.set(g["job_default"])
        if g.get("title"):       self.var_title.set(g["title"])
        messagebox.showinfo("Profile", "Profile loaded.")

    def _on_save_profile(self) -> None:
        path = (self.var_profile_path.get() or "").strip()
        if not path:
            messagebox.showwarning("Profile", "Provide a profile path.")
            return
        data = self._profile_read(path)
        data["grafana"] = {
            "url":        (self.var_api_url.get() or "").strip(),
            "api_token":  (self.var_api_token.get() or "").strip(),
            "ds_uid":     (self.var_prom_uid.get() or "").strip(),
            "job_default":(self.var_job.get() or "").strip(),
            "title":      (self.var_title.get() or "").strip(),
        }
        self._profile_write(path, data)
        messagebox.showinfo("Profile", f"Saved Grafana URL & API token to:\n{path}")

    # ---------------------------------------------------------------------
    # Helpers (selection, URL defaults/normalization)
    # ---------------------------------------------------------------------
    def _get_single_selection(self, listbox: tk.Listbox, backing: List[str]) -> Optional[str]:
        sel = listbox.curselection()
        if not sel:
            return None
        idx = sel[0]
        if 0 <= idx < len(backing):
            return backing[idx]
        return None

    def _get_multi_selection(self, listbox: tk.Listbox, backing: List[str]) -> List[str]:
        out: List[str] = []
        for idx in listbox.curselection():
            if 0 <= idx < len(backing):
                out.append(backing[idx])
        return out

    # --- New: default URL from SSH target + normalize ---
    def _ssh_host(self) -> Optional[str]:
        st = self._state
        if st is None:
            return None
        ssh = getattr(st, "ssh", None)
        host = getattr(ssh, "host", None) if ssh else None
        if host:
            return str(host).strip()
        # fallback: common flat fields
        host = getattr(st, "host", None) or getattr(st, "ssh_host", None)
        return str(host).strip() if host else None

    def _default_grafana_url(self) -> str:
        host = self._ssh_host()
        if not host:
            return ""
        # If user already typed a URL, we won't overwrite it automatically; this is only our default.
        return f"http://{host}:{self.DEFAULT_GRAFANA_PORT}"

    def _normalize_or_default_url(self, url: str) -> str:
        """
        If url is blank, use http://<ssh-host>:3000.
        If url is a bare host or host:port, add http://.
        If url lacks a port, append :3000.
        """
        if not url:
            return self._default_grafana_url()

        u = url.strip()
        # If it already starts with http/https, keep scheme
        if not re.match(r'^https?://', u, flags=re.I):
            u = "http://" + u

        # If there's no explicit port in the authority, append default 3000
        # Extract host:port (very light parsing)
        try:
            from urllib.parse import urlparse
            parsed = urlparse(u)
            port_present = bool(parsed.netloc.split(":")[1:])  # has ":port"
            if not port_present:
                # rebuild with :3000
                netloc = parsed.netloc + f":{self.DEFAULT_GRAFANA_PORT}"
                u = parsed._replace(netloc=netloc).geturl()
        except Exception:
            # Fallback: if we don't see ":<digits>" after host, append
            if not re.search(r':\d+(/|$)', u):
                if u.endswith("/"):
                    u = u[:-1]
                u += f":{self.DEFAULT_GRAFANA_PORT}"
        return u
