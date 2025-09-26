# tabs/dashboard/ui.py
import os, json
import tkinter as tk
from tkinter import ttk, filedialog
from tkinter.scrolledtext import ScrolledText
from datetime import datetime

from .tooltips import Tooltip
from .model import SnmpModel
from .selection import SelectionState
from .builder import build_dashboard_model

class DashboardTab(ttk.Frame):
    """
    Passive, discoverable UI for building Grafana dashboard JSON
    from modules/metrics in the pulled snmp.yml (AppState-managed path).
    """
    def __init__(self, master, snmp_yml_path_getter, *args, **kwargs):
        super().__init__(master, *args, **kwargs)
        self.get_snmp_yml_path = snmp_yml_path_getter

        # data/state
        self.modules_to_metrics: dict[str, list[str]] = {}
        self.sel = SelectionState()
        self.loaded_path: str | None = None

        # export options
        self.export_mode = tk.StringVar(value="ui")  # "ui" (UI import) or "api" (HTTP payload)

        # build UI
        self._build()

    # ---- outer app hook after <<ConfigsPulled>>
    def refresh(self):
        self._set_status("Pulled configs detected. Click 'Load from pulled snmp.yml' to refresh modules/metrics.", ok=True)

    # ---- UI ----
    def _build(self):
        root = ttk.Frame(self); root.pack(fill="both", expand=True, padx=8, pady=8)
        for c in range(3): root.columnconfigure(c, weight=1, uniform="col")
        root.rowconfigure(5, weight=1)

        # Controls row
        ctrl = ttk.Frame(root); ctrl.grid(row=0, column=0, columnspan=3, sticky="ew", pady=(0,6))
        ctrl.columnconfigure(1, weight=1)
        btn_load = ttk.Button(ctrl, text="Load from pulled snmp.yml", command=self._load_from_state)
        btn_load.grid(row=0, column=0, sticky="w")
        Tooltip(btn_load, "Reads the snmp.yml you pulled from the Pi (Connection tab).")

        ttk.Button(ctrl, text="Help", command=self._open_help).grid(row=0, column=2, sticky="e")
        self.lbl_status = ttk.Label(ctrl, text="Idle. Click 'Load from pulled snmp.yml' after you pull from the Pi.", foreground="#777")
        self.lbl_status.grid(row=0, column=1, sticky="w", padx=(8,0))

        # Dashboard options
        hdr = ttk.LabelFrame(root, text="Dashboard Options")
        hdr.grid(row=1, column=0, columnspan=3, sticky="ew", pady=(0,8))
        for i in range(10): hdr.columnconfigure(i, weight=1)

        ttk.Label(hdr, text="Title").grid(row=0, column=0, sticky="w")
        self.ent_title = ttk.Entry(hdr); self.ent_title.insert(0, "SNMP — Generated Dashboard")
        self.ent_title.grid(row=0, column=1, sticky="ew", padx=(0,8))

        ttk.Label(hdr, text="Datasource").grid(row=0, column=2, sticky="w")
        self.ent_ds_name = ttk.Entry(hdr); self.ent_ds_name.insert(0, "Prometheus")
        self.ent_ds_name.grid(row=0, column=3, sticky="ew", padx=(0,8))
        Tooltip(self.ent_ds_name, "Grafana datasource name (legacy name-based reference).")

        ttk.Label(hdr, text="Datasource UID").grid(row=0, column=4, sticky="w")
        self.ent_ds_uid = ttk.Entry(hdr); self.ent_ds_uid.insert(0, "")
        self.ent_ds_uid.grid(row=0, column=5, sticky="ew", padx=(0,8))
        Tooltip(self.ent_ds_uid, "Optional. If set, the dashboard will reference the datasource by UID (recommended).")

        ttk.Label(hdr, text="Refresh").grid(row=0, column=6, sticky="w")
        self.ent_refresh = ttk.Entry(hdr); self.ent_refresh.insert(0, "10s")
        self.ent_refresh.grid(row=0, column=7, sticky="ew")
        Tooltip(self.ent_refresh, "Dashboard auto-refresh interval (e.g., 5s, 10s, 1m).")

        ttk.Label(hdr, text="Var: job").grid(row=1, column=0, sticky="w")
        self.ent_job_default = ttk.Entry(hdr); self.ent_job_default.insert(0, "snmp")
        self.ent_job_default.grid(row=1, column=1, sticky="ew", padx=(0,8))
        Tooltip(self.ent_job_default, "Default selection for the $job variable (Prometheus label).")

        ttk.Label(hdr, text="Time Range").grid(row=1, column=2, sticky="w")
        self.ent_time_from = ttk.Entry(hdr); self.ent_time_from.insert(0, "now-24h")
        self.ent_time_from.grid(row=1, column=3, sticky="ew", padx=(0,8))
        ttk.Label(hdr, text="to").grid(row=1, column=4, sticky="w")
        self.ent_time_to = ttk.Entry(hdr); self.ent_time_to.insert(0, "now")
        self.ent_time_to.grid(row=1, column=5, sticky="ew")
        Tooltip(self.ent_time_from, "Default time range start (e.g., now-24h).")
        Tooltip(self.ent_time_to, "Default time range end (usually 'now').")

        fmt_row = ttk.Frame(hdr); fmt_row.grid(row=2, column=0, columnspan=6, sticky="w", pady=(6,0))
        ttk.Label(fmt_row, text="Export format:").pack(side="left")
        ttk.Radiobutton(fmt_row, text="Dashboard (UI Import)", value="ui", variable=self.export_mode)\
            .pack(side="left", padx=(6,0))
        ttk.Radiobutton(fmt_row, text="API payload (/api/dashboards/db)", value="api", variable=self.export_mode)\
            .pack(side="left", padx=(6,0))

        # Left: modules
        left = ttk.LabelFrame(root, text="Modules (from pulled snmp.yml)")
        left.grid(row=2, column=0, rowspan=3, sticky="nsew", padx=(0,8))
        left.rowconfigure(1, weight=1); left.columnconfigure(0, weight=1)

        ttk.Button(left, text="Reload from pulled file", command=self._reload_same_path)\
            .grid(row=0, column=0, sticky="ew", padx=4, pady=(4,0))

        self.lst_modules = tk.Listbox(left, selectmode="extended", exportselection=False)
        self.lst_modules.grid(row=1, column=0, sticky="nsew", padx=4, pady=4)
        self.lst_modules.bind("<<ListboxSelect>>", self._on_modules_selected)
        Tooltip(self.lst_modules, "Select one or more modules. The middle list shows the union of their metrics.")

        # Middle: metrics union for highlighted modules
        mid = ttk.LabelFrame(root, text="Metrics available (for selected module(s))")
        mid.grid(row=2, column=1, sticky="nsew")
        mid.rowconfigure(1, weight=1); mid.columnconfigure(0, weight=1)

        self.lbl_metrics_header = ttk.Label(mid, text="No modules selected.")
        self.lbl_metrics_header.grid(row=0, column=0, sticky="w", padx=4, pady=(4,0))

        self.lst_metrics = tk.Listbox(mid, selectmode="extended", exportselection=False)
        self.lst_metrics.grid(row=1, column=0, sticky="nsew", padx=4, pady=4)
        Tooltip(self.lst_metrics, "Choose metrics to add for each highlighted module.")

        mbtns = ttk.Frame(root); mbtns.grid(row=3, column=1, sticky="ew", pady=(6,0))
        ttk.Button(mbtns, text="Select All", command=self._select_all_metrics).pack(side="left")
        ttk.Button(mbtns, text="Clear Selection", command=self._clear_metric_selection).pack(side="left", padx=6)
        ttk.Button(mbtns, text="Add →", command=self._add_metrics).pack(side="right")
        Tooltip(mbtns, "Add: assigns chosen metrics to every highlighted module.")

        # Right: selected metrics by module
        right = ttk.LabelFrame(root, text="Selected metrics by module")
        right.grid(row=2, column=2, rowspan=3, sticky="nsew")
        right.rowconfigure(1, weight=1); right.columnconfigure(0, weight=1)

        self.lbl_selected_header = ttk.Label(right, text="(none)")
        self.lbl_selected_header.grid(row=0, column=0, sticky="w", padx=4, pady=(4,0))

        self.txt_selected = ScrolledText(right, height=20, wrap="none")
        self.txt_selected.grid(row=1, column=0, sticky="nsew", padx=4, pady=4)
        Tooltip(self.txt_selected, "Your picks, grouped by module.")

        rbtns = ttk.Frame(root); rbtns.grid(row=3, column=2, sticky="ew", pady=(6,0))
        ttk.Button(rbtns, text="← Remove", command=self._remove_metrics).pack(side="left")
        ttk.Button(rbtns, text="Clear All", command=self._clear_all_selected).pack(side="left", padx=6)

        # Bottom: output
        bottom = ttk.LabelFrame(root, text="Output")
        bottom.grid(row=5, column=0, columnspan=3, sticky="nsew", pady=(8,0))
        bottom.columnconfigure(0, weight=1); bottom.rowconfigure(1, weight=1)

        obtns = ttk.Frame(bottom); obtns.grid(row=0, column=0, sticky="ew", pady=4)
        ttk.Button(obtns, text="Preview JSON", command=self._preview_json).pack(side="left", padx=(0,6))
        ttk.Button(obtns, text="Copy JSON to Clipboard", command=self._copy_json_to_clipboard).pack(side="left", padx=(0,6))
        ttk.Button(obtns, text="Save JSON…", command=self._save_json).pack(side="left")

        self.txt_preview = ScrolledText(bottom, height=14, wrap="none")
        self.txt_preview.grid(row=1, column=0, sticky="nsew")

        # start empty
        self._clear_lists()
        self._clear_preview()

    # ---- help ----
    def _open_help(self):
        win = tk.Toplevel(self); win.title("Dashboard Tab Help"); win.geometry("720x520")
        txt = ScrolledText(win, wrap="word"); txt.pack(fill="both", expand=True)
        txt.insert("end", (
            "How this tab works:\n"
            "1) Pull configs from the Pi on the '1) Connection & Pull' tab.\n"
            "2) Click 'Load from pulled snmp.yml' here to load modules/metrics.\n"
            "3) Select one or more modules on the LEFT.\n"
            "4) In the MIDDLE, choose the metrics you want and click 'Add →'.\n"
            "   • The middle list shows the UNION of metrics across highlighted modules.\n"
            "   • Adding assigns each chosen metric to EVERY highlighted module.\n"
            "5) The RIGHT panel shows your curated picks, GROUPED by module.\n"
            "   • Use '← Remove' to remove picked metrics from the highlighted module(s).\n"
            "6) Use Preview/Copy/Save. Choose 'Dashboard (UI Import)' if importing with the UI; otherwise\n"
            "   choose 'API payload' for POST /api/dashboards/db.\n"
        ))
        txt.config(state="disabled")

    # ---- loading ----
    def _load_from_state(self):
        path = self.get_snmp_yml_path()
        if not path:
            self._set_status("No pulled snmp.yml yet. Use '1) Connection & Pull' first.", ok=False)
            self._clear_lists(); return
        if not os.path.isfile(path):
            self._set_status(f"snmp.yml not found at: {path}", ok=False)
            self._clear_lists(); return

        self.modules_to_metrics = SnmpModel.load_snmp_modules(path)
        self.loaded_path = path
        self._refresh_modules_listbox()
        self.sel.clear_all()
        self._refresh_selected_text()
        self._set_status(f"Loaded {len(self.modules_to_metrics)} modules from {path}", ok=True)

    def _reload_same_path(self):
        if not self.loaded_path:
            self._set_status("Nothing loaded yet. Click 'Load from pulled snmp.yml' first.", ok=False)
            return
        self.modules_to_metrics = SnmpModel.load_snmp_modules(self.loaded_path)
        self._refresh_modules_listbox()
        self._set_status(f"Reloaded {len(self.modules_to_metrics)} modules.", ok=True)

    # ---- helpers (ui) ----
    def _set_status(self, msg, ok=True):
        self.lbl_status.configure(text=msg, foreground=("#157347" if ok else "#B00020"))

    def _clear_lists(self):
        self.modules_to_metrics = {}
        self.sel.clear_all()
        self._refresh_modules_listbox()
        self._refresh_selected_text()

    def _clear_preview(self):
        self.txt_preview.config(state="normal")
        self.txt_preview.delete("1.0", "end")
        self.txt_preview.config(state="disabled")

    def _refresh_modules_listbox(self):
        self.lst_modules.delete(0, "end")
        for mod in sorted(self.modules_to_metrics.keys()):
            self.lst_modules.insert("end", mod)
        sel = self.lst_modules.curselection()
        self.lbl_metrics_header.configure(
            text="No modules selected." if not sel else f"Metrics available for {len(sel)} selected module(s)"
        )

    def _on_modules_selected(self, _evt=None):
        sel_indices = self.lst_modules.curselection()
        shown = set()
        for idx in sel_indices:
            mod = self.lst_modules.get(idx)
            shown.update(self.modules_to_metrics.get(mod, []))
        self.lst_metrics.delete(0, "end")
        for m in sorted(shown):
            self.lst_metrics.insert("end", m)
        self.lbl_metrics_header.configure(
            text="No modules selected." if not sel_indices else f"Metrics available for {len(sel_indices)} selected module(s)"
        )

    def _refresh_selected_text(self):
        total, mods = self.sel.total_counts()
        self.lbl_selected_header.configure(text=f"{total} metric(s) across {mods} module(s)" if mods else "(none)")
        self.txt_selected.config(state="normal")
        self.txt_selected.delete("1.0", "end")
        if not mods:
            self.txt_selected.insert("end", "(none)\n")
        else:
            for mod in sorted(self.sel.selected.keys()):
                items = sorted(self.sel.selected[mod])
                self.txt_selected.insert("end", f"[{mod}] — {len(items)} metric(s)\n")
                for m in items:
                    self.txt_selected.insert("end", f"  • {m}\n")
                self.txt_selected.insert("end", "\n")
        self.txt_selected.config(state="disabled")

    # ---- selection actions ----
    def _select_all_metrics(self):
        self.lst_metrics.select_set(0, "end")
        self.lst_metrics.activate("end")
        self._set_status("All metrics selected in the middle list.", ok=True)

    def _clear_metric_selection(self):
        self.lst_metrics.selection_clear(0, "end")
        self._set_status("Cleared metric selection.", ok=True)

    def _add_metrics(self):
        sel_idx = self.lst_modules.curselection()
        if not sel_idx:
            self._set_status("Select one or more modules first (left list).", ok=False); return
        modules = [self.lst_modules.get(i) for i in sel_idx]
        metrics = [self.lst_metrics.get(i) for i in self.lst_metrics.curselection()]
        if not metrics:
            self._set_status("Select one or more metrics to add (middle list).", ok=False); return
        self.sel.add_to_modules(modules, metrics)
        self._refresh_selected_text()
        self._set_status(f"Added {len(metrics)} metric(s) to {len(modules)} module(s).", ok=True)

    def _remove_metrics(self):
        sel_idx = self.lst_modules.curselection()
        if not sel_idx:
            self._set_status("Select the module(s) to remove from (left list).", ok=False); return
        modules = [self.lst_modules.get(i) for i in sel_idx]
        metrics = [self.lst_metrics.get(i) for i in self.lst_metrics.curselection()]
        if not metrics:
            self._set_status("Select one or more metrics in the middle list to remove.", ok=False); return
        self.sel.remove_from_modules(modules, metrics)
        self._refresh_selected_text()
        self._set_status("Removed selected metrics from highlighted module(s).", ok=True)

    def _clear_all_selected(self):
        if not self.sel.selected:
            self._set_status("Nothing to clear.", ok=False); return
        self.sel.clear_all()
        self._refresh_selected_text()
        self._set_status("Cleared all selected metrics.", ok=True)

    # ---- output ----
    def _collect_form_values(self):
        title = (self.ent_title.get() or "SNMP — Generated Dashboard").strip()
        ds_name = (self.ent_ds_name.get() or "Prometheus").strip()
        ds_uid  = (self.ent_ds_uid.get() or "").strip()
        refresh = (self.ent_refresh.get() or "10s").strip()
        time_from = (self.ent_time_from.get() or "now-24h").strip()
        time_to   = (self.ent_time_to.get() or "now").strip()
        job_default = (self.ent_job_default.get() or "snmp").strip()
        mode = self.export_mode.get()  # "ui" or "api"
        return title, ds_name, ds_uid, refresh, time_from, time_to, job_default, mode

    def _preview_json(self):
        model = self._build_dashboard()
        if model is None: return
        self.txt_preview.config(state="normal")
        self.txt_preview.delete("1.0", "end")
        self.txt_preview.insert("end", json.dumps(model, indent=2))
        self.txt_preview.config(state="disabled")
        self._set_status("Preview generated.", ok=True)

    def _copy_json_to_clipboard(self):
        model = self._build_dashboard()
        if model is None: return
        js = json.dumps(model, indent=2)
        self.clipboard_clear(); self.clipboard_append(js)
        self._set_status("Dashboard JSON copied to clipboard.", ok=True)

    def _save_json(self):
        model = self._build_dashboard()
        if model is None: return
        js = json.dumps(model, indent=2)
        dt = datetime.now().strftime("%Y%m%d_%H%M%S")
        default_name = f"snmp_dashboard_{dt}.json"
        path = filedialog.asksaveasfilename(
            title="Save Grafana dashboard JSON",
            defaultextension=".json",
            initialfile=default_name,
            filetypes=[("JSON", "*.json"), ("All files", "*.*")]
        )
        if not path:
            self._set_status("Save canceled.", ok=False); return
        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write(js)
            self._set_status(f"Saved: {path}", ok=True)
        except Exception as e:
            self._set_status(f"Save failed: {e}", ok=False)

    def _build_dashboard(self):
        if not self.modules_to_metrics:
            self._set_status("No modules loaded. Click 'Load from pulled snmp.yml' first.", ok=False); return None
        if not self.sel.selected:
            self._set_status("Select at least one metric.", ok=False); return None

        pairs = []
        for mod in sorted(self.sel.selected.keys()):
            for m in sorted(self.sel.selected[mod]):
                pairs.append((mod, m))

        title, ds_name, ds_uid, refresh, t_from, t_to, job_def, mode = self._collect_form_values()

        return build_dashboard_model(
            title=title,
            datasource_name=ds_name,
            datasource_uid=ds_uid or None,
            refresh=refresh,
            time_from=t_from,
            time_to=t_to,
            job_default=job_def,
            pairs=pairs,
            export_mode=mode,
        )
