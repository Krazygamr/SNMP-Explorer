import json
import re
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from ruamel.yaml.comments import CommentedMap, CommentedSeq
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple
from common.context import AppState

# --- Data model ----------------------------------------------------------------

@dataclass
class CatalogOID:
    oid: str
    name: str
    category: str = "uncategorized"           # category KEY (e.g. "fgSystem")
    subcategory: Optional[str] = None
    description: str = ""
    metric: Optional[Dict[str, Any]] = None   # {name, oid, type, help, units?, enum_values?, bit_labels?}
    units: Optional[str] = None
    syntax_raw: Optional[str] = None          # e.g., "Gauge32", "Counter64", "INTEGER { up(1), down(2) }"
    access: Optional[str] = None              # e.g., "read-only"
    module: Optional[str] = None
    tags: List[str] = field(default_factory=list)

# --- Helpers -------------------------------------------------------------------

def _walk_covers_oid(walk_list, oid: str) -> bool:
    parts = str(oid).split(".")
    for w in (walk_list or []):
        wparts = str(w).split(".")
        if len(wparts) <= len(parts) and parts[:len(wparts)] == wparts:
            return True
    return False

_ENUM_RE = re.compile(r"INTEGER\s*\{.+\}", re.IGNORECASE | re.DOTALL)
_BITS_RE = re.compile(r"BITS\b", re.IGNORECASE)
_TIMETICKS_RE = re.compile(r"TimeTicks\b", re.IGNORECASE)
_COUNTER_RE = re.compile(r"Counter(?:32|64)\b", re.IGNORECASE)
_GAUGE_RE = re.compile(r"Gauge32\b|Unsigned32\b", re.IGNORECASE)
_STRING_RE = re.compile(r"OCTET\s+STRING\b", re.IGNORECASE)
_IP_RE = re.compile(r"IPAddress\b", re.IGNORECASE)

_DEF_TYPE = "gauge"

# Returns (type, extras) where extras may include enum_values or bit_labels
# This is intentionally conservative; we only infer when confident.

def infer_metric_type(syntax_raw: Optional[str]) -> Tuple[str, Dict[str, Any]]:
    s = (syntax_raw or "").strip()
    extras: Dict[str, Any] = {}
    if not s:
        return _DEF_TYPE, extras

    if _COUNTER_RE.search(s):
        return "counter", extras
    if _TIMETICKS_RE.search(s):
        return "timeticks", extras
    if _BITS_RE.search(s):
        labels = re.findall(r"([A-Za-z][A-Za-z0-9_-]*)\s*\(\s*\d+\s*\)", s)
        if labels:
            extras["bit_labels"] = labels
        return "bits", extras
    if _ENUM_RE.search(s):
        enums = re.findall(r"([A-Za-z][A-Za-z0-9_-]*)\s*\(\s*(\d+)\s*\)", s)
        if enums:
            extras["enum_values"] = {int(num): name for name, num in enums}
        return "enum", extras
    if _GAUGE_RE.search(s):
        return "gauge", extras
    if _STRING_RE.search(s) or _IP_RE.search(s):
        return "string", extras
    if re.search(r"\bINTEGER\b", s, re.IGNORECASE):
        return "gauge", extras
    return _DEF_TYPE, extras

# --- Module editor -------------------------------------------------------------

class ModuleEditor(tk.Toplevel):
    """A simple manager to view/edit walks & metrics for one module with safety checks.
    We mutate the provided snmp_doc in place so no extra save step is required.
    """
    def __init__(self, master, snmp_doc: Dict[str, Any], module_name: str, on_close=None):
        super().__init__(master)
        self.title(f"Manage Module — {module_name}")
        self.snmp_doc = snmp_doc
        self.module_name = module_name
        self.on_close = on_close
        self.transient(master)
        self.grab_set()

        mods = self.snmp_doc.setdefault('modules', CommentedMap())
        self.mod = mods.setdefault(module_name, CommentedMap())
        self.walk: CommentedSeq = self.mod.setdefault('walk', CommentedSeq())
        self.metrics: CommentedSeq = self.mod.setdefault('metrics', CommentedSeq())

        # Layout
        root = ttk.Frame(self); root.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        panes = ttk.Panedwindow(root, orient=tk.HORIZONTAL)
        panes.pack(fill=tk.BOTH, expand=True)

        # Walks panel
        walks_fr = ttk.Labelframe(panes, text="Walks")
        self.lb_walks = tk.Listbox(walks_fr, height=15, exportselection=False)
        self.lb_walks.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        sbw = ttk.Scrollbar(walks_fr, orient=tk.VERTICAL, command=self.lb_walks.yview)
        self.lb_walks.configure(yscrollcommand=sbw.set)
        sbw.pack(side=tk.RIGHT, fill=tk.Y)

        walk_controls = ttk.Frame(walks_fr)
        walk_controls.pack(fill=tk.X, pady=(6,0))
        self.var_new_walk = tk.StringVar()
        ttk.Entry(walk_controls, textvariable=self.var_new_walk).pack(side=tk.LEFT, fill=tk.X, expand=True)
        ttk.Button(walk_controls, text="Add", command=self._add_walk).pack(side=tk.LEFT, padx=4)
        ttk.Button(walk_controls, text="Remove", command=self._remove_walk).pack(side=tk.LEFT)

        panes.add(walks_fr, weight=1)

        # Metrics panel
        metrics_fr = ttk.Labelframe(panes, text="Metrics")
        cols = ("name","oid","type","help")
        self.tv_metrics = ttk.Treeview(metrics_fr, columns=cols, show="headings", height=15)
        for c, w in [("name",200),("oid",220),("type",100),("help",400)]:
            self.tv_metrics.heading(c, text=c.title())
            self.tv_metrics.column(c, width=w, anchor=tk.W)
        self.tv_metrics.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        sbm = ttk.Scrollbar(metrics_fr, orient=tk.VERTICAL, command=self.tv_metrics.yview)
        self.tv_metrics.configure(yscrollcommand=sbm.set)
        sbm.pack(side=tk.RIGHT, fill=tk.Y)

        metric_controls = ttk.Frame(metrics_fr)
        metric_controls.pack(fill=tk.X, pady=(6,0))
        ttk.Button(metric_controls, text="Remove Selected", command=self._remove_metrics).pack(side=tk.LEFT)

        panes.add(metrics_fr, weight=2)

        # Bottom buttons
        br = ttk.Frame(root); br.pack(fill=tk.X, pady=(10,0))
        ttk.Button(br, text="Close", command=self._close).pack(side=tk.RIGHT)

        self._refresh_lists()

    # Utility: build list of metric OIDs
    def _metric_oids(self) -> List[str]:
        oids = []
        for m in (self.metrics or []):
            try:
                o = str(m.get('oid',''))
                if o:
                    oids.append(o)
            except Exception:
                pass
        return oids

    def _refresh_lists(self):
        self.lb_walks.delete(0, tk.END)
        for w in (self.walk or []):
            self.lb_walks.insert(tk.END, str(w))

        for i in self.tv_metrics.get_children():
            self.tv_metrics.delete(i)
        for m in (self.metrics or []):
            try:
                self.tv_metrics.insert("", tk.END, values=(m.get('name',''), m.get('oid',''), m.get('type',''), m.get('help','')))
            except Exception:
                pass

    def _add_walk(self):
        w = (self.var_new_walk.get() or '').strip()
        if not w:
            return
        # Basic sanity: dotted numeric OID
        if not re.fullmatch(r"\d+(?:\.\d+)*", w):
            messagebox.showerror("Walk", "Walk must be a numeric OID (e.g., 1.3.6.1.4.1.12345)")
            return
        if w in self.walk:
            messagebox.showinfo("Walk", "Already present.")
            return
        self.walk.append(w)
        self.var_new_walk.set("")
        self._refresh_lists()

    def _remove_walk(self):
        sel = list(self.lb_walks.curselection())
        if not sel:
            return
        idx = sel[0]
        w = str(self.lb_walks.get(idx))
        # Safety: block removal if a metric OID is covered by this walk
        covered = [oid for oid in self._metric_oids() if _walk_covers_oid([w], oid)]
        if covered:
            sample = "\n".join(covered[:8]) + ("\n…" if len(covered) > 8 else "")
            messagebox.showwarning(
                "Walk in use",
                "Cannot remove this walk because these metric OIDs depend on it:\n\n" + sample
            )
            return
        # OK to remove
        try:
            del self.walk[idx]
        except Exception:
            # Fallback linear search
            try:
                self.walk.remove(w)
            except Exception:
                pass
        self._refresh_lists()

    def _remove_metrics(self):
        sel = self.tv_metrics.selection()
        if not sel:
            return
        names = [self.tv_metrics.item(i, 'values')[0] for i in sel]
        if not messagebox.askyesno("Remove metrics", f"Remove {len(sel)} metric(s)?\n\n" + "\n".join(names[:6]) + ("\n…" if len(sel) > 6 else "")):
            return
        # Remove by OID match to be robust
        sel_oids = set(self.tv_metrics.item(i, 'values')[1] for i in sel)
        keep = CommentedSeq([m for m in self.metrics if str(m.get('oid','')) not in sel_oids])
        # Replace in place to preserve ruamel semantics
        self.mod['metrics'].clear()
        for m in keep:
            self.mod['metrics'].append(m)
        self._refresh_lists()

    def _close(self):
        try:
            if callable(self.on_close):
                self.on_close()
        finally:
            self.destroy()

# --- Catalog UI ----------------------------------------------------------------

class CatalogTab(ttk.Frame):
    def __init__(self, master, state: AppState):
        super().__init__(master)
        self.state = state
        self.catalog_oids: List[CatalogOID] = []
        self.filtered_catalog: List[CatalogOID] = []

        # title<->key maps for the category combobox
        self._cat_title_to_key: Dict[str, str] = {}
        self._cat_key_to_title: Dict[str, str] = {}

        # Module selection state (mirrors SNMP tab if available)
        self.var_selected_module = tk.StringVar(value="")

        self._build()

    # --- build -----------------------------------------------------------------

    def _build(self):
        outer = ttk.Frame(self); outer.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Top row: load, filter, category, module selector, add button
        top = ttk.Frame(outer); top.pack(fill=tk.X)
        ttk.Button(top, text="Load catalog JSON…", command=self.on_load_catalog).pack(side=tk.LEFT)

        ttk.Label(top, text="Filter:").pack(side=tk.LEFT, padx=(12,4))
        self.var_cat_filter = tk.StringVar()
        ent = ttk.Entry(top, textvariable=self.var_cat_filter, width=40); ent.pack(side=tk.LEFT)
        ent.bind("<KeyRelease>", lambda _e: self.refresh())

        ttk.Label(top, text="Category:").pack(side=tk.LEFT, padx=(12,4))
        self.var_cat_category = tk.StringVar(value="(all)")
        self.cmb_cat = ttk.Combobox(top, textvariable=self.var_cat_category, values=["(all)"])
        self.cmb_cat.state(["readonly"]) ; self.cmb_cat.pack(side=tk.LEFT)
        self.cmb_cat.bind("<<ComboboxSelected>>", lambda _e: self.refresh())

        # Module selector (reflects currently selected module from SNMP tab when possible)
        ttk.Label(top, text="Module:").pack(side=tk.LEFT, padx=(12,4))
        self.cmb_module = ttk.Combobox(top, textvariable=self.var_selected_module, values=["(none)"])
        self.cmb_module.state(["readonly"]) ; self.cmb_module.pack(side=tk.LEFT, padx=(0,8))
        self.cmb_module.bind("<<ComboboxSelected>>", lambda _e: self._on_module_changed())

        ttk.Button(top, text="Add to selected module", command=self.on_add_to_module).pack(side=tk.LEFT, padx=6)
        ttk.Button(top, text="Manage selected module…", command=self.on_manage_module).pack(side=tk.LEFT)

        # Table
        body = ttk.Frame(outer); body.pack(fill=tk.BOTH, expand=True, pady=8)
        wrap = ttk.Frame(body); wrap.pack(fill=tk.BOTH, expand=True)

        self.tree = ttk.Treeview(
            wrap,
            columns=("name","oid","type","category","description"),
            show="headings"
        )
        for col, w in [("name",260),("oid",220),("type",110),("category",180),("description",600)]:
            self.tree.heading(col, text=col.title())
            self.tree.column(col, width=w, anchor=tk.W)

        vsb = ttk.Scrollbar(wrap, orient="vertical", command=self.tree.yview)
        hsb = ttk.Scrollbar(wrap, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        self.tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")
        wrap.columnconfigure(0, weight=1)
        wrap.rowconfigure(0, weight=1)

        self.tree.bind("<Double-1>", lambda _e: self.on_add_to_module())

        ttk.Label(
            outer,
            text=(
                "Tip: If the metric OID is not covered by the module's walk list, "
                "you'll be prompted to add it automatically."
            )
        ).pack(anchor=tk.W, pady=(6,0))

        # Try to populate module list immediately (if snmp_doc is already present)
        self._rebuild_module_combo()

    # --- category helpers ------------------------------------------------------

    def _category_title_for_key(self, key: str) -> str:
        if not key: return ""
        return self._cat_key_to_title.get(key, key)

    def _rebuild_category_combo(self):
        self._cat_title_to_key.clear()
        self._cat_key_to_title.clear()

        titles = ["(all)"]
        cats = (self.state.catalog or {}).get("categories") or {}

        if isinstance(cats, dict):
            pairs = []
            for key, meta in cats.items():
                title = (meta or {}).get("title") or str(key)
                pairs.append((title, key))
            for title, key in sorted(pairs, key=lambda t: t[0].lower()):
                self._cat_title_to_key[title] = key
                self._cat_key_to_title[key] = title
                titles.append(title)
        else:
            for key in sorted(list(cats) if isinstance(cats, list) else []):
                self._cat_title_to_key[str(key)] = str(key)
                self._cat_key_to_title[str(key)] = str(key)
                titles.append(str(key))

        self.cmb_cat.configure(values=titles)
        self.var_cat_category.set("(all)")

    # --- module helpers --------------------------------------------------------

    def _detect_selected_module_name(self) -> Optional[str]:
        name = (self.var_selected_module.get() or "").strip()
        if name:
            return name if name != "(none)" else None

        for attr in ("selected_module", "snmp_selected_module"):
            if hasattr(self.state, attr):
                v = getattr(self.state, attr)
                if isinstance(v, str) and v:
                    return v
        ui = getattr(self.state, "ui", None)
        if isinstance(ui, dict):
            v = ui.get("selected_module")
            if isinstance(v, str) and v:
                return v
        modules = (self.state.snmp_doc or {}).get('modules', {})
        names = list(modules.keys()) if isinstance(modules, dict) else []
        return names[0] if names else None

    def _rebuild_module_combo(self):
        modules = []
        if isinstance(getattr(self.state, 'snmp_doc', None), dict):
            mods = self.state.snmp_doc.get('modules', {})
            if isinstance(mods, dict):
                modules = list(mods.keys())
        modules = modules or []
        values = modules if modules else ["(none)"]
        self.cmb_module.configure(values=values)
        current = self._detect_selected_module_name() or (modules[0] if modules else "")
        self.var_selected_module.set(current or "")

    def _on_module_changed(self):
        name = (self.var_selected_module.get() or "").strip()
        if name and hasattr(self.state, 'selected_module'):
            try:
                setattr(self.state, 'selected_module', name)
            except Exception:
                pass

    # --- actions ---------------------------------------------------------------

    def refresh(self, *_a):
        self.tree.delete(*self.tree.get_children())

        text = (self.var_cat_filter.get() or "").lower().strip()
        cat_title = self.var_cat_category.get()
        cat_key = None
        if cat_title and cat_title != "(all)":
            cat_key = self._cat_title_to_key.get(cat_title, cat_title)

        self.filtered_catalog = []
        for ent in self.catalog_oids:
            if cat_key and ent.category != cat_key:
                continue
            blob = f"{ent.name}\n{ent.oid}\n{ent.description}\n{ent.category}".lower()
            if text and text not in blob:
                continue

            m = ent.metric or {}
            mtype = m.get("type")
            if not mtype:
                inferred_type, _ = infer_metric_type(ent.syntax_raw)
                mtype = inferred_type or _DEF_TYPE
            self.filtered_catalog.append(ent)

            cat_disp = self._category_title_for_key(ent.category)
            self.tree.insert("", tk.END, values=(ent.name, ent.oid, mtype, cat_disp, ent.description))

        self._rebuild_module_combo()

    def on_load_catalog(self):
        path = filedialog.askopenfilename(
            title="Open catalog JSON",
            filetypes=[("JSON","*.json"),("YAML","*.yml *.yaml"),("All","*.*")]
        )
        if not path: return
        try:
            if path.lower().endswith((".yml",".yaml")):
                from common.yaml_rt import yaml_load as _yl
                data = _yl(open(path,"r",encoding="utf-8").read())
            else:
                data = json.loads(open(path,"r",encoding="utf-8").read())
            self.state.catalog = data or {}

            self.catalog_oids = []
            for it in self.state.catalog.get("oids", []) or []:
                self.catalog_oids.append(CatalogOID(
                    oid=str(it.get("oid","")),
                    name=str(it.get("name","")),
                    category=str(it.get("category","uncategorized")),
                    subcategory=it.get("subcategory"),
                    description=str(it.get("description","")),
                    metric=it.get("metric") or None,
                    units=it.get("units"),
                    syntax_raw=it.get("syntax_raw"),
                    access=it.get("access"),
                    module=it.get("module"),
                    tags=it.get("tags") or [],
                ))

            self._rebuild_category_combo()
            self.refresh()
            messagebox.showinfo("Catalog", f"Loaded {len(self.catalog_oids)} OIDs.")
        except Exception as e:
            messagebox.showerror("Catalog", str(e))

    def _pick_type(self, default_type: str = _DEF_TYPE) -> Optional[str]:
        dlg = tk.Toplevel(self); dlg.title("Metric type"); dlg.grab_set()
        var = tk.StringVar(value=default_type or _DEF_TYPE)
        ttk.Label(dlg, text="Select metric type for this OID:").pack(padx=10, pady=(10,4))
        cmb = ttk.Combobox(dlg, textvariable=var, values=["gauge","counter","enum","bits","timeticks","string"])
        cmb.state(["readonly"]); cmb.pack(padx=10, pady=4)
        res = {"ok": False}
        def ok(): res["ok"]=True; dlg.destroy()
        def cancel(): dlg.destroy()
        br = ttk.Frame(dlg); br.pack(pady=8)
        ttk.Button(br, text="OK", command=ok).pack(side=tk.RIGHT, padx=6)
        ttk.Button(br, text="Cancel", command=cancel).pack(side=tk.RIGHT)
        dlg.wait_window()
        return var.get() if res["ok"] else None

    def on_add_to_module(self):
        if self.state.snmp_doc is None:
            messagebox.showwarning("Catalog", "Pull configs first (Connection tab).")
            return

        modules = self.state.snmp_doc.setdefault('modules', CommentedMap())
        if not isinstance(modules, dict) or not modules:
            messagebox.showwarning("Catalog", "Create/select a module in the SNMP tab first.")
            return

        current = self._detect_selected_module_name()
        if not current or current not in modules:
            current = list(modules.keys())[0]
        self.var_selected_module.set(current)

        sel = self.tree.selection()
        if not sel and self.filtered_catalog:
            picked = [self.filtered_catalog[0]]
        else:
            vals = [self.tree.item(i, "values") for i in sel]
            by_oid = {e.oid: e for e in self.filtered_catalog}
            picked = []
            for v in vals:
                name, oid, shown_type, cat_disp, description = v
                e = by_oid.get(oid)
                if not e:
                    e = CatalogOID(
                        oid=oid, name=name, category=self._cat_title_for_disp(cat_disp),
                        description=description,
                        metric={"name": name, "oid": oid, "type": shown_type or _DEF_TYPE, "help": description}
                    )
                picked.append(e)

        if not picked:
            return

        mod = modules.setdefault(current, CommentedMap())
        walk = mod.setdefault("walk", CommentedSeq())
        metrics = mod.setdefault("metrics", CommentedSeq())

        added = 0
        for e in picked:
            default_type = (e.metric or {}).get("type") if e.metric else None
            if not default_type:
                inferred, _ = infer_metric_type(e.syntax_raw)
                default_type = inferred or _DEF_TYPE
            mtype = self._pick_type(default_type or _DEF_TYPE)
            if not mtype:
                continue

            if not _walk_covers_oid(walk, e.oid):
                if messagebox.askyesno("Walk coverage", f"Walk does not cover {e.oid}. Add it to walk?"):
                    walk.append(e.oid)

            mname = (e.metric or {}).get("name") or e.name
            mhelp = (e.metric or {}).get("help") or (e.description or e.name)
            dto = CommentedMap({"name": mname, "oid": e.oid, "type": mtype, "help": mhelp})

            if e.metric:
                for k in ("units", "enum_values", "bit_labels"):
                    if k in e.metric:
                        dto[k] = e.metric[k]

            if not e.metric:
                inferred, extras = infer_metric_type(e.syntax_raw)
                if mtype == inferred:
                    for k in ("enum_values", "bit_labels"):
                        if k in extras and extras[k]:
                            dto[k] = extras[k]

            metrics.append(dto)
            added += 1

        if added:
            messagebox.showinfo("Catalog", f"Added {added} item(s) to module '{current}'.")

    def _cat_title_for_disp(self, disp: str) -> str:
        return self._cat_title_to_key.get(disp, disp)

    def on_manage_module(self):
        if self.state.snmp_doc is None:
            messagebox.showwarning("Module", "Pull configs first (Connection tab).")
            return
        current = self._detect_selected_module_name()
        if not current:
            messagebox.showwarning("Module", "No module selected.")
            return
        ModuleEditor(self, self.state.snmp_doc, current, on_close=self._after_module_edit)

    def _after_module_edit(self):
        # After edits, nothing special is required, but we refresh in case UI needs it.
        self._rebuild_module_combo()
        self.refresh()
