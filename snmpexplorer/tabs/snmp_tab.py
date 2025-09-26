import tkinter as tk
from tkinter import ttk, messagebox, simpledialog, filedialog
from ruamel.yaml.comments import CommentedMap, CommentedSeq
from common.context import AppState
from common.yaml_rt import yaml_dump, yaml_load
from common.sshio import sftp_write, ssh_exec
from common.diff import show_diff_window
from common.notify import toast
from common.sshio import _sudo_wrap, ssh_exec, probe_snmp_metrics
from common.service_status import summarize_snmp_status
# NEW: ruamel helpers for safe quoting & preserving YAML shape
from ruamel.yaml.comments import CommentedMap, CommentedSeq
from ruamel.yaml.scalarstring import DoubleQuotedScalarString as DQ


class SnmpTab(ttk.Frame):
    def __init__(self, master, state: AppState):
        super().__init__(master)
        self.state = state
        self._build()
                # After UI/events are ready, wrap edits so we clean after each change
        if hasattr(self, "_install_cleanup_hooks"):
            self._install_cleanup_hooks()


    def _build(self):
        outer = ttk.Frame(self); outer.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        top = ttk.Frame(outer); top.pack(fill=tk.X)
        ttk.Button(top, text="Diff vs original", command=self.on_diff).pack(side=tk.LEFT)
        ttk.Button(top, text="Push to Pi", command=self.on_push).pack(side=tk.LEFT, padx=6)
        ttk.Button(top, text="Export to file…", command=self.on_export).pack(side=tk.LEFT, padx=6)

        split = ttk.Panedwindow(outer, orient=tk.HORIZONTAL); split.pack(fill=tk.BOTH, expand=True, pady=8)
        left = ttk.LabelFrame(split, text="Modules")
        self.tree_modules = ttk.Treeview(left, columns=("name",), show='tree')
        self.tree_modules.bind('<<TreeviewSelect>>', self.on_select_module)
        self.tree_modules.pack(fill=tk.BOTH, expand=True)
        split.add(left, weight=1)

        right = ttk.Notebook(split); split.add(right, weight=3)

        # Walk editor
        fr_walk = ttk.Frame(right); right.add(fr_walk, text="Walk OIDs")
        walk_top = ttk.Frame(fr_walk); walk_top.pack(fill=tk.X)
        ttk.Button(walk_top, text="Add OID", command=self.on_add_walk).pack(side=tk.LEFT)
        ttk.Button(walk_top, text="Remove selected", command=self.on_remove_walk).pack(side=tk.LEFT, padx=6)
        ttk.Button(walk_top, text="Paste list…", command=self.on_paste_walk).pack(side=tk.LEFT, padx=6)
        self.list_walk = tk.Listbox(fr_walk, selectmode=tk.EXTENDED); self.list_walk.pack(fill=tk.BOTH, expand=True, pady=6)

        # Metrics editor
        fr_metrics = ttk.Frame(right); right.add(fr_metrics, text="Metrics")
        topm = ttk.Frame(fr_metrics); topm.pack(fill=tk.X)
        ttk.Button(topm, text="Add metric", command=self.on_add_metric).pack(side=tk.LEFT)
        ttk.Button(topm, text="Edit metric", command=self.on_edit_metric).pack(side=tk.LEFT, padx=6)
        ttk.Button(topm, text="Remove metric", command=self.on_remove_metric).pack(side=tk.LEFT, padx=6)
        self.tree_metrics = ttk.Treeview(fr_metrics, columns=("name","oid","type","help"), show='headings')
        for col, w in [("name",240),("oid",220),("type",100),("help",400)]:
            self.tree_metrics.heading(col, text=col.title()); self.tree_metrics.column(col, width=w, anchor=tk.W)
        self.tree_metrics.pack(fill=tk.BOTH, expand=True, pady=6)

        # Advanced YAML
        fr_adv = ttk.Frame(right); right.add(fr_adv, text="Advanced (YAML)")
        self.txt_module_yaml = tk.Text(fr_adv, wrap=tk.NONE, height=18)
        self._add_scroll(fr_adv, self.txt_module_yaml)
        lbl_adv = ttk.Label(fr_adv, text="Raw module body. Edit carefully. Click Apply to sync Walk/Metrics tables.")
        lbl_adv.grid(row=2, column=0, sticky="w", padx=2, pady=(6, 0))
        btn_adv = ttk.Button(fr_adv, text="Apply YAML → tables", command=self.on_apply_module_yaml)
        btn_adv.grid(row=3, column=0, sticky="w", padx=2, pady=6)

    def _add_scroll(self, parent, txt: tk.Text):
        vs = ttk.Scrollbar(parent, orient='vertical', command=txt.yview)
        hs = ttk.Scrollbar(parent, orient='horizontal', command=txt.xview)
        txt.configure(yscrollcommand=vs.set, xscrollcommand=hs.set)
        txt.grid(row=0, column=0, sticky='nsew')
        vs.grid(row=0, column=1, sticky='ns')
        hs.grid(row=1, column=0, sticky='ew')
        parent.columnconfigure(0, weight=1)
        parent.rowconfigure(0, weight=1)

    # ---------- helpers ----------
    def refresh(self):
        if self.state.snmp_doc is None:
            return
        modules = self.state.snmp_doc.get('modules', CommentedMap())
        self.tree_modules.delete(*self.tree_modules.get_children())
        for name in modules.keys():
            self.tree_modules.insert('', tk.END, iid=name, text=name)
        kids = self.tree_modules.get_children()
        if kids:
            self.tree_modules.selection_set(kids[0])
            self.tree_modules.focus(kids[0])
            self.on_select_module()

    def _walk_covers_oid(self, walk_list, oid: str) -> bool:
        parts = str(oid).split(".")
        for w in (walk_list or []):
            wparts = str(w).split(".")
            if len(wparts) <= len(parts) and parts[:len(wparts)] == wparts:
                return True
        return False

    def current_module_name(self):
        sel = self.tree_modules.selection()
        return sel[0] if sel else None

    def _get_current_module(self) -> CommentedMap:
        name = self.current_module_name()
        if self.state.snmp_doc is None:
            raise RuntimeError("No snmp.yml loaded")
        modules = self.state.snmp_doc.setdefault('modules', CommentedMap())
        if not name:
            name = simpledialog.askstring("New module", "Module name:", parent=self)
            if not name:
                raise RuntimeError("No module selected")
            modules.setdefault(name, CommentedMap())
            self.refresh()
            self.tree_modules.selection_set(name)
        return modules.setdefault(name, CommentedMap())

    # ---------- events ----------
    def on_select_module(self, _e=None):
        name = self.current_module_name()
        if not name or self.state.snmp_doc is None:
            return
        mod = self.state.snmp_doc.setdefault('modules', CommentedMap()).get(name, CommentedMap())

        # Walk
        self.list_walk.delete(0, tk.END)
        walk = mod.get('walk', CommentedSeq()) or []
        for oid in walk:
            self.list_walk.insert(tk.END, str(oid))

        # Metrics
        self.tree_metrics.delete(*self.tree_metrics.get_children())
        for m in (mod.get('metrics', []) or []):
            if isinstance(m, dict):
                self.tree_metrics.insert('', tk.END, values=(m.get('name',''), m.get('oid',''), m.get('type',''), m.get('help','')))

        # Advanced YAML
        self.txt_module_yaml.delete('1.0', tk.END)
        self.txt_module_yaml.insert(tk.END, yaml_dump(CommentedMap(mod)))

    # Walk handlers
    def on_add_walk(self):
        mod = self._get_current_module()
        oid = simpledialog.askstring("Add OID", "Numeric OID (e.g., 1.3.6.1.4.1...):", parent=self)
        if not oid: return
        walk = mod.setdefault('walk', CommentedSeq())
        if oid not in walk:
            walk.append(oid)
        self.on_select_module()

    def on_paste_walk(self):
        mod = self._get_current_module()
        data = simpledialog.askstring("Paste OIDs", "Paste OIDs (one per line):", parent=self)
        if not data: return
        walk = mod.setdefault('walk', CommentedSeq())
        for ln in data.splitlines():
            oid = ln.strip()
            if oid and oid not in walk:
                walk.append(oid)
        self.on_select_module()

    def on_remove_walk(self):
        mod = self._get_current_module()
        sel = list(self.list_walk.curselection())
        if not sel: return
        walk = mod.setdefault('walk', CommentedSeq())
        for idx in reversed(sel):
            try: del walk[idx]
            except Exception: pass
        self.on_select_module()

    # Metric dialogs
    def _edit_metric_dialog(self, init=None):
        init = init or {}
        dlg = tk.Toplevel(self); dlg.title("Metric"); dlg.grab_set()
        vals = {
            'name': tk.StringVar(value=init.get('name','')),
            'oid':  tk.StringVar(value=init.get('oid','')),
            'type': tk.StringVar(value=init.get('type','gauge')),
            'help': tk.StringVar(value=init.get('help','')),
            'units': tk.StringVar(value=init.get('units','')),
        }
        def row(label, var):
            fr = ttk.Frame(dlg); fr.pack(fill=tk.X, padx=10, pady=4)
            ttk.Label(fr, text=label, width=12).pack(side=tk.LEFT)
            ttk.Entry(fr, textvariable=var, width=52).pack(side=tk.LEFT, fill=tk.X, expand=True)

        row("name", vals['name'])
        row("oid",  vals['oid'])
        frt = ttk.Frame(dlg); frt.pack(fill=tk.X, padx=10, pady=4)
        ttk.Label(frt, text="type", width=12).pack(side=tk.LEFT)
        cmb = ttk.Combobox(frt, textvariable=vals['type'],
                           values=["gauge","counter","enum","bits","timeticks","string"])
        cmb.state(["readonly"]); cmb.pack(side=tk.LEFT)
        row("help", vals['help'])
        row("units", vals['units'])

        res = {}
        br = ttk.Frame(dlg); br.pack(fill=tk.X, pady=8)
        def ok():
            res.update({k:v.get().strip() for k,v in vals.items()})
            if not res['name']: messagebox.showwarning("Metric","Name is required",parent=dlg); return
            if not res['oid']:  messagebox.showwarning("Metric","OID is required", parent=dlg); return
            dlg.destroy()
        def cancel(): res.clear(); dlg.destroy()
        ttk.Button(br, text="OK", command=ok).pack(side=tk.RIGHT, padx=6)
        ttk.Button(br, text="Cancel", command=cancel).pack(side=tk.RIGHT)
        dlg.wait_window()
        return res or None

    def on_add_metric(self):
        mod = self._get_current_module()
        dto = self._edit_metric_dialog()
        if not dto: return
        metrics = mod.setdefault('metrics', CommentedSeq())
        metrics.append(CommentedMap(dto))
        w = mod.setdefault('walk', CommentedSeq())
        if not self._walk_covers_oid(w, dto['oid']):
            if messagebox.askyesno("Walk coverage", f"Walk does not cover {dto['oid']}. Add it to walk?"):
                w.append(dto['oid'])
        self.on_select_module()

    def on_edit_metric(self):
        mod = self._get_current_module()
        row = self.tree_metrics.selection()
        if not row: return
        idx = self.tree_metrics.index(row[0])
        metrics = mod.setdefault('metrics', CommentedSeq())
        if idx < 0 or idx >= len(metrics): return
        cur = metrics[idx]
        dto = self._edit_metric_dialog(dict(cur))
        if not dto: return
        metrics[idx] = CommentedMap(dto)
        w = mod.setdefault('walk', CommentedSeq())
        if not self._walk_covers_oid(w, dto['oid']):
            if messagebox.askyesno("Walk coverage", f"Walk does not cover {dto['oid']}. Add it to walk?"):
                w.append(dto['oid'])
        self.on_select_module()

    def on_remove_metric(self):
        mod = self._get_current_module()
        rows = list(self.tree_metrics.selection())
        if not rows: return
        metrics = mod.setdefault('metrics', CommentedSeq())
        for r in sorted((self.tree_metrics.index(i) for i in rows), reverse=True):
            try: del metrics[r]
            except Exception: pass
        self.on_select_module()

    def on_apply_module_yaml(self):
        name = self.current_module_name()
        if not name:
            return
        try:
            body = yaml_load(self.txt_module_yaml.get('1.0', tk.END)) or {}
            cleaned, fx, er = self._clean_module(name, body)
            self.state.snmp_doc.setdefault('modules', CommentedMap())[name] = CommentedMap(cleaned)
            if hasattr(self, "on_select_module"):
                self.on_select_module()
            msg = []
            if fx: msg.append("Fixes: " + "; ".join(fx[:8]) + (" ..." if len(fx) > 8 else ""))
            if er: msg.append("Errors: " + "; ".join(er[:8]) + (" ..." if len(er) > 8 else ""))
            toast(self, "Applied YAML → tables", "\n".join(msg) or "OK", ok=(not er))
        except Exception as e:
            messagebox.showerror("Module YAML", str(e))


    # Diff/Push/Export
    def on_diff(self):
        if self.state.snmp_doc is None: return
        new_text = yaml_dump(self.state.snmp_doc)
        show_diff_window(self, "snmp.yml — Diff", self.state.orig_snmp_text, new_text, self.state.ssh.snmp_path)

    def on_export(self):
        if self.state.snmp_doc is None: return
        path = filedialog.asksaveasfilename(title="Save snmp.yml", defaultextension=".yml",
                                            filetypes=[("YAML","*.yml *.yaml")])
        if not path: return
        with open(path, 'w', encoding='utf-8') as f:
            f.write(yaml_dump(self.state.snmp_doc))
        messagebox.showinfo("Saved", path)

    def _sanitize_snmp_doc(self, doc: dict) -> dict:
        """
        Remove keys unsupported by snmp_exporter from each metric.
        Allowed keys (per 0.24.x): name, oid, type, help, indexes, lookups,
        enum_values, regex_extracts, allow_duplicates.
        """
        if not isinstance(doc, dict):
            return doc
        allowed = {
            "name", "oid", "type", "help",
            "indexes", "lookups", "enum_values", "regex_extracts", "allow_duplicates"
        }
        modules = doc.get("modules", {})
        if isinstance(modules, dict):
            for mname, mval in modules.items():
                if not isinstance(mval, dict):
                    continue
                metrics = mval.get("metrics")
                if isinstance(metrics, list):
                    for i, metric in enumerate(metrics):
                        if isinstance(metric, dict):
                            # strip unknown keys
                            bad = [k for k in list(metric.keys()) if k not in allowed]
                            for k in bad:
                                metric.pop(k, None)
        return doc

    def _probe_metrics_resilient(self, ssh) -> tuple[bool, int, str]:
        """
        Try curl, then wget, then python3 on the Pi to fetch /metrics.
        Returns (ok, line_count, why)
        """
        from common.sshio import ssh_exec, _sudo_wrap
        port = getattr(ssh, "snmp_port", 9116)
        url  = f"http://127.0.0.1:{port}/metrics"
        # 1) curl
        code, out, err = ssh_exec(ssh, f"curl -sS --max-time 3 {url} 2>/dev/null || true")
        if out:
            lines = out.splitlines()
            return True, len(lines), ""
        # 2) wget
        code, out, err = ssh_exec(ssh, f"wget -qO- {url} 2>/dev/null || true")
        if out:
            lines = out.splitlines()
            return True, len(lines), ""
        # 3) python3 stdlib
        py = (
            "python3 - <<'PY'\n"
            "import sys, urllib.request\n"
            f"u='{url}'\n"
            "try:\n"
            "    with urllib.request.urlopen(u, timeout=3) as r:\n"
            "        sys.stdout.write(r.read().decode('utf-8','replace'))\n"
            "except Exception as e:\n"
            "    sys.stderr.write(str(e))\n"
            "PY\n"
        )
        code, out, err = ssh_exec(ssh, py)
        if out:
            lines = out.splitlines()
            return True, len(lines), ""
        why = (err or "").strip() or "no curl/wget/python fetch"
        return False, 0, why


    def on_push(self):
        try:
            if self.state.snmp_doc is None:
                return

            # 0) Clean & validate entire document (quotes, types, dedupe, walk)
            doc, fixes, errs = self._clean_all_modules()
            if errs:
                messagebox.showerror(
                    "snmp.yml validation",
                    "Cannot push — fix these issues first:\n• " + "\n• ".join(errs[:12]) + ("..." if len(errs) > 12 else "")
                )
                return
            if fixes:
                toast(self, "snmp.yml cleanup",
                     f"Applied {len(fixes)} fix(es)\n" + "\n".join(fixes[:8]) + (" ..." if len(fixes) > 8 else ""),
                     ok=True)

            # ---- resolve paths ----
            target = getattr(self.state.ssh, "snmp_path", "/etc/snmp_exporter/snmp.yml")
            staging = getattr(self.state.ssh, "staging_dir", "/var/lib/snmptool")
            if not staging or not staging.startswith("/"):
                staging = "/var/lib/snmptool"

            # ---- sanitize + serialize local YAML (normalize LF, final \n) ----
            doc = self._sanitize_snmp_doc(self.state.snmp_doc)
            local_text = yaml_dump(doc).replace("\r\n", "\n").replace("\r", "\n")
            if not local_text.endswith("\n"):
                local_text += "\n"

            # ---- upload to staging ----
            from common.sshio import sftp_write, sftp_read, ssh_exec
            import time, os, hashlib
            tmp_remote = f"{staging}/snmp_push_{int(time.time())}_{os.getpid()}.yml"
            sftp_write(self.state.ssh, tmp_remote, local_text)
            wrote_with = "sftp->staging"

            # ---- atomic install with correct perms/group ----
            inst_cmd = (
                f"install -m 0664 -o root -g snmpexp {tmp_remote} {target} "
                f"&& rm -f {tmp_remote} || (rm -f {tmp_remote}; false)"
            )
            code_inst, out_inst, err_inst = ssh_exec(self.state.ssh, _sudo_wrap(self.state.ssh, inst_cmd))
            if code_inst != 0:
                raise RuntimeError(f"sudo install failed: {err_inst or out_inst or code_inst}")
            try:
                # keep your existing exporter-compat sanitizer if present
                if hasattr(self, "_sanitize_snmp_doc"):
                    doc = self._sanitize_snmp_doc(doc)
            except Exception:
                pass

            local_text = yaml_dump(doc).replace("\r\n", "\n").replace("\r", "\n")
            if not local_text.endswith("\n"):
                local_text += "\n"
                
            # ---- read back via SFTP (exact bytes), fallback sudo cat ----
            try:
                remote_text = sftp_read(self.state.ssh, target)
                if isinstance(remote_text, bytes):
                    remote_text = remote_text.decode("utf-8", errors="replace")
            except Exception:
                code_chk, out_chk, _ = ssh_exec(self.state.ssh, _sudo_wrap(self.state.ssh, f"cat {target} || true"))
                remote_text = out_chk or ""
            remote_text = remote_text.replace("\r\n", "\n").replace("\r", "\n")
            if not remote_text.endswith("\n"):
                remote_text += "\n"

            # ---- byte-length + sha equality ----
            sha = lambda s: hashlib.sha256(s.encode("utf-8", errors="replace")).hexdigest()
            ok_written = (len(remote_text) == len(local_text) and sha(remote_text) == sha(local_text))

            # ---- restart exporter and probe (resilient) ----
            svc = self.state.ssh.snmp_service

            # restart service quietly
            ssh_exec(self.state.ssh, _sudo_wrap(self.state.ssh, f"systemctl restart {svc} || true"))

            # check active state via exit code (no stdout pollution)
            code_active, _, _ = ssh_exec(self.state.ssh, _sudo_wrap(self.state.ssh, f"systemctl is-active --quiet {svc}"))
            active_label = "active" if code_active == 0 else "inactive"

            # listening check stays as-is
            code_listen, out_listen, _ = ssh_exec(
                self.state.ssh, _sudo_wrap(self.state.ssh, "ss -lntp | grep 9116 || true")
            )

            # resilient probe for metrics
            ok_metrics, nlines, why_probe = self._probe_metrics_resilient(self.state.ssh)

            # ---- build summary ----
            summary_lines = [
                f"Write method: {wrote_with}",
                ("Remote file verification: OK (bytes match)"
                if ok_written else "Remote file verification: FAILED (mismatch)"),
                f"Service active: {active_label}",
                f"Listening on :9116: {'YES' if out_listen.strip() else 'NO'}",
                f"Scrape probe: {'OK' if ok_metrics else 'FAILED'} ({nlines} lines)",
            ]
            if not ok_metrics and why_probe:
                summary_lines.append(f"Probe detail: {why_probe}")


            summary = "\n".join(summary_lines)

            if ok_written:
                self.state.orig_snmp_text = local_text

            toast(
                self,
                "SNMP Exporter push " + ("OK" if (ok_written and ok_metrics) else "Issues"),
                summary,
                ok=(ok_written and ok_metrics),
            )

        except Exception as e:
            messagebox.showerror("Push error", str(e))

                # ================== SANITY / CLEANUP HELPERS ==================
    _ALLOWED_TYPES = {"gauge", "counter", "enum", "bits", "timeticks", "OctetString"}
    _TYPE_MAP = {
        "string": "OctetString",
        "octetstring": "OctetString",
        "octet_string": "OctetString",
        "str": "OctetString",
    }

    def _dq(self, s: str) -> DQ:
        """Force double-quoted scalar (for help text)."""
        return DQ("" if s is None else str(s))

    def _ensure_seq(self, val) -> CommentedSeq:
        """Coerce any value to a YAML sequence we can safely manipulate."""
        if isinstance(val, CommentedSeq):
            return val
        seq = CommentedSeq()
        if isinstance(val, list):
            seq.extend(val)
        elif val not in (None, "", [], {}):
            seq.append(val)
        return seq

    def _walk_covers_oid(self, walk_list: list[str], oid: str) -> bool:
        """
        Returns True if any walk root covers this OID.
        Coverage if oid == w or oid startswith w + '.'
        """
        if not oid:
            return True
        for w in walk_list or []:
            w = str(w)
            if oid == w or oid.startswith(w + "."):
                return True
        return False

    def _normalize_metric(self, m: dict) -> tuple[dict, list[str], list[str]]:
        """
        Normalize one metric:
          - trims strings
          - maps type aliases
          - forces help: "double quoted"
          - validates required fields and indexes shape
        Returns (metric, fixes[], errors[]).
        """
        fixes, errs = [], []
        if not isinstance(m, dict):
            return m, fixes, ["metric is not a mapping"]

        # Trim
        for k in ("name", "oid", "type", "help"):
            if k in m and isinstance(m[k], str):
                m[k] = m[k].strip()

        # Requireds
        if not m.get("name"):
            errs.append("missing name")
        if not m.get("oid"):
            errs.append("missing oid")

        # Type normalize/validate
        t = m.get("type", "gauge")
        t_norm = self._TYPE_MAP.get(str(t).strip(), t)
        if t_norm != t:
            fixes.append(f"type '{t}'→'{t_norm}'")
            m["type"] = t_norm
        if m.get("type") not in self._ALLOWED_TYPES:
            errs.append(f"unsupported type '{m.get('type')}'")

        # Help → double-quoted
        if "help" in m and not isinstance(m["help"], DQ):
            m["help"] = self._dq(m["help"])
            fixes.append("help forced to double quotes")

        # Indexes shape: list-of-maps
        idx = m.get("indexes")
        if idx is not None and not isinstance(idx, (list, CommentedSeq)):
            if isinstance(idx, dict):
                m["indexes"] = CommentedSeq([CommentedMap(idx)])
                fixes.append("indexes wrapped into list")
            else:
                errs.append("indexes must be a list of maps")

        return m, fixes, errs

    def _dedupe_metrics(self, metrics: list[dict]) -> tuple[list[dict], list[str]]:
        """Keep the last copy per metric name; note that we kept the last."""
        fixes = []
        by_name = {}
        for i, mm in enumerate(metrics):
            name = (mm.get("name") or f"_noname_{i}").strip()
            if name in by_name:
                fixes.append(f"duplicate metric '{name}' → kept last")
            by_name[name] = (i, mm)
        # keep only last occurrences, preserving original order where possible
        keep = {i for i, _m in by_name.values()}
        return [m for i, m in enumerate(metrics) if i in keep], fixes

    def _clean_module(self, name: str, mod: dict) -> tuple[dict, list[str], list[str]]:
        """
        Clean a single module:
          - ensure walk/metrics are sequences
          - normalize each metric
          - dedupe by name (last wins)
          - add any missing OIDs to walk for coverage
        Returns (module, fixes[], errors[]).
        """
        fixes, errs = [], []
        if not isinstance(mod, dict):
            return mod, fixes, [f"module '{name}' is not a mapping"]

        mod["walk"] = self._ensure_seq(mod.get("walk") or [])
        mod["metrics"] = self._ensure_seq(mod.get("metrics") or [])

        # Normalize metrics
        new_metrics, mf = [], []
        for m in list(mod["metrics"]):
            nm, fx, er = self._normalize_metric(dict(m))
            mf.extend(fx)
            if er:
                errs.append(f"{nm.get('name','(no name)')}: {', '.join(er)}")
                continue
            new_metrics.append(CommentedMap(nm))

        # Deduplicate
        new_metrics, fx2 = self._dedupe_metrics(new_metrics)
        mf.extend(fx2)

        # Ensure walk covers all metric OIDs
        have = [str(w) for w in mod["walk"]]
        for m in new_metrics:
            oid = str(m.get("oid") or "")
            if oid and not self._walk_covers_oid(have, oid):
                mod["walk"].append(oid)
                have.append(oid)
                mf.append(f"walk + {oid}")

        mod["metrics"] = self._ensure_seq(new_metrics)
        if mf:
            fixes.extend(mf)
        return mod, fixes, errs

    def _clean_all_modules(self) -> tuple[dict, list[str], list[str]]:
        """Clean entire snmp_doc; returns (doc, fixes[], errors[])."""
        doc = self.state.snmp_doc or {}
        fixes, errs = [], []
        modules = doc.get("modules") or CommentedMap()
        if not isinstance(modules, (dict, CommentedMap)):
            return doc, fixes, ["'modules' is not a mapping"]

        for name, mod in list(modules.items()):
            new_mod, fx, er = self._clean_module(name, dict(mod))
            modules[name] = CommentedMap(new_mod)
            fixes.extend([f"{name}: {x}" for x in fx])
            errs.extend([f"{name}: {x}" for x in er])

        doc["modules"] = modules
        return doc, fixes, errs

    def _install_cleanup_hooks(self):
        """
        Wrap add/edit/remove handlers (if present) so we auto-clean the current module
        after each edit without you changing those methods.
        """
        def _wrap(name):
            if not hasattr(self, name): return
            orig = getattr(self, name)
            if not callable(orig): return
            def wrapped(*a, **kw):
                r = orig(*a, **kw)
                try:
                    mod_name = self.current_module_name() if hasattr(self, "current_module_name") else None
                    if mod_name:
                        mods = self.state.snmp_doc.setdefault("modules", CommentedMap())
                        cleaned, fx, er = self._clean_module(mod_name, dict(mods.get(mod_name, {})))
                        mods[mod_name] = CommentedMap(cleaned)
                        if fx or er:
                            msg = []
                            if fx: msg.append("Fixes: " + "; ".join(fx[:6]) + (" ..." if len(fx) > 6 else ""))
                            if er: msg.append("Errors: " + "; ".join(er[:6]) + (" ..." if len(er) > 6 else ""))
                            toast(self, "Metric cleanup", "\n".join(msg) or "OK", ok=(not er))
                        # refresh the UI if you have a method for it
                        if hasattr(self, "on_select_module"):
                            self.on_select_module()
                except Exception:
                    pass
                return r
            setattr(self, name, wrapped)

        for fn in ("on_add_metric", "on_edit_metric", "on_remove_metric"):
            _wrap(fn)
    # ================== /SANITY / CLEANUP HELPERS ==================


