import ssl
import urllib.request, urllib.error, json as jsonlib
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from ruamel.yaml.comments import CommentedMap, CommentedSeq
from common.context import AppState
from common.yaml_rt import yaml_dump, yaml_load
from common.sshio import sftp_write, ssh_exec
from common.diff import show_diff_window

class PromTab(ttk.Frame):
    def __init__(self, master, state: AppState):
        super().__init__(master)
        self.state = state
        self._build()

    def _build(self):
        outer = ttk.Frame(self); outer.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        top = ttk.Frame(outer); top.pack(fill=tk.X)
        ttk.Button(top, text="Diff vs original", command=self.on_diff).pack(side=tk.LEFT)
        ttk.Button(top, text="Push to Pi", command=self.on_push).pack(side=tk.LEFT, padx=6)
        ttk.Button(top, text="Export to file…", command=self.on_export).pack(side=tk.LEFT, padx=6)
        ttk.Button(top, text="Check Prometheus Targets", command=self.on_check_prometheus).pack(side=tk.LEFT, padx=12)
        self.var_prom_url = tk.StringVar(value="http://localhost:9090")
        ttk.Entry(top, textvariable=self.var_prom_url, width=36).pack(side=tk.LEFT)

        split = ttk.Panedwindow(outer, orient=tk.HORIZONTAL); split.pack(fill=tk.BOTH, expand=True, pady=8)
        left = ttk.LabelFrame(split, text="Scrape Jobs")
        self.tree_jobs = ttk.Treeview(left, columns=("job_name",), show='tree')
        self.tree_jobs.bind('<<TreeviewSelect>>', self.on_select_job)
        self.tree_jobs.pack(fill=tk.BOTH, expand=True)
        split.add(left, weight=1)

        right = ttk.LabelFrame(split, text="Job Editor"); split.add(right, weight=3)
        def row(label, var, width=44):
            fr = ttk.Frame(right); fr.pack(fill=tk.X, pady=2)
            ttk.Label(fr, text=label, width=16).pack(side=tk.LEFT)
            e = ttk.Entry(fr, textvariable=var, width=width); e.pack(side=tk.LEFT, fill=tk.X, expand=True)
            return e

        self.var_job_name = tk.StringVar()
        self.var_metrics_path = tk.StringVar()
        self.var_scrape_interval = tk.StringVar()
        self.var_params_module = tk.StringVar()
        self.var_params_auth = tk.StringVar()
        self.var_targets = tk.StringVar()

        row("job_name", self.var_job_name)
        row("metrics_path", self.var_metrics_path)
        row("scrape_interval", self.var_scrape_interval)
        row("params.module", self.var_params_module)
        row("params.auth", self.var_params_auth)
        row("targets (comma/space)", self.var_targets)

        btns = ttk.Frame(right); btns.pack(fill=tk.X, pady=6)
        ttk.Button(btns, text="Apply to job", command=self.on_apply_job_fields).pack(side=tk.LEFT)
        ttk.Button(btns, text="Add job", command=self.on_add_job).pack(side=tk.LEFT, padx=6)
        ttk.Button(btns, text="Remove job", command=self.on_remove_job).pack(side=tk.LEFT, padx=6)

        raw = ttk.LabelFrame(outer, text="prometheus.yml (raw editor)")
        raw.pack(fill=tk.BOTH, expand=True, pady=8)
        self.txt_prom_yaml = tk.Text(raw, wrap=tk.NONE, height=16)
        self._add_scroll(raw, self.txt_prom_yaml)
        btn_apply = ttk.Button(raw, text="Apply raw → structure", command=self.on_apply_prom_yaml)
        btn_apply.grid(row=2, column=0, sticky="w", padx=2, pady=6)

    def _add_scroll(self, parent, txt: tk.Text):
        vs = ttk.Scrollbar(parent, orient='vertical', command=txt.yview)
        hs = ttk.Scrollbar(parent, orient='horizontal', command=txt.xview)
        txt.configure(yscrollcommand=vs.set, xscrollcommand=hs.set)
        txt.grid(row=0, column=0, sticky='nsew')
        vs.grid(row=0, column=1, sticky='ns')
        hs.grid(row=1, column=0, sticky='ew')
        parent.columnconfigure(0, weight=1)
        parent.rowconfigure(0, weight=1)

    def refresh(self):
        if self.state.prom_doc is None:
            return
        self.tree_jobs.delete(*self.tree_jobs.get_children())
        sc = self.state.prom_doc.setdefault('scrape_configs', CommentedSeq())
        for i, cfg in enumerate(sc):
            if not isinstance(cfg, dict): continue
            name = cfg.get('job_name', f"job_{i}")
            self.tree_jobs.insert('', tk.END, iid=name, text=name)
        self.txt_prom_yaml.delete('1.0', tk.END)
        self.txt_prom_yaml.insert(tk.END, yaml_dump(self.state.prom_doc))
        kids = self.tree_jobs.get_children()
        if kids:
            self.tree_jobs.selection_set(kids[0]); self.tree_jobs.focus(kids[0]); self.on_select_job()

    def _find_job_cfg(self, name: str):
        sc = self.state.prom_doc.setdefault('scrape_configs', CommentedSeq())
        for cfg in sc:
            if isinstance(cfg, dict) and cfg.get('job_name') == name:
                return cfg
        return None

    def on_select_job(self, _e=None):
        name = self.current_job_name()
        if not name or self.state.prom_doc is None: return
        cfg = self._find_job_cfg(name)
        if not cfg: return
        self.var_job_name.set(cfg.get('job_name',''))
        self.var_metrics_path.set(cfg.get('metrics_path',''))
        self.var_scrape_interval.set(cfg.get('scrape_interval',''))
        params = cfg.get('params', {}) or {}
        mod = params.get('module', ['']); auth = params.get('auth', [''])
        self.var_params_module.set(mod[0] if isinstance(mod, list) and mod else "")
        self.var_params_auth.set(auth[0] if isinstance(auth, list) and auth else "")
        tgs = []
        for scfg in (cfg.get('static_configs') or []):
            tgs.extend(scfg.get('targets', []) or [])
        self.var_targets.set(", ".join(tgs))

    def current_job_name(self):
        sel = self.tree_jobs.selection()
        return sel[0] if sel else None

    def on_apply_job_fields(self):
        name = self.current_job_name()
        if not name or self.state.prom_doc is None: return
        cfg = self._find_job_cfg(name)
        if not cfg: return
        cfg['job_name'] = self.var_job_name.get().strip()
        if self.var_metrics_path.get().strip():
            cfg['metrics_path'] = self.var_metrics_path.get().strip()
        else:
            cfg.pop('metrics_path', None)
        if self.var_scrape_interval.get().strip():
            cfg['scrape_interval'] = self.var_scrape_interval.get().strip()
        else:
            cfg.pop('scrape_interval', None)
        p = CommentedMap()
        if self.var_params_module.get().strip(): p['module'] = [self.var_params_module.get().strip()]
        if self.var_params_auth.get().strip():   p['auth']   = [self.var_params_auth.get().strip()]
        if p: cfg['params'] = p
        else: cfg.pop('params', None)
        raw = self.var_targets.get().strip()
        targets = [t.strip() for t in (raw.replace(';', ',').replace('\n', ',')).split(',') if t.strip()]
        if targets: cfg['static_configs'] = [CommentedMap({'targets': targets})]
        else:       cfg.pop('static_configs', None)
        if name != cfg['job_name']: self.refresh()
        else:
            self.txt_prom_yaml.delete('1.0', tk.END); self.txt_prom_yaml.insert(tk.END, yaml_dump(self.state.prom_doc))

    def on_add_job(self):
        if self.state.prom_doc is None: return
        name = tk.simpledialog.askstring("New job", "job_name:", parent=self)
        if not name: return
        sc = self.state.prom_doc.setdefault('scrape_configs', CommentedSeq())
        sc.append(CommentedMap({'job_name': name}))
        self.refresh()
        self.tree_jobs.selection_set(name); self.tree_jobs.focus(name); self.on_select_job()

    def on_remove_job(self):
        if self.state.prom_doc is None: return
        name = self.current_job_name()
        if not name: return
        if not messagebox.askyesno("Remove job", f"Delete job '{name}'? This cannot be undone."):
            return
        sc = self.state.prom_doc.setdefault('scrape_configs', CommentedSeq())
        for i, cfg in enumerate(sc):
            if isinstance(cfg, dict) and cfg.get('job_name') == name:
                del sc[i]; break
        self.refresh()

    def on_apply_prom_yaml(self):
        try:
            self.state.prom_doc = yaml_load(self.txt_prom_yaml.get('1.0', tk.END))
            self.refresh()
        except Exception as e:
            messagebox.showerror("prometheus.yml", str(e))

    def on_diff(self):
        if self.state.prom_doc is None: return
        new_text = yaml_dump(self.state.prom_doc)
        show_diff_window(self, "prometheus.yml — Diff", self.state.orig_prom_text, new_text, self.state.ssh.prom_path)

    def on_export(self):
        if self.state.prom_doc is None: return
        path = filedialog.asksaveasfilename(title="Save prometheus.yml", defaultextension=".yml",
                                            filetypes=[("YAML","*.yml *.yaml")])
        if not path: return
        with open(path, 'w', encoding='utf-8') as f:
            f.write(yaml_dump(self.state.prom_doc))
        messagebox.showinfo("Saved", path)

    def on_push(self):
        try:
            if self.state.prom_doc is None:
                return
            text = yaml_dump(self.state.prom_doc)

            from common.sshio import _sudo_wrap, ssh_exec, push_file_with_sudo

            # Optional promtool validation (upload to /tmp and validate there)
            try:
                tmp = "/tmp/prometheus.yml"
                push_file_with_sudo(self.state.ssh, text, tmp, mode="0644")  # place the tmp file with sudo to be safe
                code, out, err = ssh_exec(
                    self.state.ssh,
                    _sudo_wrap(self.state.ssh, f"(command -v promtool >/dev/null 2>&1 && promtool check config {tmp}) || echo __NO_PROMTOOL__")
                )
                if '__NO_PROMTOOL__' not in (out or "") and code != 0:
                    raise RuntimeError(out or err or 'promtool validation failed')
            except Exception:
                # If promtool missing or fails setup, we still continue (same as before)
                pass

            # Now install to final path (with backup) using sudo
            push_file_with_sudo(self.state.ssh, text, self.state.ssh.prom_path, mode="0644")

            # Restart Prometheus
            cmd = f"systemctl restart {self.state.ssh.prom_service} && systemctl status {self.state.ssh.prom_service} --no-pager --lines=0 || true"
            code, out, err = ssh_exec(self.state.ssh, _sudo_wrap(self.state.ssh, cmd))

            messagebox.showinfo("Prometheus", f"Exit={code}\n{(out or err).strip()}")
            self.state.orig_prom_text = text
        except Exception as e:
            messagebox.showerror("Push error", str(e))


    def on_check_prometheus(self):
        try:
            base = self.var_prom_url.get().strip().rstrip('/')
            if not base:
                messagebox.showwarning("Prometheus", "Enter a Prometheus base URL (e.g., http://prom:9090)")
                return
            api = f"{base}/api/v1/targets"
            ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
            req = urllib.request.Request(api, headers={"Accept": "application/json"})
            with urllib.request.urlopen(req, timeout=15, context=ctx) as resp:
                data = jsonlib.loads(resp.read().decode('utf-8','ignore'))
            if data.get('status') != 'success':
                messagebox.showerror("Prometheus", f"API returned: {data.get('status')}")
                return
            d = data.get('data', {})
            active = d.get('activeTargets', [])
            dropped = d.get('droppedTargets', [])
            up = sum(1 for t in active if t.get('health') == 'up')
            down = sum(1 for t in active if t.get('health') != 'up')
            snmp_targets = [t for t in active if 'snmp' in ((t.get('labels', {}).get('job','') + t.get('scrapeUrl','')).lower())]
            lines = [f"Targets: {len(active)} active, {len(dropped)} dropped", f"UP: {up}  DOWN: {down}"]
            if snmp_targets:
                lines.append(""); lines.append(f"SNMP targets (up to {min(8, len(snmp_targets))}):")
                for t in snmp_targets[:8]:
                    job = t.get('labels', {}).get('job',''); inst = t.get('labels', {}).get('instance','')
                    health = t.get('health',''); last_err = t.get('lastError','')
                    lines.append(f"- job={job} instance={inst} health={health} err={last_err}")
            else:
                lines.append(""); lines.append("No SNMP-related targets detected.")
            messagebox.showinfo("Prometheus targets", "\n".join(lines))
        except urllib.error.URLError as e:
            messagebox.showerror("Prometheus", str(e))
        except Exception as e:
            messagebox.showerror("Prometheus", str(e))
