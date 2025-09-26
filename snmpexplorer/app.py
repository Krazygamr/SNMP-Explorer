# app.py
import tkinter as tk
from tkinter import ttk
from common.context import AppState
from tabs.connection_tab import ConnectionTab
from tabs.snmp_tab import SnmpTab
from tabs.prom_tab import PromTab
from tabs.catalog_tab import CatalogTab
from tabs.dashboard_tab import DashboardTab  # NEW
from tabs.installation_tab import InstallationTab  # NEW

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("SNMP/Prometheus Editor v2 (modular)")
        self.geometry("1280x900")
        self.minsize(1100, 800)

        self.state = AppState()
        nb = ttk.Notebook(self)
        nb.pack(fill=tk.BOTH, expand=True)

        # --- Instantiate tabs ---
        self.tab_conn = ConnectionTab(nb, self.state)
        self.tab_snmp = SnmpTab(nb, self.state)
        self.tab_prom = PromTab(nb, self.state)
        self.tab_cat  = CatalogTab(nb, self.state)

        self.state.ui = {
            "connection_tab": self.tab_conn,
            "snmp_tab": self.tab_snmp,
            "prom_tab": self.tab_prom,
            "catalog_tab": self.tab_cat,
        }

        # Single source of truth for the Dashboard tab:
        def _snmp_yml_path_getter():
            # Set by ConnectionTab.on_pull_both after a successful pull
            return getattr(self.state, "snmp_yml_local_path", None)

        # Instantiate Dashboard tab BEFORE adding it
        self.tab_dash = DashboardTab(nb, _snmp_yml_path_getter)

        # NEW: Installation tab (verify/install/overwrite flows)
        self.tab_install = InstallationTab(nb, self.state)

        # --- Add tabs to notebook (in order) ---
        nb.add(self.tab_conn, text="1) Connection & Pull")
        nb.add(self.tab_snmp, text="2) SNMP Exporter (snmp.yml)")
        nb.add(self.tab_prom, text="3) Prometheus (prometheus.yml)")
        nb.add(self.tab_cat,  text="4) Catalog")
        nb.add(self.tab_dash, text="5) Dashboard")
        nb.add(self.tab_install, text="6) Installation")  # NEW

        # Provide a simple map so child tabs (e.g., Installation) can navigate
        # back to a specific tab (uses ttk.Notebook.select(child))
        nb.tabs = {
            "Connection": self.tab_conn,
            "SNMP": self.tab_snmp,
            "Prometheus": self.tab_prom,
            "Catalog": self.tab_cat,
            "Dashboard": self.tab_dash,
            "Installation": self.tab_install,
        }
        self.notebook = nb  # keep a handle if other code expects it

        # Cross-tab refresh: when ConnectionTab finishes pulling
        self.tab_conn.bind("<<ConfigsPulled>>", self._on_configs_pulled)
        self.tab_conn.bind("<<SshProfileChanged>>", self._on_ssh_profile_changed)
    def _on_configs_pulled(self, _evt=None):
        # Let other tabs refresh after a pull
        for tab in (self.tab_snmp, self.tab_prom, self.tab_cat):
            if hasattr(tab, "refresh"):
                tab.refresh()
        # Refresh Dashboard tab so it re-parses updated snmp.yml
        if hasattr(self.tab_dash, "refresh"):
            self.tab_dash.refresh()
        # (Optional) If Installation tab has a refresh hook later, call it guarded
        if hasattr(self.tab_install, "refresh"):
            self.tab_install.refresh()
    def _on_ssh_profile_changed(self, _evt=None):
        # Update any tabs that display connection context
        if hasattr(self.tab_install, "refresh"):
            self.tab_install.refresh()


if __name__ == "__main__":
    App().mainloop()
