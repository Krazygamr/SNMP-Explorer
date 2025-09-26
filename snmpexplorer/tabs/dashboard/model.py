# tabs/dashboard/model.py
import os, yaml

class SnmpModel:
    """Loads and parses snmp.yml -> dict[module] -> [metric, ...]."""
    @staticmethod
    def load_snmp_modules(path: str) -> dict:
        if not path or not os.path.isfile(path):
            return {}
        with open(path, "r", encoding="utf-8") as f:
            cfg = yaml.safe_load(f) or {}
        modules = (cfg.get("modules") or {})
        out = {}
        for mod_name, mod_cfg in modules.items():
            names = set()
            for m in (mod_cfg or {}).get("metrics", []) or []:
                if isinstance(m, dict):
                    if "name" in m and m["name"]:
                        names.add(str(m["name"]))
                    elif "oid" in m and m["oid"]:
                        names.add(SnmpModel.oid_to_metric_guess(m["oid"]))
            out[mod_name] = sorted(names)
        return out

    @staticmethod
    def oid_to_metric_guess(oid) -> str:
        s = str(oid).strip().lstrip(".")
        parts = [p for p in s.split(".") if p.isdigit()]
        return "oid_" + "_".join(parts) if parts else "oid_unknown"
