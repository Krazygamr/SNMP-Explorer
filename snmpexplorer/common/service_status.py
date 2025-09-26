# common/service_status.py
import re

def parse_systemctl_status(text: str) -> dict:
    d = {"active": False, "since": "", "pid": "", "listen": ""}
    m = re.search(r"Active:\s+active\s+\(running\)\s+since\s+(.+);", text)
    if m: d["active"] = True; d["since"] = m.group(1)
    m = re.search(r"Main PID:\s+(\d+)", text);  d["pid"] = m.group(1) if m else ""
    m = re.search(r"--web\.listen-address=([^\s]+)", text); d["listen"] = m.group(1) if m else ""
    return d

def summarize_snmp_status(status_text: str, metrics_ok: bool, metrics_lines: int) -> str:
    p = parse_systemctl_status(status_text)
    lines = []
    lines.append("Service: " + ("active (running)" if p["active"] else "NOT running"))
    if p["since"]: lines.append(f"Since: {p['since']}")
    if p["pid"]:   lines.append(f"PID:   {p['pid']}")
    if p["listen"]:lines.append(f"Listen: {p['listen']}")
    lines.append("")
    lines.append("Metrics probe: " + ("OK" if metrics_ok else "FAILED"))
    if metrics_ok: lines.append(f"Non-comment metric lines: {metrics_lines}")
    return "\n".join(lines)
