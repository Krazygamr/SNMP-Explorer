# tabs/dashboard/builder.py
from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

# ================================================================
# Shared helpers
# ================================================================

def _ds_ref_for_variable() -> Dict[str, Any]:
    """
    Every panel should reference the DS variable, not a hard-coded UID/name.
    Grafana resolves ${DS_PROMETHEUS} to a concrete uid at runtime.
    """
    return {"type": "prometheus", "uid": "${DS_PROMETHEUS}"}


def _templating_block(
    datasource_uid: Optional[str],
    instance_query_job: str = "snmp",
    window_default: str = "2m",
) -> Dict[str, Any]:
    """
    Build templating section with:
      - DS_PROMETHEUS  (datasource picker for prometheus)
      - instance       (query label_values(up{job="snmp"}, instance))
      - window         (2m/5m/10m)
    """
    ds_current = {"text": "prometheus", "value": (datasource_uid or "")}
    return {
        "list": [
            {
                "current": ds_current,
                "name": "DS_PROMETHEUS",
                "options": [],
                "query": "prometheus",
                "refresh": 1,
                "type": "datasource",
            },
            {
                "current": {},
                "datasource": _ds_ref_for_variable(),
                "includeAll": False,
                "label": "Instance",
                "name": "instance",
                "options": [],
                "query": f'label_values(up{{job="{instance_query_job}"}}, instance)',
                "refresh": 1,
                "type": "query",
            },
            {
                "current": {"text": window_default, "value": window_default},
                "label": "Rate Window",
                "name": "window",
                "options": [
                    {"selected": window_default == "2m", "text": "2m", "value": "2m"},
                    {"selected": window_default == "5m", "text": "5m", "value": "5m"},
                    {"selected": window_default == "10m", "text": "10m", "value": "10m"},
                ],
                "query": "2m,5m,10m",
                "type": "custom",
            },
        ]
    }

# ================================================================
# Opinionated IF-MIB block (your original layout)
# ================================================================

def _panel_stat_up(y: int = 0) -> Dict[str, Any]:
    return {
        "type": "stat",
        "title": "Target Health",
        "gridPos": {"h": 5, "w": 6, "x": 0, "y": y},
        "datasource": _ds_ref_for_variable(),
        "pluginVersion": "12.1.1",
        "options": {
            "colorMode": "value",
            "graphMode": "none",
            "justifyMode": "center",
            "reduceOptions": {"calcs": ["lastNotNull"], "fields": "", "values": False},
            "textMode": "auto",
            "thresholds": {"mode": "absolute", "steps": [{"color": "red"}, {"color": "green", "value": 1}]},
            "wideLayout": True,
        },
        "fieldConfig": {
            "defaults": {
                "mappings": [],
                "thresholds": {"mode": "absolute", "steps": [{"color": "green", "value": 0}, {"color": "red", "value": 80}]},
            },
            "overrides": [],
        },
        "targets": [{"refId": "A", "expr": 'up{job="snmp", instance="$instance"}'}],
    }


def _panel_total_in(y: int = 0) -> Dict[str, Any]:
    return {
        "type": "timeseries",
        "title": "Total Inbound (Mbps, $window)",
        "gridPos": {"h": 5, "w": 9, "x": 6, "y": y},
        "datasource": _ds_ref_for_variable(),
        "pluginVersion": "12.1.1",
        "options": {
            "legend": {"displayMode": "list", "placement": "bottom", "showLegend": True},
            "tooltip": {"mode": "single", "hideZeros": False},
        },
        "fieldConfig": {"defaults": {"unit": "Mbps"}, "overrides": []},
        "targets": [{
            "refId": "A",
            "legendFormat": "Inbound",
            "expr": 'sum by (instance) (increase(ifInOctets{job="snmp", instance="$instance"}[$window])) * 8 / 1e6',
        }],
    }


def _panel_total_out(y: int = 0) -> Dict[str, Any]:
    return {
        "type": "timeseries",
        "title": "Total Outbound (Mbps, $window)",
        "gridPos": {"h": 5, "w": 9, "x": 15, "y": y},
        "datasource": _ds_ref_for_variable(),
        "pluginVersion": "12.1.1",
        "options": {
            "legend": {"displayMode": "list", "placement": "bottom", "showLegend": True},
            "tooltip": {"mode": "single", "hideZeros": False},
        },
        "fieldConfig": {"defaults": {"unit": "Mbps"}, "overrides": []},
        "targets": [{
            "refId": "A",
            "legendFormat": "Outbound",
            "expr": 'sum by (instance) (increase(ifOutOctets{job="snmp", instance="$instance"}[$window])) * 8 / 1e6',
        }],
    }


def _panel_top5_in(y: int = 5) -> Dict[str, Any]:
    return {
        "type": "timeseries",
        "title": "Top 5 Interfaces Inbound (Mbps, $window)",
        "gridPos": {"h": 8, "w": 12, "x": 0, "y": y},
        "datasource": _ds_ref_for_variable(),
        "pluginVersion": "12.1.1",
        "options": {
            "legend": {"displayMode": "list", "placement": "right", "showLegend": True},
            "tooltip": {"mode": "single", "hideZeros": False},
        },
        "targets": [{
            "refId": "A",
            "range": True,
            "legendFormat": "ifIndex {{ifIndex}}",
            "expr": 'topk(5, increase(ifInOctets{job="snmp", instance="$instance"}[$window]) / 8 / 1e6)',
        }],
        "fieldConfig": {"defaults": {"unit": "Mbps"}, "overrides": []},
    }


def _panel_top5_out(y: int = 5) -> Dict[str, Any]:
    return {
        "type": "timeseries",
        "title": "Top 5 Interfaces Outbound (Mbps, $window)",
        "gridPos": {"h": 8, "w": 12, "x": 12, "y": y},
        "datasource": _ds_ref_for_variable(),
        "pluginVersion": "12.1.1",
        "options": {
            "legend": {"displayMode": "list", "placement": "right", "showLegend": True},
            "tooltip": {"mode": "single", "hideZeros": False},
        },
        "targets": [{
            "refId": "A",
            "legendFormat": "ifIndex {{ifIndex}}",
            "expr": 'topk(5, increase(ifOutOctets{job="snmp", instance="$instance"}[$window]) * 8 / 1e6)',
        }],
        "fieldConfig": {"defaults": {"unit": "Mbps"}, "overrides": []},
    }


def _panel_interface_table(y: int = 13) -> Dict[str, Any]:
    return {
        "type": "table",
        "title": "Interface Table (ifIndex, ifDescr, In/Out Mbps, $window)",
        "gridPos": {"h": 9, "w": 24, "x": 0, "y": y},
        "datasource": _ds_ref_for_variable(),
        "pluginVersion": "12.1.1",
        "fieldConfig": {
            "defaults": {
                "mappings": [],
                "thresholds": {"mode": "absolute", "steps": [{"color": "green", "value": 0}, {"color": "red", "value": 80}]},
                "custom": {"align": "auto", "cellOptions": {"type": "auto"}, "inspect": False},
            },
            "overrides": [
                {"matcher": {"id": "byName", "options": "in_mbps"}, "properties": [{"id": "unit", "value": "Mbps"}]},
                {"matcher": {"id": "byName", "options": "out_mbps"}, "properties": [{"id": "unit", "value": "Mbps"}]},
            ],
        },
        "options": {"cellHeight": "sm", "footer": {"show": False, "reducer": ["sum"], "fields": "", "countRows": False}, "showHeader": True},
        "targets": [
            {"refId": "A", "expr": 'ifDescr{job="snmp", instance="$instance"}'},
            {"refId": "B", "legendFormat": "in_mbps", "expr": 'increase(ifInOctets{job="snmp", instance="$instance"}[$window]) * 8 / 1e6'},
            {"refId": "C", "legendFormat": "out_mbps", "expr": 'increase(ifOutOctets{job="snmp", instance="$instance"}[$window]) * 8 / 1e6'},
        ],
        "transformations": [
            {"id": "joinByField", "options": {"byField": "ifIndex"}},
            {"id": "organize", "options": {
                "excludeByName": {"Time": True, "job": True},
                "order": ["ifIndex", "ifDescr", "in_mbps", "out_mbps", "instance"],
                "renameByName": {"B": "in_mbps", "C": "out_mbps", "Value": "ifDescr_present"},
            }},
        ],
    }


def _ifmib_panels() -> List[Dict[str, Any]]:
    return [
        _panel_stat_up(0),
        _panel_total_in(0),
        _panel_total_out(0),
        _panel_top5_in(5),
        _panel_top5_out(5),
        _panel_interface_table(13),
    ]

# ================================================================
# Dynamic panel helpers (case-insensitive detection)
# ================================================================

# IF-MIB keys (lowercased set for detection)
_IFMIB_KEYS = {"ifInOctets", "ifOutOctets", "ifHCInOctets", "ifHCOutOctets"}
_IFMIB_KEYS_LC = {s.lower() for s in _IFMIB_KEYS}


def _lower_name_map(pairs: List[Tuple[str, str]]) -> Dict[str, str]:
    """Map lowercased metric name -> original metric name (last occurrence wins)."""
    name_map: Dict[str, str] = {}
    for _mod, m in pairs:
        name_map[m.lower()] = m
    return name_map


def _first_present(candidates_lc: List[str], name_map: Dict[str, str]) -> Optional[str]:
    """Return the first original-name that exists, given lowercase candidates."""
    for nlc in candidates_lc:
        if nlc in name_map:
            return name_map[nlc]
    return None


def _fortigate_panels(selected_lc: set[str], name_map: Dict[str, str], y: int = 0) -> List[Dict[str, Any]]:
    """
    Add a compact FortiGate health row if we recognize FG metrics (case-insensitive):
      - CPU %, Mem %, Sessions (stat tiles)
      - A session rate tile if one of fgsyssesrate{1,30,60} is present
    """
    panels: List[Dict[str, Any]] = []
    x = 0

    def _stat(title: str, metric_name: str, unit: str = "none", width: int = 6) -> Dict[str, Any]:
        nonlocal x
        expr = f'{metric_name}{{job="snmp", instance="$instance"}}'
        p = {
            "type": "stat",
            "title": title,
            "gridPos": {"h": 5, "w": width, "x": x, "y": y},
            "datasource": _ds_ref_for_variable(),
            "options": {
                "colorMode": "value", "graphMode": "none", "justifyMode": "center",
                "reduceOptions": {"calcs": ["lastNotNull"], "fields": "", "values": False},
                "wideLayout": True,
            },
            "fieldConfig": {"defaults": {"unit": unit, "mappings": [], "thresholds": {"mode": "absolute", "steps": [{"color": "green", "value": 0}, {"color": "red", "value": 80}]}}, "overrides": []},
            "targets": [{"refId": "A", "expr": f"avg({expr})"}],
        }
        x += width
        return p

    # CPU %
    cpu = _first_present(["fgsyscpuusage", "fgsyscpu"], name_map)
    if cpu:
        panels.append(_stat("CPU %", cpu, "percent", 6))

    # Memory %
    mem = _first_present(["fgsysmemusage", "fgmemusage"], name_map)
    if mem:
        panels.append(_stat("Mem %", mem, "percent", 6))

    # Sessions
    ses = _first_present(["fgsyssescount", "fgsyssessions", "fgsyssescnt"], name_map)
    if ses:
        panels.append(_stat("Sessions", ses, "none", 6))

    # Session rate (pick first available)
    rate = _first_present(["fgsyssesrate1", "fgsyssesrate30", "fgsyssesrate60"], name_map)
    if rate:
        panels.append(_stat("Sess rate", rate, "none", 6))

    return panels


def _generic_panels_excluding(
    pairs: List[Tuple[str, str]],
    excluded_lc: set[str],
    y_start: int,
) -> List[Dict[str, Any]]:
    """
    Build generic per-metric time series panels for all selected metrics
    that aren't excluded (case-insensitive).
    """
    panels: List[Dict[str, Any]] = []
    cols, w, h = 3, 24 // 3, 8
    x, y = 0, y_start
    for idx, (mod, metric) in enumerate(pairs):
        if metric.lower() in excluded_lc:
            continue
        panels.append({
            "type": "timeseries",
            "title": f"{metric} ({mod})",
            "datasource": _ds_ref_for_variable(),
            "gridPos": {"h": h, "w": w, "x": x, "y": y},
            "fieldConfig": {"defaults": {"unit": "none", "mappings": [], "thresholds": {"mode": "absolute", "steps": [{"color": "green", "value": 0}, {"color": "red", "value": 80}]}}, "overrides": []},
            "options": {"legend": {"displayMode": "table", "placement": "bottom"}, "tooltip": {"mode": "single"}},
            "targets": [{"refId": "A", "expr": f'{metric}{{job="snmp", instance="$instance"}}', "legendFormat": "{{instance}}"}],
        })
        x += w
        if (idx + 1) % cols == 0:
            x = 0
            y += h
    return panels

# ================================================================
# Public API
# ================================================================

def build_dashboard_model(
    title: str,
    datasource_name: str,
    datasource_uid: Optional[str],
    refresh: str,
    time_from: str,
    time_to: str,
    job_default: str,
    pairs: List[Tuple[str, str]],
    export_mode: str = "ui",
) -> Dict[str, Any]:
    """
    Compositional layout:
      • IF-MIB section if any octet metrics are present (kept exactly as before)
      • FortiGate health row if FG metrics are present (case-insensitive detection)
      • Generic per-metric panels for everything else you selected
    """
    name_map = _lower_name_map(pairs)
    selected_lc = {m.lower() for _, m in pairs}

    # IF-MIB?
    use_ifmib = bool(_IFMIB_KEYS_LC & selected_lc)

    panels: List[Dict[str, Any]] = []
    y_cursor = 0
    if use_ifmib:
        panels.extend(_ifmib_panels())
        y_cursor = 22  # IF-MIB block occupies rows 0..21

    # FortiGate quick stats (if present)
    fg_keys = {"fgsyscpuusage", "fgsysmemusage", "fgsyssescount", "fgsyssesrate1", "fgsyssesrate30", "fgsyssesrate60"}
    if fg_keys & selected_lc:
        panels.extend(_fortigate_panels(selected_lc, name_map, y=y_cursor))
        y_cursor += 5

    # Generic grid for the rest
    excluded_lc: set[str] = set()
    if use_ifmib:
        excluded_lc |= _IFMIB_KEYS_LC | {"ifname", "ifdescr", "ifalias"}
    excluded_lc |= (fg_keys & selected_lc)

    panels.extend(_generic_panels_excluding(pairs, excluded_lc=excluded_lc, y_start=y_cursor))

    dashboard: Dict[str, Any] = {
        "title": title or "SNMP Dashboard",
        "tags": ["SNMP", "Prometheus"],
        "timezone": "",
        "schemaVersion": 41,
        "version": 1,
        "editable": True,
        "time": {"from": time_from or "now-24h", "to": time_to or "now"},
        "refresh": refresh or "10s",
        "graphTooltip": 0,
        "links": [],
        "panels": panels,
        "templating": _templating_block(datasource_uid=datasource_uid or "", instance_query_job=job_default or "snmp"),
        "annotations": {"list": [
            {"builtIn": 1, "datasource": {"type": "grafana", "uid": "-- Grafana --"}, "enable": True, "hide": True,
             "iconColor": "rgba(0, 211, 255, 1)", "name": "Annotations & Alerts", "type": "dashboard"}
        ]},
        "timepicker": {},
        "fiscalYearStartMonth": 0,
        "preload": False,
    }

    if export_mode == "api":
        return {"dashboard": dashboard, "overwrite": False, "folderId": 0}
    return dashboard
