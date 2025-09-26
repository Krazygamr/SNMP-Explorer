# common/context.py
from dataclasses import dataclass, field
from typing import Optional, Any, List, Dict

@dataclass
class SSHConfig:
    host: str = "192.168.1.10"
    port: int = 22
    username: str = "pi"
    password: str = ""
    key_path: str = ""
    snmp_path: str = "/etc/snmp_exporter/snmp.yml"
    prom_path: str = "/etc/prometheus/prometheus.yml"
    snmp_service: str = "snmp_exporter"
    prom_service: str = "prometheus"

@dataclass
class AppState:
    # Use default_factory for mutables!
    ssh: SSHConfig = field(default_factory=SSHConfig)

    # originals for diff
    orig_snmp_text: str = ""
    orig_prom_text: str = ""

    # ruamel round-trip docs
    snmp_doc: Optional[Any] = None
    prom_doc: Optional[Any] = None

    # catalog
    catalog: Optional[Dict] = None
    catalog_oids: List[Dict] = field(default_factory=list)

    
