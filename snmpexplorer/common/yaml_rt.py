from ruamel.yaml import YAML
from io import StringIO

def yaml_loader() -> YAML:
    y = YAML()
    y.preserve_quotes = True
    y.indent(mapping=2, sequence=4, offset=2)
    return y

def yaml_load(text: str):
    y = yaml_loader()
    return y.load(text) or {}

def yaml_dump(data) -> str:
    y = yaml_loader()
    buf = StringIO()
    y.dump(data, buf)
    return buf.getvalue()
