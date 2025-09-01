
import yara
from pathlib import Path

def load_rules(rules_dir: str):
    rule_files = {}
    for p in Path(rules_dir).glob("*.yar*"):
        rule_files[p.stem] = str(p)
    if not rule_files:
        return None
    return yara.compile(filepaths=rule_files)

def scan_with_yara(rules, path: str):
    if rules is None:
        return []
    try:
        matches = rules.match(path)
        return [m.rule for m in matches]
    except Exception:
        return []
