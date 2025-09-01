
import re

OBF_PATTERNS = [
    r"fromcharcode\s*\(", r"wscript\.shell", r"powershell\s*-enc",
    r"new-object\s+net\.webclient", r"invoke-expression", r"atob\(", r"eval\s*\("
]
def analyze_script(path: str):
    try:
        txt = open(path, "r", errors="ignore", encoding="utf-8").read()
        hits = [p for p in OBF_PATTERNS if re.search(p, txt, flags=re.I)]
        if hits:
            return {"label": "suspicious", "notes": [f"Obfuscation/APIs: {', '.join(hits)}"], "script_hits": len(hits)}
        return {"label": "benign", "notes": [], "script_hits": 0}
    except Exception as e:
        return {"label": "unknown", "notes": [f"Script read error: {e}"], "script_hits": 0}
