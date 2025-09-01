import math, os, re

def file_size_bytes(path: str) -> int:
    try:
        return os.path.getsize(path)
    except Exception:
        return 0

def sample_entropy_from_file(path: str, max_bytes: int = 4000000) -> float:
    try:
        with open(path, "rb") as f:
            data = f.read(max_bytes)
        if not data:
            return 0.0
        counts = [0]*256
        for b in data:
            counts[b] += 1
        n = len(data)
        ent = 0.0
        for c in counts:
            if c:
                p = c/n
                ent -= p * math.log2(p)
        return float(ent)
    except Exception:
        return 0.0

# Simple script obfuscation hits count
OBF_PATTERNS = [
    r"fromcharcode\s*\(", r"wscript\.shell", r"powershell\s*-enc",
    r"new-object\s+net\.webclient", r"invoke-expression", r"atob\(", r"eval\s*\("
]
def script_obfuscation_hits(path: str) -> int:
    try:
        txt = open(path, "r", errors="ignore", encoding="utf-8").read()
        return sum(1 for p in OBF_PATTERNS if re.search(p, txt, flags=re.I))
    except Exception:
        return 0
