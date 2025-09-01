
import pefile
import math

def _entropy(data: bytes) -> float:
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
            ent -= p*math.log2(p)
    return ent

def analyze_pe(path: str):
    verdicts = []
    score = 0
    try:
        pe = pefile.PE(path, fast_load=True)
        pe.parse_data_directories(directories=[])

        high_entropy_sections = 0
        for section in pe.sections:
            data = section.get_data()[:200000]
            ent = _entropy(data)
            if ent > 7.2:
                high_entropy_sections += 1
        if high_entropy_sections >= 2:
            score += 2
            verdicts.append(f"High-entropy sections: {high_entropy_sections}")

        sus_imports = {"VirtualAlloc", "WriteProcessMemory", "CreateRemoteThread", "NtUnmapViewOfSection"}
        found = set()
        try:
            for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []):
                for imp in entry.imports:
                    if imp.name:
                        name = imp.name.decode(errors="ignore")
                        if name in sus_imports:
                            found.add(name)
        except Exception:
            pass
        if found:
            score += 2
            verdicts.append(f"Suspicious imports: {', '.join(sorted(found))}")

        label = "malicious" if score >= 2 else "benign"
        prob = min(0.95, 0.5 + 0.2*score)
        return {"label": label, "score": score, "prob": prob, "notes": verdicts, "high_entropy_sections": high_entropy_sections, "sus_imports_count": len(found)}
    except Exception as e:
        return {"label": "unknown", "score": 0, "prob": 0.5, "notes": [f"PE parse error: {e}"], "high_entropy_sections": 0, "sus_imports_count": 0}
