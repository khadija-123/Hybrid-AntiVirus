
from oletools.olevba import VBA_Parser

def analyze_office(path: str):
    try:
        vba = VBA_Parser(path)
        if vba.detect_vba_macros():
            return {"label": "suspicious", "notes": ["VBA macros present"], "has_macros": 1}
        return {"label": "benign", "notes": [], "has_macros": 0}
    except Exception as e:
        return {"label": "unknown", "notes": [f"OLE parse error: {e}"], "has_macros": 0}
