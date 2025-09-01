
def analyze_pdf(path: str):
    red_flags = [b"/JS", b"/JavaScript", b"/AA", b"/OpenAction", b"/Launch"]
    hits = []
    try:
        with open(path, "rb") as f:
            blob = f.read(4000000)
        for flag in red_flags:
            if flag in blob:
                hits.append(flag.decode())
        if hits:
            return {"label": "suspicious", "notes": [f"PDF flags: {', '.join(hits)}"], "pdf_flag_count": len(hits)}
        return {"label": "benign", "notes": [], "pdf_flag_count": 0}
    except Exception as e:
        return {"label": "unknown", "notes": [f"PDF read error: {e}"], "pdf_flag_count": 0}
