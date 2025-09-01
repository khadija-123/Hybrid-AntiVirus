
import zipfile
import os
from tempfile import TemporaryDirectory
from ..router import detect_type
from .yara_scan import scan_with_yara
from .pe_static import analyze_pe
from .pdf_static import analyze_pdf
from .office_static import analyze_office
from .script_static import analyze_script

def analyze_archive(path: str, yara_rules, score_cb):
    results = []
    try:
        with TemporaryDirectory() as td:
            with zipfile.ZipFile(path) as z:
                z.extractall(td)
            for root, _, files in os.walk(td):
                for f in files:
                    fp = os.path.join(root, f)
                    ftype = detect_type(fp)
                    y = scan_with_yara(yara_rules, fp)
                    if ftype == "pe":
                        r = analyze_pe(fp)
                    elif ftype == "pdf":
                        r = analyze_pdf(fp)
                    elif ftype == "office":
                        r = analyze_office(fp)
                    elif ftype == "script":
                        r = analyze_script(fp)
                    else:
                        r = {"label": "unknown", "notes": []}
                    # score inner file with ML-like scorer
                    scored = score_cb(fp, ftype, y, r)
                    results.append({"file": fp, "type": ftype, "yara": y, "result": r, "score": scored})
        label = "benign"
        for item in results:
            if item["score"]["prob"] >= 0.75 or item["yara"] or item["result"].get("label") in {"malicious","suspicious"}:
                label = "suspicious"
                break
        return {"label": label, "notes": [f"Scanned {len(results)} inner files"], "details": results}
    except Exception as e:
        return {"label": "unknown", "notes": [f"Archive error: {e}"], "details": []}
