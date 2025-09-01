import argparse, json, os
from .router import detect_type
from .detectors.yara_scan import load_rules, scan_with_yara
from .detectors.pe_static import analyze_pe
from .detectors.pdf_static import analyze_pdf
from .detectors.office_static import analyze_office
from .detectors.script_static import analyze_script
from .detectors.archive_scan import analyze_archive
from .ml_scorer import load_weights, score_file

def _route_and_analyze(path: str):
    ftype = detect_type(path)
    if ftype == "pe":
        return ftype, analyze_pe(path)
    if ftype == "pdf":
        return ftype, analyze_pdf(path)
    if ftype == "office":
        return ftype, analyze_office(path)
    if ftype == "script":
        return ftype, analyze_script(path)
    return ftype, {"label": "unknown", "notes": []}

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("target", help="file or folder to scan")
    ap.add_argument("--rules", default=os.path.join(os.path.dirname(__file__), "rules"), help="YARA rules dir")
    ap.add_argument("--models", default=os.path.join(os.path.dirname(__file__), "..", "models"), help="Models dir")
    args = ap.parse_args()

    rules = load_rules(args.rules)
    weights = load_weights(args.models)

    def score_cb(fp, ftype, y, r):
        return score_file(fp, ftype, y, r, weights)

    paths = []
    if os.path.isdir(args.target):
        for root, _, files in os.walk(args.target):
            for f in files:
                paths.append(os.path.join(root, f))
    else:
        paths.append(args.target)

    reports = []
    for p in paths:
        ftype, analysis = _route_and_analyze(p)
        yhits = scan_with_yara(rules, p)
        if ftype == "archive":
            rep = analyze_archive(p, rules, score_cb)
            final = rep["label"]
            prob = 0.75 if final == "suspicious" else 0.2
            reports.append({"path": p, "type": ftype, "yara_hits": yhits, "result": rep, "ml": {"label": final, "prob": prob}})
        else:
            ml = score_cb(p, ftype, yhits, analysis)
            final = "malicious" if ("EICAR_Test_File" in yhits or ml["label"]=="malicious") else ("suspicious" if (yhits or ml["label"]=="suspicious") else "benign")
            reports.append({"path": p, "type": ftype, "yara_hits": yhits, "result": analysis, "ml": ml, "final_label": final})

    print(json.dumps(reports, indent=2, default=str))

if __name__ == "__main__":
    main()
