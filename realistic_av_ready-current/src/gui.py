import os, json, threading, tkinter as tk
from tkinter import filedialog, messagebox, ttk
from .router import detect_type
from .detectors.yara_scan import load_rules, scan_with_yara
from .detectors.pe_static import analyze_pe
from .detectors.pdf_static import analyze_pdf
from .detectors.office_static import analyze_office
from .detectors.script_static import analyze_script
from .ml_scorer import load_weights, score_file

APP_TITLE = "AV Ready Scanner"

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(APP_TITLE)
        self.geometry("820x500")
        self.rules = load_rules(os.path.join(os.path.dirname(__file__), "rules"))
        self.weights = load_weights(os.path.join(os.path.dirname(__file__), "..", "models"))
        self._build_ui()

    def _build_ui(self):
        frm = ttk.Frame(self, padding=10)
        frm.pack(fill="both", expand=True)

        self.path_var = tk.StringVar()
        row1 = ttk.Frame(frm); row1.pack(fill="x")
        ttk.Entry(row1, textvariable=self.path_var).pack(side="left", fill="x", expand=True, padx=(0,8))
        ttk.Button(row1, text="Browse File", command=self._choose_file).pack(side="left", padx=4)
        ttk.Button(row1, text="Browse Folder", command=self._choose_folder).pack(side="left", padx=4)
        ttk.Button(row1, text="Scan", command=self._scan).pack(side="left", padx=4)

        self.text = tk.Text(frm, wrap="none")
        self.text.pack(fill="both", expand=True, pady=(10,0))
        yscroll = ttk.Scrollbar(self.text, orient="vertical", command=self.text.yview)
        self.text.configure(yscrollcommand=yscroll.set)
        yscroll.pack(side="right", fill="y")

    def _choose_file(self):
        path = filedialog.askopenfilename()
        if path:
            self.path_var.set(path)

    def _choose_folder(self):
        path = filedialog.askdirectory()
        if path:
            self.path_var.set(path)

    def _scan(self):
        target = self.path_var.get().strip()
        if not target:
            messagebox.showerror(APP_TITLE, "Please select a file or folder")
            return
        self.text.delete("1.0", "end")
        self.text.insert("end", f"Scanning: {target}\n")

        def worker():
            try:
                out = self._scan_impl(target)
                self.text.insert("end", json.dumps(out, indent=2))
            except Exception as e:
                self.text.insert("end", f"\nError: {e}")

        threading.Thread(target=worker, daemon=True).start()

    def _scan_impl(self, target):
        items = []
        if os.path.isdir(target):
            for root, _, files in os.walk(target):
                for f in files:
                    items.append(os.path.join(root, f))
        else:
            items.append(target)

        results = []
        for p in items:
            ftype = detect_type(p)
            y = scan_with_yara(self.rules, p)
            if ftype == "pe":
                r = analyze_pe(p)
            elif ftype == "pdf":
                r = analyze_pdf(p)
            elif ftype == "office":
                r = analyze_office(p)
            elif ftype == "script":
                r = analyze_script(p)
            else:
                r = {"label": "unknown", "notes": []}
            ml = score_file(p, ftype, y, r, self.weights)
            final = "malicious" if ("EICAR_Test_File" in y or ml["label"]=="malicious") else ("suspicious" if (y or ml["label"]=="suspicious") else "benign")
            results.append({"path": p, "type": ftype, "yara_hits": y, "result": r, "ml": ml, "final_label": final})
        return results

if __name__ == "__main__":
    App().mainloop()
