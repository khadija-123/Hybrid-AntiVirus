
# Hybrid Antivirus  (Runs on Windows, Python 3.13) — No version traps

**What it does**
- Scans single files or folders
- Supports: EXE/DLL (PE), PDFs, Office docs, scripts, ZIPs (recursively scans contents)
- **YARA signatures** (includes EICAR test + realistic rules for PowerShell / macros)
- **Heuristics** + **Tiny ML-like scorer** (JSON coefficients, no sklearn/lightgbm required)
- **GUI with Tkinter** (choose file/folder and scan)

**Why it will run on your machine**
- No LightGBM
- No scikit-learn pickles
- ML is a small logistic scorer implemented in pure Python with JSON weights


## 2) Run CLI

python -m src.app <path-to-file-or-folder>


## 3) Run GUI

python -m src.gui


## 4) Test YARA quickly
- File: `samples/eicar.txt` contains the standard EICAR string (harmless test)

python -m src.app samples\eicar.txt



## 6) Model
- The model is trained on 20% dataset of Ember-2018-V2-features in Kaggle using LightGBM model with accuracy of 92.09.
