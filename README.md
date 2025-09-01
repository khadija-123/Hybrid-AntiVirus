
# Hybrid Antivirus  (Runs on Windows, Python 3.13) 

**What it does**
- Scans single files or folders
- Supports: EXE/DLL (PE), PDFs, Office docs, scripts, ZIPs (recursively scans contents)
- **YARA signatures** (includes EICAR test + realistic rules for PowerShell / macros)
- **Heuristics** + **AI model** (JSON coefficients,  sklearn/lightgbm required)
- **GUI with Tkinter** (choose file/folder and scan)

## 1) Run CLI

python -m src.app <path-to-file-or-folder>


## 2) Run GUI

python -m src.gui


## 3) Test YARA quickly
- File: `samples/eicar.txt` contains the standard EICAR string (harmless test)

python -m src.app samples\eicar.txt

## 6) Model
- The model is trained on 20% dataset of Ember-2018-V2-features in Kaggle using LightGBM model with accuracy of 92.09.

## 6) Model
- The model is trained on 20% dataset of Ember-2018-V2-features in Kaggle using LightGBM model with accuracy of 92.09.
