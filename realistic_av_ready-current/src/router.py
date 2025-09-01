
import os
import magic

PE_EXTS = {".exe", ".dll", ".sys"}
OFFICE_EXTS = {".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".rtf", ".xlsm", ".pptm", ".docm"}
SCRIPT_EXTS = {".js", ".vbs", ".ps1", ".bat", ".cmd", ".py"}
ARCHIVE_EXTS = {".zip"}

def detect_type(path: str) -> str:
    ext = os.path.splitext(path)[1].lower()
    try:
        mime = magic.from_file(path, mime=True) or ""
    except Exception:
        mime = ""
    if ext in PE_EXTS: return "pe"
    if ext in OFFICE_EXTS: return "office"
    if ext in SCRIPT_EXTS: return "script"
    if ext in ARCHIVE_EXTS: return "archive"
    if "pdf" in mime or ext == ".pdf": return "pdf"
    return "generic"
