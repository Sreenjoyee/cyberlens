"""
attachment.py - endpoint / attachment indicators.   [Member 1]

We never open or run files. We only look at the name and the first bytes
("magic bytes") which reveal the real file type.
"""
from core.indicators.common import Indicator
from core.integrity import sha256_bytes

DANGEROUS = {"exe", "scr", "com", "bat", "cmd", "msi", "dll", "js", "vbs", "ps1", "hta", "jar", "lnk", "iso"}
DOCUMENTS = {"pdf", "doc", "docx", "xls", "xlsx", "txt", "jpg", "png"}
MACRO = {"docm", "xlsm", "pptm", "dotm"}
ARCHIVE = {"zip", "rar", "7z", "gz"}

# magic bytes -> (real type, extensions that honestly use it)
MAGIC = {
    b"MZ": ("a Windows executable", {"exe", "dll", "scr"}),
    b"%PDF": ("a PDF", {"pdf"}),
    b"PK\x03\x04": ("a ZIP container", {"zip", "docx", "xlsx", "pptx", "docm", "xlsm", "pptm", "jar"}),
    b"\xff\xd8\xff": ("a JPEG image", {"jpg", "jpeg"}),
    b"\x89PNG": ("a PNG image", {"png"}),
}

# id -> (name, weight, reason)
CHECKS = {
    "ATT_DANGEROUS_EXT": ("Executable / script attachment", 25, "This file type runs code when opened."),
    "ATT_DOUBLE_EXT": ("Double file extension", 15, "invoice.pdf.exe: Windows hides '.exe', so you see 'invoice.pdf'."),
    "ATT_MACRO_OFFICE": ("Macro-enabled Office file", 15, "Macros run code once you click 'Enable Content'."),
    "ATT_ARCHIVE": ("Compressed archive", 8, "Archives hide their contents from mail scanners."),
    "ATT_MAGIC_MISMATCH": ("Content does not match extension", 25, "The file's bytes show a different type than its name claims."),
}


def analyze(email) -> list:
    hits = {id_: [] for id_ in CHECKS}
    for att in email.attachments:
        exts = att.filename.lower().split(".")[1:]        # 'a.pdf.exe' -> ['pdf', 'exe']
        last = exts[-1] if exts else ""
        if last in DANGEROUS:
            hits["ATT_DANGEROUS_EXT"].append(att.filename)
        if len(exts) >= 2 and exts[-2] in DOCUMENTS and last in DANGEROUS:
            hits["ATT_DOUBLE_EXT"].append(att.filename)
        if last in MACRO:
            hits["ATT_MACRO_OFFICE"].append(att.filename)
        if last in ARCHIVE:
            hits["ATT_ARCHIVE"].append(att.filename)
        for magic, (real_type, honest) in MAGIC.items():
            if att.content and att.content.startswith(magic) and last not in honest:
                hits["ATT_MAGIC_MISMATCH"].append(f"{att.filename} is really {real_type}")

    found = []
    for id_, evidence in hits.items():
        if evidence:
            name, weight, reason = CHECKS[id_]
            found.append(Indicator(id_, name, "attachment", weight, reason, evidence))
    return found


def file_hashes(email) -> list:
    """SHA-256 of every attachment (shared as an IoC instead of the file itself)."""
    return [{"filename": a.filename, "size": len(a.content or b""),
             "sha256": sha256_bytes(a.content) if a.content else "(name only)"} for a in email.attachments]
