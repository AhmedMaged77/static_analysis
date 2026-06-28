import math
import re
import base64
import zipfile
import subprocess
import os
import datetime
import tempfile
from pathlib import Path
from typing import Optional

import magic  # pip install python-magic
import yara  # pip install yara-python
import clamd  # pip install clamd
import exiftool  # pip install PyExifTool
import pefile  # pip install pefile
import pikepdf  # pip install pikepdf
from oletools.olevba import VBA_Parser  # pip install oletools
from oletools.oleid import OleID

try:
    import rarfile  
except Exception:
    rarfile = None

try:
    import py7zr   
except Exception:
    py7zr = None


DEBUG = False
DEFAULT_MAX_DEPTH = 1


def debug_log(message: str) -> None:
    if DEBUG:
        print(f"[static_analyzer] {message}")


def add_reason(reasons: list[str], reason: str) -> None:
    if reason not in reasons:
        reasons.append(reason)


def get_extension(filename: str) -> Optional[str]:
    base = os.path.basename(filename)
    if "." not in base:
        return None
    return base.rsplit(".", 1)[-1].lower()


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = {}
    for b in data:
        freq[b] = freq.get(b, 0) + 1
    length = len(data)
    return -sum((c / length) * math.log2(c / length) for c in freq.values())


def detect_mime(file_path: str) -> list[str]:
    try:
        mime = magic.from_file(file_path, mime=True)
        return [mime] if mime else []
    except Exception:
        return []


YARA_RULES_DIR = os.getenv("YARA_RULES_DIR", "./yara_rules")
_yara_rules = None


def load_yara_rules() -> Optional[yara.Rules]:
    rule_files = (
        list(Path(YARA_RULES_DIR).glob("*.yar")) +
        list(Path(YARA_RULES_DIR).glob("*.yara"))
    )
    if not rule_files:
        return None
    sources = {str(p.stem): str(p) for p in rule_files}
    return yara.compile(filepaths=sources)


def run_yara(file_path: str) -> dict:
    global _yara_rules
    if _yara_rules is None:
        _yara_rules = load_yara_rules()
    if _yara_rules is None:
        return {"matches": []}
    matches = _yara_rules.match(file_path)
    return {"matches": [m.rule for m in matches]}


def run_clamav(file_path: str) -> dict:
    try:
        cd = clamd.ClamdUnixSocket()
        result = cd.scan(file_path)
        status = result.get(file_path, ("OK", None))
        infected = 0 if status[0] == "OK" else 1
        return {"Infected files": str(infected)}
    except Exception:
        try:
            r = subprocess.run(
                ["clamscan", "--no-summary", file_path],
                capture_output=True, text=True
            )
            infected = 1 if "FOUND" in r.stdout else 0
            return {"Infected files": str(infected)}
        except Exception:
            return {"Infected files": "0"}


def run_exiftool(file_path: str) -> dict:
    try:
        with exiftool.ExifTool() as et:
            meta = et.get_metadata(file_path)
        return {
            "creator": meta.get("XMP:Creator") or meta.get("PDF:Creator", ""),
            "producer": meta.get("PDF:Producer") or meta.get("XMP:Producer", ""),
        }
    except Exception:
        return {}


URL_RE = re.compile(rb"https?://[^\s\x00-\x1f\"\'<>]{4,}")
IP_RE = re.compile(rb"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def extract_iocs(file_path: str) -> list[dict]:
    iocs = []
    try:
        with open(file_path, "rb") as f:
            data = f.read()
        seen = set()
        for m in URL_RE.finditer(data):
            val = m.group().decode(errors="ignore").rstrip(".,)")
            if val not in seen:
                iocs.append({"ioc": val, "ioc_type": "url"})
                seen.add(val)
        for m in IP_RE.finditer(data):
            val = m.group().decode(errors="ignore")
            parts = val.split(".")
            if all(0 <= int(p) <= 255 for p in parts) and val not in seen:
                iocs.append({"ioc": val, "ioc_type": "ip"})
                seen.add(val)
    except Exception:
        pass
    return iocs


def detect_archive_type(file_path: str, mime: list[str]) -> Optional[str]:
    ext = get_extension(file_path)
    if ext in {"zip", "rar", "7z"}:
        return ext
    if any("officedocument" in m for m in mime):
        return "zip"
    if any("zip" in m for m in mime):
        return "zip"
    if any("rar" in m for m in mime):
        return "rar"
    if any("7z" in m or "7-zip" in m for m in mime):
        return "7z"
    return None


def extract_children(file_path: str, mime: list[str], extract_dir: str) -> list[str]:
    children = []
    archive_type = detect_archive_type(file_path, mime)
    if not archive_type:
        try:
            with zipfile.ZipFile(file_path):
                archive_type = "zip"
        except Exception:
            return children

    debug_log(f"Extracting {archive_type} archive: {file_path}")
    try:
        if archive_type == "zip":
            with zipfile.ZipFile(file_path) as zf:
                for name in zf.namelist():
                    zf.extract(name, extract_dir)
                    children.append(os.path.join(extract_dir, name))
        elif archive_type == "rar":
            if rarfile is None:
                debug_log("rarfile not installed; skipping RAR extraction")
                return children
            with rarfile.RarFile(file_path) as rf:
                rf.extractall(extract_dir)
                for name in rf.namelist():
                    children.append(os.path.join(extract_dir, name))
        elif archive_type == "7z":
            if py7zr is None:
                debug_log("py7zr not installed; skipping 7z extraction")
                return children
            with py7zr.SevenZipFile(file_path, mode="r") as zf:
                zf.extractall(path=extract_dir)
                for name in zf.getnames():
                    children.append(os.path.join(extract_dir, name))
    except Exception as exc:
        debug_log(f"Failed to extract {file_path}: {exc}")

    return children


def analyze_pe(file_path: str) -> dict:
    result = {"score": 0, "reasons": []}
    SUSPICIOUS_APIS = {
        "VirtualAlloc", "VirtualAllocEx", "WriteProcessMemory",
        "CreateRemoteThread", "NtUnmapViewOfSection",
        "RegSetValueEx", "CreateService", "StartService",
        "IsDebuggerPresent", "CheckRemoteDebuggerPresent",
        "GetTickCount", "Sleep", "NtDelayExecution",
        "WSAStartup", "connect", "InternetOpen",
        "CryptEncrypt", "CryptGenKey",
    }
    KNOWN_PACKERS = {".upx0", ".upx1", ".aspack", ".themida", ".nsp0"}
    try:
        pe = pefile.PE(file_path)

        imports_found = []
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                for imp in entry.imports:
                    if imp.name:
                        name = imp.name.decode(errors="ignore")
                        if name in SUSPICIOUS_APIS:
                            imports_found.append(name)
        if imports_found:
            result["score"] += len(imports_found) * 10
            add_reason(result["reasons"], f"Suspicious imports: {imports_found}")

        for section in pe.sections:
            name = section.Name.decode(errors="ignore").strip("\x00").lower()
            entropy = section.get_entropy()
            if entropy > 7.2:
                result["score"] += 20
                add_reason(result["reasons"], f"High entropy section '{name}': {entropy:.2f}")
            if (
                section.Characteristics & 0x20000000 and
                section.Characteristics & 0x80000000
            ):
                result["score"] += 30
                add_reason(
                    result["reasons"],
                    f"Section '{name}' is writable AND executable (W^X violation)"
                )
            if name in KNOWN_PACKERS:
                result["score"] += 40
                add_reason(result["reasons"], f"Known packer section: {name}")

        ts = pe.FILE_HEADER.TimeDateStamp
        if ts == 0 or ts == 0xFFFFFFFF:
            result["score"] += 15
            add_reason(result["reasons"], "PE timestamp is zeroed/invalid")
        else:
            compiled = datetime.datetime.utcfromtimestamp(ts)
            now = datetime.datetime.utcnow()
            if compiled > now or compiled.year < 2000:
                result["score"] += 20
                add_reason(result["reasons"], f"Suspicious compile timestamp: {compiled}")

        overlay = pe.get_overlay()
        if overlay and len(overlay) > 1024:
            result["score"] += 20
            add_reason(
                result["reasons"],
                f"PE has overlay data ({len(overlay)} bytes) — common in packers"
            )

        result["imphash"] = pe.get_imphash()

    except pefile.PEFormatError:
        pass
    except Exception:
        pass
    return result


def analyze_office_macros(file_path: str) -> dict:
    result = {"score": 0, "reasons": []}

    AUTOEXEC_KEYWORDS = {
        "AutoOpen", "AutoClose", "AutoExec", "Document_Open",
        "Workbook_Open", "Auto_Open", "DocumentOpen"
    }
    DANGEROUS_KEYWORDS = {
        "Shell", "WScript", "CreateObject", "PowerShell",
        "cmd.exe", "mshta", "regsvr32", "certutil",
        "Environ", "StrReverse"
    }
    # Removed "Base64" and "Chr(" from DANGEROUS — too common in legitimate macros
    # Chr() is used in normal string handling; Base64 in data encoding

    OBFUSCATION_COMBOS = [
        ("Chr(", "StrReverse"),   # common obfuscation pair
        ("Chr(", "Environ"),
    ]

    try:
        vba = VBA_Parser(file_path)
        if not vba.detect_vba_macros():
            return result

        # Don't score just for having macros — score only on what they DO
        has_autoexec   = False
        has_dangerous  = False
        dangerous_hits = []
        autoexec_hits  = []
        total_chr      = 0
        total_lines    = 0

        for _, _, _, code in vba.extract_macros():
            code_upper  = code.upper()
            total_lines += len(code.splitlines())

            hits_auto = [k for k in AUTOEXEC_KEYWORDS if k.upper() in code_upper]
            if hits_auto:
                has_autoexec = True
                autoexec_hits.extend(hits_auto)

            hits_danger = [k for k in DANGEROUS_KEYWORDS if k.upper() in code_upper]
            if hits_danger:
                has_dangerous = True
                dangerous_hits.extend(hits_danger)

            total_chr += code_upper.count("CHR(")

        # Score only on combinations — autoexec alone or dangerous alone is weak signal
        if has_autoexec and has_dangerous:
            result["score"] += 60
            add_reason(
                result["reasons"],
                f"Macro with auto-execution AND dangerous calls: "
                f"autoexec={autoexec_hits}, dangerous={dangerous_hits}"
            )
        elif has_autoexec:
            result["score"] += 15
            add_reason(result["reasons"], f"Macro with auto-execution trigger: {autoexec_hits}")
        elif has_dangerous:
            result["score"] += 20
            add_reason(
                result["reasons"],
                f"Macro with dangerous calls (no autoexec): {dangerous_hits}"
            )

        # Obfuscation: Chr() ratio relative to code size, not raw count
        # Legitimate macros can have some Chr() calls; only flag excessive ratio
        if total_lines > 0:
            chr_ratio = total_chr / total_lines
            if chr_ratio > 2.0 and total_chr > 20:
                result["score"] += 25
                add_reason(
                    result["reasons"],
                    f"High Chr() density ({total_chr} calls over {total_lines} lines) "
                    f"- likely obfuscation"
                )

    except Exception:
        pass

    # OLE indicators (unchanged — these are reliable signals)
    try:
        oid = OleID(file_path)
        for i in oid.check():
            if i.id == "flash" and i.value:
                result["score"] += 50
                add_reason(result["reasons"], "Embedded Flash object")
            if i.id == "ext_rels" and i.value:
                result["score"] += 20
                add_reason(
                    result["reasons"],
                    "External relationships (template injection risk)"
                )
    except Exception:
        pass

    return result


def analyze_pdf(file_path: str) -> dict:
    result = {"score": 0, "reasons": []}

    DANGEROUS_KEYS = {
        "/JS":           ("JavaScript in PDF", 50),
        "/JavaScript":   ("JavaScript in PDF", 50),
        "/Launch":       ("/Launch action (RCE risk)", 60),
        "/OpenAction":   ("OpenAction trigger", 30),
        "/AA":           ("Additional Actions (auto-trigger)", 25),
        "/RichMedia":    ("RichMedia (Flash embed)", 40),
        "/EmbeddedFile": ("Embedded file in PDF", 20),
        "/XFA":          ("XFA form (complex attack surface)", 20),
        "/URI":          ("URI action", 10),
        "/SubmitForm":   ("Form submission action", 15),
        "/ImportData":   ("ImportData action", 20),
    }

    # Filters that are only useful for obfuscation when stacked
    OBFUSCATION_FILTERS = {"/ASCIIHexDecode", "/ASCII85Decode", "/LZWDecode"}
    # Legitimate compression filters — fine on their own
    NORMAL_FILTERS = {"/FlateDecode", "/DCTDecode", "/JPXDecode", "/CCITTFaxDecode"}

    try:
        with pikepdf.open(file_path, suppress_warnings=True) as pdf:
            page_count = len(pdf.pages)

            # ── Page-level dangerous key scan ────────────────────────────
            for obj in pdf.pages:
                for key, (reason, pts) in DANGEROUS_KEYS.items():
                    if key in obj:
                        result["score"] += pts
                        add_reason(result["reasons"], reason)

            # ── Document-level OpenAction ─────────────────────────────────
            if "/OpenAction" in pdf.Root:
                result["score"] += 30
                add_reason(result["reasons"], "Document-level OpenAction")

            # ── Object stream analysis (the real obfuscation signal) ──────
            obj_stream_count   = 0
            stacked_filter_count = 0
            js_in_objstm       = False
            anonymous_streams  = 0

            for obj in pdf.objects:
                if not isinstance(obj, pikepdf.Stream):
                    continue

                stream_dict = dict(obj)

                # /ObjStm — objects packed inside a stream to hide them
                if stream_dict.get("/Type") == pikepdf.Name("/ObjStm"):
                    obj_stream_count += 1

                # Stacked filters — layered encoding is an obfuscation technique
                filters = stream_dict.get("/Filter")
                if filters is not None:
                    if isinstance(filters, pikepdf.Array):
                        filter_names = {str(f) for f in filters}
                        # Multiple filters = stacking
                        if len(filters) > 1:
                            # Only suspicious if obfuscation filters are involved
                            if filter_names & OBFUSCATION_FILTERS:
                                stacked_filter_count += 1
                        # Single obfuscation filter alongside JS is suspicious
                        elif filter_names & OBFUSCATION_FILTERS:
                            # Only flag if paired with other signals (checked below)
                            pass

                # Anonymous streams (no /Type, no /Subtype) are sometimes
                # used to hide shellcode — only flag if there are many of them
                # relative to page count, to avoid false positives on simple docs
                has_type    = "/Type"    in stream_dict
                has_subtype = "/Subtype" in stream_dict
                if not has_type and not has_subtype:
                    anonymous_streams += 1

            # Score based on real obfuscation signals, not raw counts

            if obj_stream_count > 5:
                result["score"] += 20
                add_reason(
                    result["reasons"],
                    f"Object streams (/ObjStm) detected ({obj_stream_count}) "
                    f"- objects hidden inside compressed streams"
                )

            if stacked_filter_count > 0:
                result["score"] += 30 * min(stacked_filter_count, 3)
                add_reason(
                    result["reasons"],
                    f"Stacked encoding filters detected ({stacked_filter_count} streams) "
                    f"- layered obfuscation technique"
                )

            # Anonymous stream ratio: only meaningful relative to page count
            # A 1-page doc with 50 anonymous streams is suspicious.
            # A 100-page doc with 50 anonymous streams is probably fine.
            if page_count > 0:
                anon_ratio = anonymous_streams / page_count
                if anon_ratio > 20 and anonymous_streams > 30:
                    result["score"] += 15
                    add_reason(
                        result["reasons"],
                        f"High anonymous stream ratio ({anonymous_streams} streams, "
                        f"{page_count} pages) - possible hidden content"
                    )

    except pikepdf.PasswordError:
        result["score"] += 40
        add_reason(result["reasons"], "PDF is password-protected")
    except Exception:
        pass

    return result


def analyze_strings(file_path: str) -> dict:
    result = {"score": 0, "reasons": []}

    SUSPICIOUS_PATTERNS = [
        (r'powershell\s+-[eE]',                          "Encoded PowerShell command",        40),
        (r'cmd\.exe\s*/[cC]',                            "cmd.exe execution",                 30),
        (r'mshta\.exe',                                  "MSHTA execution (LOLBin)",          35),
        (r'certutil.*-decode',                           "Certutil decode (LOLBin abuse)",    40),
        (r'regsvr32.*scrobj',                            "Regsvr32 scriptlet (Squiblydoo)",   50),
        (r'WScript\.Shell',                              "WScript.Shell COM object",          30),
        (r'net\s+user\s+.*\/add',                        "User creation command",             50),
        # Removed:
        # - HKEY_* registry keys  → too common in legitimate installers
        # - %APPDATA%/%TEMP%       → too common in legitimate software
        # - UNC paths              → too common in enterprise software
    ]

    # Patterns that indicate a Base64 blob is benign — skip these
    B64_BENIGN_PREFIXES = {
        "MIIC", "MIID", "MIIE", "MIIF",  # X.509 certificates
        "AAAA",                            # SSH public keys
        "TVqQ",                            # PE file magic in b64 (handle separately)
    }

    # These decoded prefixes ARE suspicious even if the blob looks normal
    B64_SUSPICIOUS_DECODED = [
        b"MZ",           # PE executable
        b"PK",           # ZIP/Office doc
        b"powershell",
        b"cmd.exe",
        b"WScript",
        b"CreateObject",
        b"<script",
        b"invoke-",
    ]

    try:
        with open(file_path, "rb") as f:
            data = f.read()

        strings = re.findall(rb'[\x20-\x7e]{6,}', data)
        decoded = [s.decode(errors="ignore") for s in strings]
        combined = "\n".join(decoded)

        # Pattern matching (unchanged)
        for pattern, reason, pts in SUSPICIOUS_PATTERNS:
            if re.search(pattern, combined, re.IGNORECASE):
                result["score"] += pts
                add_reason(result["reasons"], reason)

        # Base64 — much stricter now
        # Require length >= 100 (not 40) to cut noise significantly
        b64_candidates = re.findall(r'(?:[A-Za-z0-9+/]{100,}={0,2})', combined)

        suspicious_b64 = []
        for blob in b64_candidates:
            # Skip known-benign prefixes
            if any(blob.startswith(p) for p in B64_BENIGN_PREFIXES):
                continue

            # Must be valid Base64 padding
            pad = len(blob) % 4
            if pad:
                blob += "=" * (4 - pad)

            try:
                raw = base64.b64decode(blob)
            except Exception:
                continue  # not valid Base64, skip

            # Skip if decoded content is mostly non-printable
            # (e.g. image/font binary data embedded in Office XML)
            printable = sum(0x20 <= b <= 0x7e for b in raw)
            printable_ratio = printable / len(raw) if raw else 0

            # Check for suspicious decoded content
            raw_lower = raw[:200].lower()
            is_suspicious = any(sig in raw_lower for sig in B64_SUSPICIOUS_DECODED)

            if is_suspicious:
                suspicious_b64.append(blob[:30] + "...")
                result["score"] += 40
                add_reason(
                    result["reasons"],
                    f"Base64 decodes to suspicious content (executable/script markers)"
                )
            elif printable_ratio > 0.85 and len(raw) > 200:
                # High printable ratio = likely a script or command, not binary data
                raw_str = raw.decode(errors="ignore").lower()
                if any(kw in raw_str for kw in [
                    "powershell", "invoke", "wscript", "createobject",
                    "cmd.exe", "shellexecute", "http://", "https://"
                ]):
                    suspicious_b64.append(blob[:30] + "...")
                    result["score"] += 35
                    add_reason(
                        result["reasons"],
                        "Base64 blob contains suspicious script/command keywords"
                    )

        if len(suspicious_b64) > 1:
            result["score"] += 10  # bonus for multiple suspicious blobs
            add_reason(
                result["reasons"],
                f"Multiple suspicious Base64 blobs found ({len(suspicious_b64)})"
            )

    except Exception:
        pass

    return result


def analyze_archive(file_path: str, mime: Optional[list[str]] = None) -> dict:
    result = {"score": 0, "reasons": []}
    if mime is None:
        mime = detect_mime(file_path)

    archive_type = detect_archive_type(file_path, mime)
    if archive_type == "zip":
        try:
            with zipfile.ZipFile(file_path) as zf:
                infos = zf.infolist()
                total_compressed = sum(i.compress_size for i in infos)
                total_uncompressed = sum(i.file_size for i in infos)
                if total_compressed > 0:
                    ratio = total_uncompressed / total_compressed
                    if ratio > 100:
                        result["score"] += 60
                        add_reason(
                            result["reasons"],
                            f"Zip bomb risk: compression ratio {ratio:.0f}:1"
                        )
                nested = [
                    n for n in zf.namelist()
                    if n.endswith((".zip", ".rar", ".7z", ".gz"))
                ]
                if nested:
                    result["score"] += 20
                    add_reason(
                        result["reasons"],
                        f"Nested archives found ({len(nested)}) inside archive"
                    )
                for info in infos:
                    if info.flag_bits & 0x1:
                        result["score"] += 25
                        add_reason(
                            result["reasons"],
                            "Password-protected entries in archive"
                        )
                        break
        except Exception:
            pass
    elif archive_type == "rar":
        if rarfile is None:
            return result
        try:
            with rarfile.RarFile(file_path) as rf:
                infos = rf.infolist()
                total_compressed = sum(
                    getattr(i, "compress_size", 0) for i in infos
                )
                total_uncompressed = sum(
                    getattr(i, "file_size", 0) for i in infos
                )
                if total_compressed > 0:
                    ratio = total_uncompressed / total_compressed
                    if ratio > 100:
                        result["score"] += 60
                        add_reason(
                            result["reasons"],
                            f"Zip bomb risk: compression ratio {ratio:.0f}:1"
                        )
                nested = [
                    n for n in rf.namelist()
                    if n.endswith((".zip", ".rar", ".7z", ".gz"))
                ]
                if nested:
                    result["score"] += 20
                    add_reason(
                        result["reasons"],
                        f"Nested archives found ({len(nested)}) inside archive"
                    )
                if hasattr(rf, "needs_password") and rf.needs_password():
                    result["score"] += 25
                    add_reason(
                        result["reasons"],
                        "Password-protected entries in archive"
                    )
                else:
                    for info in infos:
                        needs_pw = getattr(info, "needs_password", None)
                        if callable(needs_pw) and needs_pw():
                            result["score"] += 25
                            add_reason(
                                result["reasons"],
                                "Password-protected entries in archive"
                            )
                            break
        except Exception:
            pass
    elif archive_type == "7z":
        if py7zr is None:
            return result
        try:
            with py7zr.SevenZipFile(file_path, mode="r") as zf:
                infos = []
                if hasattr(zf, "list"):
                    infos = zf.list()
                total_compressed = sum(
                    getattr(i, "compressed", 0) for i in infos
                )
                total_uncompressed = sum(
                    getattr(i, "uncompressed", 0) for i in infos
                )
                if total_compressed > 0:
                    ratio = total_uncompressed / total_compressed
                    if ratio > 100:
                        result["score"] += 60
                        add_reason(
                            result["reasons"],
                            f"Zip bomb risk: compression ratio {ratio:.0f}:1"
                        )
                names = zf.getnames() if hasattr(zf, "getnames") else []
                nested = [
                    n for n in names
                    if n.endswith((".zip", ".rar", ".7z", ".gz"))
                ]
                if nested:
                    result["score"] += 20
                    add_reason(
                        result["reasons"],
                        f"Nested archives found ({len(nested)}) inside archive"
                    )
                if getattr(zf, "password_protected", False):
                    result["score"] += 25
                    add_reason(
                        result["reasons"],
                        "Password-protected entries in archive"
                    )
                elif hasattr(zf, "needs_password") and zf.needs_password():
                    result["score"] += 25
                    add_reason(
                        result["reasons"],
                        "Password-protected entries in archive"
                    )
        except Exception:
            pass

    return result


def analyze_file(
    file_path: str,
    depth: int = 0,
    max_depth: int = DEFAULT_MAX_DEPTH
) -> list[dict]:
    results = []

    with open(file_path, "rb") as f:
        data = f.read()

    mime = detect_mime(file_path)
    yara_out = run_yara(file_path)
    entropy = shannon_entropy(data)
    clamav = run_clamav(file_path)
    exif = run_exiftool(file_path)
    iocs = extract_iocs(file_path)

    record = {
        "file": {
            "filename": os.path.basename(file_path),
            "extension": get_extension(file_path),
            "depth": depth,
            "flavors": {
                "mime": mime,
                "yara": yara_out.get("matches", []),
            }
        },
        "scan": {
            "entropy": {"entropy": entropy},
            "clamav": clamav,
            "exiftool": exif,
            "yara": yara_out,
        },
        "pdf": {"yara": {"matches": []}},
        "iocs": iocs,
        "_pe": analyze_pe(file_path),
        "_macros": analyze_office_macros(file_path),
        "_strings": analyze_strings(file_path),
        "_archive": analyze_archive(file_path, mime),
    }

    if any("pdf" in m for m in mime):
        record["pdf"]["yara"] = yara_out
        record["_pdf_deep"] = analyze_pdf(file_path)

    results.append(record)

    # Recurse into embedded files (depth 1 only)
    if depth < max_depth:
        debug_log(f"Recursing into children for {file_path} at depth {depth}")
        with tempfile.TemporaryDirectory(prefix="static_analyzer_") as extract_dir:
            debug_log(f"Using extraction dir: {extract_dir}")
            for child_path in extract_children(file_path, mime, extract_dir):
                if os.path.isfile(child_path):
                    results.extend(
                        analyze_file(
                            child_path,
                            depth=depth + 1,
                            max_depth=max_depth
                        )
                    )
        debug_log(f"Cleaned up extraction dir: {extract_dir}")

    return results
