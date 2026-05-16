# scoring_v2.py
# Standalone scoring logic for the new in-process analysis engine.
# Does NOT modify or import from file_scoring.py.

from typing import Optional

from utils import vt_lookup


DEBUG = False

VERDICT_THRESHOLDS = {
    "Benign": 0,
    "Suspicious": 30,
    "Malicious": 61,
}

MAX_IOC_VT_LOOKUPS = 20


def debug_log(message: str) -> None:
    if DEBUG:
        print(f"[scoring_v2] {message}")


def add_reason(reasons: list[str], reason: str) -> None:
    if reason not in reasons:
        reasons.append(reason)


def analyze_file_type(
    file_json: dict,
    depth: int,
    extension: str,
    parent_extension: str = None
) -> dict:

    # Canonical definitions
    CANONICAL_TYPES = {
        "office_doc": {
            "doc", "docx", "docm",
            "xls", "xlsx", "xlsm",
            "ppt", "pptx", "office_doc"
        },
        "pdf": {"pdf"},
        "archive": {"zip", "rar", "7z", "tar", "gz", "archive"},
        "executable": {"executable", "exe", "dll", "elf", "macho"},
        "script": {"script", "js", "vbs", "ps1", "bat", "sh"},
        "image": {"image", "png", "jpg", "jpeg", "gif", "bmp", "heic"},
        "text": {"image", "txt", "csv"}
    }

    EXTENSION_TO_TYPE = {
        ext: category
        for category, exts in CANONICAL_TYPES.items()
        for ext in exts
    }

    EXPECTED_CHILDREN = {
        "office_doc": {"xml", "image", "rels", "ole", "png", "jpg", "jpeg", "gif", "bmp", "heic"},
        "pdf": {"image", "font", "text", "png", "jpg", "jpeg", "gif", "bmp", "heic", "txt", "csv"},
        "archive": {"office_doc", "pdf", "image", "text", "png", "jpg", "jpeg", "gif", "bmp", "heic", "txt", "csv"},
        "image": set()
    }


    extension = extension.lower() if extension else None
    file_type = EXTENSION_TO_TYPE.get(extension, "unknown")

    mime = file_json.get("mime", [])
    yara = file_json.get("yara", [])

    # Root file logic
    if depth == 0:
        classification = "Unusual"

        if (
            any(file_type in m for m in mime) or
            any(file_type in y for y in yara) or
            (extension and any(extension in m for m in mime)) or
            (extension and any(extension in y for y in yara))
        ):
            classification = "Normal"

        return mime, classification


    # Child file logic
    classification = "Unusual"
    parent_extension = EXTENSION_TO_TYPE.get(parent_extension, "unknown")
    expected = EXPECTED_CHILDREN.get(parent_extension, set())

    for m in mime:
        for e in expected:
            if e in m:
                classification = "Normal"

    for m in yara:
        for e in expected:
            if e in m:
                classification = "Normal"

    if extension in expected or file_type in expected:
        classification = "Normal"

    return mime, classification



def get_extension(filename: str) -> Optional[str]:
    if "." not in filename:
        return None
    return filename.rsplit(".", 1)[-1].lower()


def determine_verdict(score: int) -> str:
    if score >= VERDICT_THRESHOLDS["Malicious"]:
        return "Malicious"
    if score >= VERDICT_THRESHOLDS["Suspicious"]:
        return "Suspicious"
    return "Benign"


def analyze_iocs(iocs: list) -> tuple[int, list[str]]:
    score = 0
    reasons = []
    vt_cache: dict[tuple[str, str], Optional[dict]] = {}
    vt_lookups = 0
    limit_reached = False

    suspicious_tlds = {
        ".tk", ".ml", ".ga", ".cf", ".gq",
        ".xyz", ".buzz", ".top", ".loan", ".bond",
        ".faith", ".stream", ".download", ".online",
        ".tech", ".work", ".country", ".kim",
        ".science", ".ninja", ".date", ".racing",
        ".cricket", ".win", ".space", ".accountant",
        ".realtor", ".christmas", ".gdn", ".men", ".pro", ".click", ".site"
    }

    for item in iocs:
        ioc      = item.get("ioc", "")
        ioc_type = item.get("ioc_type", "")

        if ioc_type in {"url", "domain"}:
            score += 5
            for tld in suspicious_tlds:
                if tld in ioc:
                    score += 20
                    add_reason(reasons, f"Suspicious TLD detected: {tld}")

        if ioc_type == "ip":
            score += 30
            add_reason(reasons, "IP exist in the file")

        # BUG FIX: vt_lookup is now correctly inside the loop
        cache_key = (ioc, ioc_type)
        if cache_key in vt_cache:
            vt_result = vt_cache[cache_key]
            debug_log(f"VT cache hit for {ioc} ({ioc_type})")
        else:
            if vt_lookups >= MAX_IOC_VT_LOOKUPS:
                if not limit_reached:
                    add_reason(reasons, "VirusTotal IOC lookup limit reached")
                    limit_reached = True
                continue
            try:
                vt_result = vt_lookup(ioc, ioc_type)
                vt_cache[cache_key] = vt_result
                vt_lookups += 1
                debug_log(f"VT lookup for {ioc} ({ioc_type})")
            except Exception as exc:
                debug_log(f"VT lookup failed for {ioc} ({ioc_type}): {exc}")
                continue

        if vt_result:
            if vt_result.get("malicious", 0) > 0:
                score += 100
                add_reason(
                    reasons,
                    f"VirusTotal malicious IOC: {ioc} "
                    f"(detections: {vt_result['malicious']})"
                )
            elif vt_result.get("suspicious", 0) > 1:
                score += 50
                add_reason(reasons, f"VirusTotal suspicious IOC: {ioc}")

    return score, reasons


def check_automated_files(creator):

    HIGH_RISK_CREATORS = {
        "headless", "puppeteer", "playwright", "selenium", "chromium"
    }

    PDF_ENGINES = {
        "skia", "pdfium", "wkhtmltopdf", "weasyprint",
        "prince", "pdfkit", "reportlab"
    }

    SCRIPT_TOOLS = {
        "libreoffice", "openoffice", "unoconv",
        "pandoc", "ghostscript"
    }
    score = 0
    creator = creator.lower()
    reasons = []
    if any(k in creator for k in HIGH_RISK_CREATORS):
        score += 40
        add_reason(reasons, f"Document generated by automated browser: {creator}")

    elif any(k in creator for k in PDF_ENGINES):
        score += 30
        add_reason(reasons, f"Programmatic PDF generator detected: {creator}")

    elif any(k in creator for k in SCRIPT_TOOLS):
        score += 20
        add_reason(reasons, f"Document generated via scripting tool: {creator}")

    return score, reasons


def check_yara(yara_out):
    matches = yara_out.get("matches", [])
    score = 0
    reasons = []
    if matches:
        for rule in matches:
            score += 30
            add_reason(reasons, f"yara rule fired: {rule}")

    return score, reasons



def compute_score(analysis_json, file_path):
    score     = 0
    reasons   = []
    extension = get_extension(file_path)

    for jsn in analysis_json:
        depth = jsn.get("file", {}).get("depth")

        if depth == 0:
            file_type, classification = analyze_file_type(
                jsn.get("file", {}).get("flavors", {}), depth, extension
            )
            if classification == "Unusual":
                score += 50
                add_reason(
                    reasons,
                    f"Unmatched file type, original: {extension}, detected: {file_type}"
                )
        else:
            child_extension = (
                jsn.get("file", {}).get("extension") or
                get_extension(jsn.get("file", {}).get("filename", ""))
            )
            file_type, classification = analyze_file_type(
                jsn.get("file", {}).get("flavors", {}),
                depth,
                child_extension,
                extension
            )
            if classification == "Unusual":
                score += 50
                add_reason(
                    reasons,
                    f"Unmatched file type included, parent: {extension}, detected: {file_type}"
                )

        mime = jsn.get("file", {}).get("flavors", {}).get("mime", [])
        yara = jsn.get("file", {}).get("flavors", {}).get("yara", [])
        # Skip entropy checks for PDFs (high entropy in PDFs is normal)
        is_pdf = bool(jsn.get("pdf")) or any("pdf" in m for m in mime)

        for m in mime:
            if "encrypted" in m:
                score += 50
                add_reason(reasons, "Encrypted file")
        for m in yara:
            if "encrypted" in m:
                score += 50
                add_reason(reasons, "Encrypted file")

        clamav_scan  = jsn.get("scan", {}).get("clamav", {})
        infected_raw = clamav_scan.get("Infected files", "0")
        try:
            infected = int(infected_raw)
        except (ValueError, TypeError):
            infected = 0
        if infected > 0:
            score += 100
            add_reason(reasons, "ClamAV detected malware signature")

        entropy = jsn.get("scan", {}).get("entropy", {}).get("entropy")
        # Only apply entropy penalties when the file is not a PDF
        if not is_pdf and entropy and entropy > 7.7:
            score += 25
            if entropy > 7.9:
                score += 10
            add_reason(reasons, f"High entropy = {entropy}")

        if jsn.get("iocs", []):
            s, r = analyze_iocs(jsn.get("iocs", []))
            score += s
            for u in r:
                add_reason(reasons, u)

        if jsn.get("scan", {}).get("exiftool", {}).get("creator"):
            s, r = check_automated_files(jsn["scan"]["exiftool"]["creator"])
            score += s
            for u in r:
                add_reason(reasons, u)

        if jsn.get("scan", {}).get("exiftool", {}).get("producer"):
            s, r = check_automated_files(jsn["scan"]["exiftool"]["producer"])
            score += s
            for u in r:
                add_reason(reasons, u)

        if jsn.get("scan", {}).get("yara", {}):
            s, r = check_yara(jsn["scan"]["yara"])
            score += s
            for u in r:
                add_reason(reasons, u)

        if jsn.get("pdf", {}).get("yara", {}):
            s, r = check_yara(jsn["pdf"]["yara"])
            score += s
            for u in r:
                add_reason(reasons, u)

        # ── New module scores (PE, macros, strings, archive, PDF deep) ────
        for module_key in ("_pe", "_macros", "_strings", "_archive", "_pdf_deep"):
            module_result = jsn.get(module_key, {})
            if module_result:
                score += module_result.get("score", 0)
                for r in module_result.get("reasons", []):
                    add_reason(reasons, r)

    verdict = determine_verdict(score)

    return score, verdict, reasons
