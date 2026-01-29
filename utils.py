import hashlib

def sha256sum(file_path):
    h = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()

def compute_score(strelka_json):
    """
    Example scoring logic:
    - +50 if YARA match
    - +20 if suspicious macros
    """
    score = 0
    reasons = []

    yara_matches = strelka_json.get("file", {}).get("flavors", {}).get("yara", [])
    if yara_matches:
        score += 50
        reasons.append(f"YARA matches: {', '.join(yara_matches)}")

    olevba_matches = strelka_json.get("file", {}).get("flavors", {}).get("olevba", [])
    if olevba_matches:
        score += 20
        reasons.append("Suspicious macros detected")

    verdict = "malicious" if score > 50 else "benign"
    return score, verdict, reasons
