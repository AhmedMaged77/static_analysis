import json
from typing import Dict, List, Optional

def analyze_file_type(
    file_json: dict,
    depth: int,
    extension: str | None,
    parent_extension: str | None = None
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
            any(extension in m for m in mime) or
            any(extension in y for y in yara)
        ):
            classification = "Normal"

        return mime, classification
        

    # Child file logic
    classification = "Unusual"
    parent_extension = EXTENSION_TO_TYPE.get(parent_extension,"unknown")
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



def compute_score(strelka_json,file_path):
  
  score = 0
  reasons = []
  verdict = "Benign"
  extension = get_extension(file_path)
  for jsn in strelka_json:
    depth = jsn.get("file", {}).get("depth")
    if depth == 0:
      file_type,classification = analyze_file_type(jsn.get("file", {}).get("flavors", {}),depth,extension)
      if classification == "Unusual" :
         score = score + 50
         reasons.append(f"Umatched file type, original: {extension}, detected: {file_type}")
    else:
      file_type,classification = analyze_file_type(jsn.get("file", {}).get("flavors", {}),depth,extension,extension)
      if classification == "Unusual" :
         score = score + 50
         reasons.append(f"Umatched file type included, parent: {extension}, detected: {file_type}")
    
    mime = jsn.get("file", {}).get("flavors", {}).get("mime", [])
    yara = jsn.get("file", {}).get("flavors", {}).get("yara", [])
    
    for m in mime:
      if "encrypted" in m:
        score += 50
        reasons.append("Encrypted file")
    for m in yara:
      if "encrypted" in m:
        score += 50 
        reasons.append("Encrypted file")

    clamav_scan = jsn.get("scan", {}).get("clamav", {})

    infected_raw = clamav_scan.get("Infected files", "0")

    try:
        infected = int(infected_raw)
    except (ValueError, TypeError):
        infected = 0

    if infected > 0:
        score += 100
        reasons.append("ClamAV detected malware signature")

    entropy = jsn.get("scan", {}).get("entropy",{}).get("entropy")

    if entropy > 7.2:
       score += 25
       reasons.append(f"High entropy = {entropy}")



  if score >= 50 :
    verdict = "Malicious"

  
  return score, verdict, reasons





