import hashlib
import os
import re
import socket
import requests
import base64
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import urlparse

import dns.resolver
import httpx
import tldextract
import whois
from bs4 import BeautifulSoup
from dotenv import load_dotenv

load_dotenv()

VT_API_KEY = os.getenv("VT_API_KEY")

HEADERS = {
    "x-apikey": VT_API_KEY
}


def sha256sum(file_path):
    h = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def vt_lookup(ioc_value: str, ioc_type: str) -> dict :
    """
    Fast VT lookup (NO rescan)
    ioc_type: url | domain | ip | hash
    """

    if not VT_API_KEY:
        raise RuntimeError("VirusTotal API key not found")

    try:
        if ioc_type == "url":
            # VT requires URL to be base64 encoded
            url_id = base64.urlsafe_b64encode(
                ioc_value.encode()
            ).decode().strip("=")

            url = f"https://www.virustotal.com/api/v3/urls/{url_id}"

        elif ioc_type == "domain":
            url = f"https://www.virustotal.com/api/v3/domains/{ioc_value}"

        elif ioc_type == "ip":
            url = f"https://www.virustotal.com/api/v3/ip_addresses/{ioc_value}"

        elif ioc_type == "hash":
            url = f"https://www.virustotal.com/api/v3/files/{ioc_value}"

        else:
            return None

        r = requests.get(url, headers=HEADERS, timeout=10)

        if r.status_code != 200:
            return None

        data = r.json()
        stats = data.get("data", {}).get("attributes", {}).get(
            "last_analysis_stats", {}
        )

        return {
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
        }

    except Exception:
        return None


# URL Analysis Utility Functions

# Common URL shortener domains
URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd",
    "buff.ly", "adf.ly", "bl.ink", "lnkd.in", "rb.gy", "shorturl.at",
    "cutt.ly", "rebrand.ly", "v.gd", "qr.ae", "tiny.cc", "x.co",
    "soo.gd", "s2r.co", "clicky.me", "budurl.com", "bc.vc",
}

# Suspicious TLDs frequently abused in phishing / malware campaigns
SUSPICIOUS_TLDS = {
    "tk", "ml", "ga", "cf", "gq", "xyz", "buzz", "top", "loan",
    "bond", "faith", "stream", "download", "online", "tech", "work",
    "country", "kim", "science", "ninja", "date", "racing", "cricket",
    "win", "space", "accountant", "realtor", "christmas", "gdn", "men",
    "pro", "click", "site", "icu", "cam", "monster", "rest", "surf",
}

# Well-known brands targeted by homograph / look-alike attacks
BRAND_KEYWORDS = [
    "paypal", "google", "apple", "microsoft", "amazon", "facebook",
    "instagram", "netflix", "linkedin", "twitter", "whatsapp", "chase",
    "wellsfargo", "bankofamerica", "dropbox", "icloud",
]


def whois_lookup(domain: str) -> dict:
    """
    Perform a WHOIS lookup and return creation date, registrar,
    domain age in days, and whether WHOIS info is hidden/redacted.
    """
    result = {
        "creation_date": None,
        "registrar": None,
        "domain_age_days": None,
        "whois_hidden": False,
        "error": None,
    }
    try:
        w = whois.whois(domain)

        # Creation date can be a list or a single value
        creation = w.creation_date
        if isinstance(creation, list):
            creation = creation[0]

        if creation:
            result["creation_date"] = str(creation)
            age = (datetime.now(timezone.utc) - creation.replace(tzinfo=timezone.utc)).days
            result["domain_age_days"] = age

        result["registrar"] = w.registrar

        # Detect hidden / privacy-protected WHOIS
        org = str(w.org or "").lower()
        name = str(w.name or "").lower()
        privacy_keywords = ["privacy", "redact", "proxy", "guard", "protect", "whoisguard", "domains by proxy"]
        if any(kw in org for kw in privacy_keywords) or any(kw in name for kw in privacy_keywords):
            result["whois_hidden"] = True

    except Exception as exc:
        result["error"] = str(exc)

    return result


def dns_lookup(domain: str) -> dict:
    """
    Resolve A, AAAA, MX, and NS records for *domain*.
    Returns a dict of record-type → list-of-values, plus an error key.
    """
    records: dict = {"A": [], "AAAA": [], "MX": [], "NS": [], "error": None}
    for rtype in ("A", "AAAA", "MX", "NS"):
        try:
            answers = dns.resolver.resolve(domain, rtype, lifetime=5)
            records[rtype] = [str(r) for r in answers]
        except Exception:
            pass  # record type simply not present
    if not any(records[k] for k in ("A", "AAAA", "MX", "NS")):
        records["error"] = "No DNS records found"
    return records


async def fetch_url_content(url: str, timeout: float = 5.0) -> dict:
    """
    Fetch the URL content asynchronously with httpx.
    Returns body text, final URL (after redirects), status code,
    redirect count, and any error.
    """
    result = {
        "body": "",
        "final_url": url,
        "status_code": None,
        "redirect_count": 0,
        "error": None,
    }
    try:
        async with httpx.AsyncClient(
            follow_redirects=True,
            max_redirects=10,
            timeout=timeout,
            verify=False,  # allow self-signed certs for analysis
        ) as client:
            resp = await client.get(url, headers={
                "User-Agent": (
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/120.0.0.0 Safari/537.36"
                )
            })
            result["body"] = resp.text[:500_000]  # cap to 500 KB of text
            result["final_url"] = str(resp.url)
            result["status_code"] = resp.status_code
            result["redirect_count"] = len(resp.history)
    except httpx.TooManyRedirects:
        result["error"] = "Too many redirects (>10)"
        result["redirect_count"] = 10
    except Exception as exc:
        result["error"] = str(exc)
    return result


def parse_html(html: str) -> dict:
    """
    Parse HTML and extract security-relevant signals:
    - hidden iframes
    - external scripts
    - obfuscated JS patterns (eval, atob, unescape, document.write)
    - login / phishing forms
    - suspicious keywords
    """
    signals: dict = {
        "hidden_iframes": [],
        "external_scripts": [],
        "obfuscated_js": [],
        "login_forms": False,
        "suspicious_keywords": [],
    }

    soup = BeautifulSoup(html, "html.parser")

    # --- Hidden iframes ---
    for iframe in soup.find_all("iframe"):
        style = (iframe.get("style") or "").lower()
        width = iframe.get("width", "")
        height = iframe.get("height", "")
        hidden = iframe.get("hidden") is not None
        if hidden or "display:none" in style.replace(" ", "") or "visibility:hidden" in style.replace(" ", ""):
            signals["hidden_iframes"].append(iframe.get("src", "unknown"))
        elif width in ("0", "1") or height in ("0", "1"):
            signals["hidden_iframes"].append(iframe.get("src", "unknown"))

    # --- External scripts ---
    for script in soup.find_all("script", src=True):
        src = script["src"]
        if src.startswith("http") or src.startswith("//"):
            signals["external_scripts"].append(src)

    # --- Obfuscated JS ---
    obfus_patterns = re.compile(
        r"\b(eval|atob|unescape|document\.write|String\.fromCharCode|setTimeout\s*\(\s*['\"]|"
        r"window\[.?\\x|\\u00|fromCharCode)\b", re.IGNORECASE
    )
    for script in soup.find_all("script"):
        text = script.string or ""
        matches = obfus_patterns.findall(text)
        if matches:
            signals["obfuscated_js"].extend(set(matches))

    # --- Login / phishing forms ---
    for form in soup.find_all("form"):
        inputs = form.find_all("input")
        type_set = {inp.get("type", "").lower() for inp in inputs}
        name_set = {(inp.get("name") or "").lower() for inp in inputs}
        if "password" in type_set or "password" in name_set:
            signals["login_forms"] = True
            break

    # --- Suspicious keywords ---
    page_text = soup.get_text(separator=" ").lower()
    keyword_list = [
        "verify your account", "confirm your identity", "urgent",
        "suspended", "unusual activity", "update your payment",
        "reset your password", "login immediately", "click here to verify",
        "your account has been limited", "act now",
    ]
    for kw in keyword_list:
        if kw in page_text:
            signals["suspicious_keywords"].append(kw)

    return signals


def vt_url_lookup(url: str) -> Optional[dict]:
    """
    Look up a URL on VirusTotal and return malicious / suspicious counts.
    Returns None if no API key or on error.
    """
    if not VT_API_KEY:
        return None
    try:
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        api_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
        r = requests.get(api_url, headers=HEADERS, timeout=10)
        if r.status_code != 200:
            return None
        stats = r.json().get("data", {}).get("attributes", {}).get(
            "last_analysis_stats", {}
        )
        return {
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0),
        }
    except Exception:
        return None


def vt_domain_lookup(domain: str) -> Optional[dict]:
    """
    Look up a domain on VirusTotal and return analysis stats.
    """
    if not VT_API_KEY:
        return None
    try:
        api_url = f"https://www.virustotal.com/api/v3/domains/{domain}"
        r = requests.get(api_url, headers=HEADERS, timeout=10)
        if r.status_code != 200:
            return None
        stats = r.json().get("data", {}).get("attributes", {}).get(
            "last_analysis_stats", {}
        )
        return {
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0),
        }
    except Exception:
        return None


def is_ip_address(hostname: str) -> bool:
    """Return True if *hostname* is an IPv4 or IPv6 literal."""
    try:
        socket.inet_pton(socket.AF_INET, hostname)
        return True
    except OSError:
        pass
    try:
        socket.inet_pton(socket.AF_INET6, hostname.strip("[]"))
        return True
    except OSError:
        return False


def detect_homograph(domain: str) -> Optional[str]:
    """
    Check if the domain looks like a well-known brand with character
    substitutions (e.g. paypa1.com, g00gle.com).
    Returns the matched brand or None.
    """
    # Normalize: strip TLD, replace common leet-speak chars
    extracted = tldextract.extract(domain)
    name = extracted.domain.lower()

    leet_map = str.maketrans("01345", "oleas")
    normalised = name.translate(leet_map)

    for brand in BRAND_KEYWORDS:
        if brand == name:
            continue  # exact match is fine (could be legit subdomain)
        # Check similarity: the normalised name contains the brand
        if brand in normalised and brand != normalised:
            return brand
        # Levenshtein-ish: off by 1-2 chars
        if len(name) == len(brand):
            diffs = sum(1 for a, b in zip(name, brand) if a != b)
            if 1 <= diffs <= 2:
                return brand
    return None

