from urllib.parse import urlparse
from email.utils import parseaddr
import difflib
import html
import re
import json
import os
import urllib.request


# --- Configuration ---

TRUSTED_BRANDS = {
    "paypal": ["paypal.com"],
    "google": ["google.com"],
    "microsoft": ["microsoft.com", "outlook.com"],
    "apple": ["apple.com"],
    "netflix": ["netflix.com"]
}


# --- Limits: clamp oversized input instead of rejecting it ---

MAX_NAME_LEN = 200
MAX_EMAIL_LEN = 320
MAX_SUBJECT_LEN = 500
MAX_BODY_LEN = 10000
MAX_FILENAME_LEN = 255
MAX_URL_LEN = 2048
MAX_AUTH_RESULTS_LEN = 1000
MAX_LINKS = 100
MAX_ATTACHMENTS = 50


# --- Helper Functions ---

def clamp(text, limit: int) -> str:
    """Trim untrusted text to a safe length. Never raises on bad input."""
    if not isinstance(text, str):
        return ""
    return text[:limit]


def safe_escape(text: str) -> str:
    """Escape untrusted email-originated values before placing them in reason strings."""
    return html.escape(clamp(text, MAX_BODY_LEN), quote=True)


def get_email_domain(email_address: str) -> str:
    """Extracts the domain from a full email address."""
    email_address = clamp(email_address, MAX_EMAIL_LEN)

    _, address = parseaddr(email_address)
    addr_to_use = address if address else email_address

    if "@" in addr_to_use:
        return addr_to_use.split("@")[-1].lower().strip()

    return addr_to_use.lower().strip()


def get_url_domain(url: str) -> str:
    """Extracts the domain from a URL, handling missing schemes."""
    url = clamp(url, MAX_URL_LEN)

    try:
        if not url.startswith(("http://", "https://")):
            url = "https://" + url

        parsed_url = urlparse(url)
        domain = parsed_url.netloc.lower()

        if domain.startswith("www."):
            domain = domain[4:]

        return domain

    except Exception:
        return ""


def is_official_brand_domain(brand_key: str, domain: str) -> bool:
    """Verifies if a domain is exactly the official domain or a valid subdomain."""
    domain = clamp(domain, MAX_EMAIL_LEN).lower().strip()
    official_domains = TRUSTED_BRANDS.get(brand_key, [])

    for official in official_domains:
        if domain == official or domain.endswith("." + official):
            return True

    return False


def has_shortened_link(links) -> bool:
    """Detects shortened link domains."""
    shortened_domains = {"bit.ly", "tinyurl.com", "t.co", "goo.gl"}

    for link in links:
        if get_url_domain(link) in shortened_domains:
            return True

    return False


def check_safe_browsing(links) -> bool:
    """Checks links against Google Safe Browsing API. Returns True if any link is flagged."""
    if not links:
        return False

    api_key = os.environ.get("SAFE_BROWSING_API_KEY")
    if not api_key:
        return False

    url = "https://safebrowsing.googleapis.com/v4/threatMatches:find?key=" + api_key

    payload = {
        "client": {
            "clientId": "gmail-addon-scorer",
            "clientVersion": "1.0"
        },
        "threatInfo": {
            "threatTypes": [
                "MALWARE",
                "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE"
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": link} for link in links]
        }
    }

    try:
        request = urllib.request.Request(
            url,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST"
        )

        with urllib.request.urlopen(request, timeout=2.0) as response:
            result = json.loads(response.read().decode("utf-8"))
            return "matches" in result

    except Exception:
        # Fail open: if Safe Browsing is unavailable, continue with the local rules.
        return False



def parse_auth_results(auth_header: str) -> dict:
    """Extract SPF, DKIM, DMARC results from Authentication-Results header."""
    auth_header = clamp(auth_header, MAX_AUTH_RESULTS_LEN)

    results = {
        "spf": "unknown",
        "dkim": "unknown",
        "dmarc": "unknown"
    }

    if not auth_header:
        return results

    auth_lower = auth_header.lower()

    if "spf=pass" in auth_lower:
        results["spf"] = "pass"
    elif "spf=fail" in auth_lower:
        results["spf"] = "fail"
    elif "spf=none" in auth_lower:
        results["spf"] = "none"

    if "dkim=pass" in auth_lower:
        results["dkim"] = "pass"
    elif "dkim=fail" in auth_lower:
        results["dkim"] = "fail"
    elif "dkim=none" in auth_lower:
        results["dkim"] = "none"

    if "dmarc=pass" in auth_lower:
        results["dmarc"] = "pass"
    elif "dmarc=fail" in auth_lower:
        results["dmarc"] = "fail"
    elif "dmarc=none" in auth_lower:
        results["dmarc"] = "none"

    return results


def normalize_links(raw_links):
    """Safely normalize links from the input payload."""
    if not isinstance(raw_links, list):
        return []

    links = []

    for item in raw_links[:MAX_LINKS]:
        if isinstance(item, str):
            links.append(clamp(item, MAX_URL_LEN))
        elif isinstance(item, dict):
            link = item.get("href") or item.get("url") or item.get("link") or ""
            links.append(clamp(link, MAX_URL_LEN))

    return [link for link in links if link]


def normalize_filenames(raw_attachments):
    """Safely normalize attachment filenames from the input payload."""
    if not isinstance(raw_attachments, list):
        return []

    filenames = []

    for item in raw_attachments[:MAX_ATTACHMENTS]:
        if isinstance(item, str):
            filenames.append(clamp(item, MAX_FILENAME_LEN))
        elif isinstance(item, dict):
            filename = item.get("filename") or item.get("name") or ""
            filenames.append(clamp(filename, MAX_FILENAME_LEN))

    return [filename for filename in filenames if filename]


def is_lookalike_domain(sender_domain: str, official_domain: str) -> bool:
    """Detects simple typosquatting / lookalike sender domains."""
    sender_domain = clamp(sender_domain, MAX_EMAIL_LEN)
    official_domain = clamp(official_domain, MAX_EMAIL_LEN)

    if not sender_domain or not official_domain:
        return False

    similarity = difflib.SequenceMatcher(None, sender_domain, official_domain).ratio()
    return 0.80 <= similarity < 1.0


# --- Main Scoring Function ---

def analyze_email(input_data: dict) -> dict:
    """
    Main scorer entry point.
    Takes a plain dict and returns:
    score, verdict, color, reasons, recommendation.
    """

    if not isinstance(input_data, dict):
        input_data = {}

    # Safe input reading: every field uses .get() with defaults.
    sender_name = clamp(input_data.get("sender_name", ""), MAX_NAME_LEN)
    sender_email = clamp(input_data.get("sender_email", ""), MAX_EMAIL_LEN)
    reply_to = clamp(input_data.get("reply_to", "") or "", MAX_EMAIL_LEN)
    subject = clamp(input_data.get("subject", ""), MAX_SUBJECT_LEN)
    body = clamp(input_data.get("body", ""), MAX_BODY_LEN)
    auth_results = clamp(input_data.get("auth_results", ""), MAX_AUTH_RESULTS_LEN)

    links = normalize_links(input_data.get("links", []))
    filenames = normalize_filenames(input_data.get("attachments", []))

    # Parse sender authentication results.
    auth = parse_auth_results(auth_results)

    score = 0
    reasons = []

    # 1. Sender Authentication: SPF, DKIM, DMARC
    if auth.get("spf") == "fail":
        score += 30
        reasons.append("SPF authentication failed")
    elif auth.get("spf") == "none":
        score += 5
        reasons.append("SPF not configured for sender domain")

    if auth.get("dkim") == "fail":
        score += 30
        reasons.append("DKIM signature verification failed")
    elif auth.get("dkim") == "none":
        score += 5
        reasons.append("DKIM not configured for sender domain")

    if auth.get("dmarc") == "fail":
        score += 30
        reasons.append("DMARC policy failed")

   # 2. Social Engineering / Urgent Language
    has_urgent = input_data.get("has_urgent_language", False)

    if has_urgent:
     score += 15
     reasons.append("Contains social engineering / urgent language")

    # 3. Shortened Links
    if has_shortened_link(links):
        score += 25
        reasons.append("Contains a shortened URL designed to hide the real destination")

    # External URL reputation signal: Google Safe Browsing
    if check_safe_browsing(links):
        score += 100
        reasons.append("One or more links were flagged as potentially unsafe by Google Safe Browsing")    

    # 4. Risky Attachments
    risky_extensions = [".exe", ".bat", ".scr", ".js", ".vbs", ".zip"]

    if any(filename.lower().endswith(ext) for filename in filenames for ext in risky_extensions):
        score += 25
        reasons.append("Contains a risky or executable attachment type")

    sender_domain_raw = get_email_domain(sender_email)
    sender_domain_safe = safe_escape(sender_domain_raw)
    sender_name_lower = sender_name.lower()

    # 5. Sender-name impersonation
    # 6. Typosquatting / lookalike sender domains
    # 7. Brand spoofing in link URL
    for brand, official_domains in TRUSTED_BRANDS.items():

        # Sender-name impersonation
        if re.search(r'\b' + re.escape(brand) + r'\b', sender_name_lower) and not is_official_brand_domain(brand, sender_domain_raw):
            score += 25
            reasons.append(
                f"Sender name mimics '{brand.capitalize()}', but email domain is unofficial"
            )

        # Typosquatting / lookalike sender domains
        for official in official_domains:
            if is_lookalike_domain(sender_domain_raw, official):
                score += 20
                reasons.append(
                    f"Sender domain ({sender_domain_safe}) is a lookalike (typosquat) of {official}"
                )
                break

        # Brand spoofing in the URL itself.
        # Important: this does NOT compare visible link text vs actual href.
        for link in links:
            url_domain_raw = get_url_domain(link)
            url_domain_safe = safe_escape(url_domain_raw)

            if re.search(r'\b' + re.escape(brand) + r'\b', link.lower()) and url_domain_raw and not is_official_brand_domain(brand, url_domain_raw):
                score += 25
                reasons.append(
                    f"Contains a link mimicking '{brand.capitalize()}' (URL Spoofing)"
                )
                break

    # 8. Reply-To mismatch
    if reply_to:
        reply_domain_raw = get_email_domain(reply_to)
        reply_domain_safe = safe_escape(reply_domain_raw)

        if sender_domain_raw != reply_domain_raw:
            score += 20
            reasons.append(
                "Reply-To domain differs from the Sender domain (potential spoofing)"
            )

    # Ensure reasons is never empty.
    if not reasons:
        reasons.append("No strong phishing indicators were detected")

    # Order-preserving deduplication.
    unique_reasons = list(dict.fromkeys(reasons))

    # Final calculation and verdict.
    final_score = min(score, 100)

    if final_score <= 30:
        verdict = "Low Risk"
        color = "#2E7D32"
        recommendation = (
            "No strong phishing indicators were detected"
            if final_score == 0
            else "This email looks safe to read."
        )
    elif final_score <= 65:
        verdict = "Suspicious"
        color = "#EF6C00"
        recommendation = "Exercise caution. Do not click links or download files unless verified."
    else:
        verdict = "High Risk"
        color = "#C62828"
        recommendation = "Warning! This email has multiple severe red flags. Do not interact with its content."

    return {
        "score": final_score,
        "verdict": verdict,
        "color": color,
        "reasons": unique_reasons,
        "recommendation": recommendation
    }