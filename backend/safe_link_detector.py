import requests, re, validators, tldextract, whois, datetime, socket

# ====== CONFIG ======
GOOGLE_API_KEY = "AIzaSyA7syDyxmLc1sPfTul_6rzZJ26wUbRBF-w"

# ====== GOOGLE SAFE BROWSING ======
def check_google(url):
    try:
        endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GOOGLE_API_KEY}"
        payload = {
            "client": {"clientId": "cti-india", "clientVersion": "1.0"},
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "PHISHING"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}],
            },
        }
        r = requests.post(endpoint, json=payload)
        result = r.json()
        return "Malicious (Google Safe Browsing)" if result.get("matches") else None
    except:
        return None

# ====== PHISHTANK ======
def check_phishtank(url):
    try:
        r = requests.post("https://checkurl.phishtank.com/checkurl/", data={"url": url, "format": "json"})
        data = r.json()
        if data.get("results", {}).get("verified"):
            return "Malicious (PhishTank Verified)"
    except:
        pass
    return None

# ====== URLHAUS ======
def check_urlhaus(url):
    try:
        r = requests.post("https://urlhaus-api.abuse.ch/v1/url/", data={"url": url})
        data = r.json()
        if data.get("query_status") == "ok":
            return "Malicious (URLHaus Malware)"
    except:
        pass
    return None

# ====== WHOIS + DOMAIN AGE ======
def check_domain_info(url):
    try:
        domain = f"{tldextract.extract(url).domain}.{tldextract.extract(url).suffix}"
        info = whois.whois(domain)

        created = info.creation_date
        country = info.country
        registrar = info.registrar

        if isinstance(created, list):
            created = created[0]

        age_days = (datetime.datetime.now() - created).days if created else None

        risk = None
        if age_days and age_days < 90:
            risk = "High Risk (New Domain)"
        return {"age_days": age_days, "country": country, "registrar": registrar, "domain_risk": risk}
    except:
        return {"age_days": None, "country": None, "registrar": None, "domain_risk": None}

# ====== IP GEOLOCATION (FREE) ======
def check_ip_location(url):
    try:
        domain = f"{tldextract.extract(url).domain}.{tldextract.extract(url).suffix}"
        ip = socket.gethostbyname(domain)
        r = requests.get(f"http://ip-api.com/json/{ip}").json()
        return {"ip": ip, "server_country": r.get("country"), "isp": r.get("isp")}
    except:
        return {"ip": None, "server_country": None, "isp": None}

# ====== HEURISTIC DETECTOR ======
SUSPICIOUS_WORDS = ["login", "verify", "update", "secure", "account", "free", "bonus", "wallet", "upi", "kyc"]
SHORTENERS = ["bit.ly", "tinyurl", "t.co", "goo.gl", "cutt.ly", "rb.gy"]

def heuristic(url):
    if len(url) > 75:
        return "Suspicious (Very long URL)"
    if "xn--" in url:
        return "High Risk (Punycode attack)"
    for w in SUSPICIOUS_WORDS:
        if w in url.lower():
            return f"Suspicious (Keyword: {w})"
    domain = f"{tldextract.extract(url).domain}.{tldextract.extract(url).suffix}"
    if domain in SHORTENERS:
        return "Suspicious (Shortened URL)"
    if re.match(r".*\d+\.\d+\.\d+\.\d+.*", url):
        return "High Risk (IP Link)"
    return "Safe"

# ====== MASTER SCAN FUNCTION ======
def scan_url(url):
    if not validators.url(url):
        return {"url": url, "status": "Invalid URL"}

    checks = [
        check_google(url),
        check_phishtank(url),
        check_urlhaus(url),
        heuristic(url)
    ]

    # Decide status (priority)
    for c in checks:
        if c and ("Malicious" in c or "High Risk" in c):
            status = c
            break
    else:
        status = next((c for c in checks if c and "Suspicious" in c), "Safe")

    # Domain + Location info
    domain_info = check_domain_info(url)
    ip_info = check_ip_location(url)

    # If domain is risky and not yet flagged
    if domain_info["domain_risk"] and "Malicious" not in status:
        status = domain_info["domain_risk"]

    # Final output
    return {
        "url": url,
        "status": status,
        "domain_age_days": domain_info["age_days"],
        "domain_country": domain_info["country"],
        "registrar": domain_info["registrar"],
        "server_ip": ip_info["ip"],
        "server_country": ip_info["server_country"],
        "isp": ip_info["isp"]
    }

# ====== TEST ======
if __name__ == "__main__":
    test = "https://www.google.com/"
    print(scan_url(test))