import re
import joblib
import socket
import whois
import datetime
import requests
import pandas as pd
from urllib.parse import urlparse

# Load the trained model
model = joblib.load("model/phishing_model.pkl")

# List of features in correct order
FEATURE_COLUMNS = [
    'having_IPhaving_IP_Address', 'URLURL_Length', 'Shortining_Service', 'having_At_Symbol',
    'double_slash_redirecting', 'Prefix_Suffix', 'having_Sub_Domain', 'SSLfinal_State',
    'Domain_registeration_length', 'Favicon', 'port', 'HTTPS_token', 'Request_URL',
    'URL_of_Anchor', 'Links_in_tags', 'SFH', 'Submitting_to_email', 'Abnormal_URL',
    'Redirect', 'on_mouseover', 'RightClick', 'popUpWidnow', 'Iframe', 'age_of_domain',
    'DNSRecord', 'web_traffic', 'Page_Rank', 'Google_Index', 'Links_pointing_to_page',
    'Statistical_report'
]

# --- Feature extraction functions ---

def has_ip(url):
    return -1 if re.search(r'((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(\.(?!$)|$)){4}', url) else 1

def url_length(url):
    length = len(url)
    return -1 if length < 54 else (0 if length <= 75 else 1)

def shortening_service(url):
    return -1 if re.search(r"(bit\.ly|goo\.gl|tinyurl\.com|ow\.ly|t\.co|is\.gd)", url) else 1

def having_at_symbol(url):
    return -1 if "@" in url else 1

def double_slash_redirecting(url):
    return -1 if url.rfind("//") > 6 else 1

def prefix_suffix(domain):
    return -1 if "-" in domain else 1

def sub_domain(domain):
    dots = domain.split(".")
    return 1 if len(dots) <= 3 else (0 if len(dots) == 4 else -1)

def ssl_final_state(url):
    return 1 if urlparse(url).scheme == "https" else -1

def domain_registration_length(whois_info):
    try:
        exp = whois_info.expiration_date
        cre = whois_info.creation_date
        if isinstance(exp, list): exp = exp[0]
        if isinstance(cre, list): cre = cre[0]
        if exp and cre:
            age = (exp - cre).days
            return 1 if age >= 365 else -1
    except: pass
    return -1

def favicon():
    return 1  # Placeholder: assumes favicon loads from the same domain

def port():
    return 1  # Assume standard ports only

def https_token(domain):
    return -1 if "https" in domain else 1

def request_url(url, domain):
    try:
        response = requests.get(url, timeout=5)
        external_links = re.findall(r'<img[^>]+src="(http[^"]+)"', response.text)
        total_links = len(external_links)
        external = sum(1 for link in external_links if domain not in link)
        return 1 if total_links == 0 else (-1 if external / total_links >= 0.61 else (0 if 0.31 <= external / total_links < 0.61 else 1))
    except:
        return -1

def url_of_anchor(url, domain):
    try:
        response = requests.get(url, timeout=5)
        anchors = re.findall(r'<a\s+(?:[^>]*?\s+)?href="([^"]*)"', response.text)
        total = len(anchors)
        unsafe = sum(1 for a in anchors if "#" in a or "javascript:" in a or "mailto:" in a or domain not in a)
        return 1 if total == 0 else (-1 if unsafe / total >= 0.67 else (0 if 0.31 <= unsafe / total < 0.67 else 1))
    except:
        return -1

def links_in_tags(url):
    return 1  # Placeholder: assume safe

def sfh(url):
    return -1 if "about:blank" in url else 1

def submitting_to_email(url):
    return -1 if "mailto:" in url else 1

def abnormal_url(domain, whois_info):
    return -1 if whois_info is None or whois_info.domain_name is None else 1

def redirect(url):
    try:
        response = requests.get(url, timeout=5)
        return -1 if len(response.history) > 2 else 1
    except:
        return -1

def on_mouseover(url):
    return 1  # Placeholder

def right_click(url):
    return 1  # Placeholder

def popup_window(url):
    return 1  # Placeholder

def iframe(url):
    return 1  # Placeholder

def age_of_domain(whois_info):
    try:
        cre = whois_info.creation_date
        if isinstance(cre, list): cre = cre[0]
        if cre:
            age = (datetime.datetime.now() - cre).days
            return 1 if age >= 180 else -1
    except: pass
    return -1

def dns_record(domain):
    try:
        socket.gethostbyname(domain)
        return 1
    except:
        return -1

def web_traffic():
    return 1  # Placeholder

def page_rank():
    return 1  # Placeholder

def google_index(url):
    return 1  # Placeholder

def links_pointing():
    return 1  # Placeholder

def statistical_report():
    return 1  # Placeholder

# --- Main URL Feature Extraction ---

def extract_features(url):
    try:
        domain = urlparse(url).netloc
        whois_info = whois.whois(domain)
    except:
        domain = urlparse(url).netloc
        whois_info = None

    features = [
        has_ip(url),
        url_length(url),
        shortening_service(url),
        having_at_symbol(url),
        double_slash_redirecting(url),
        prefix_suffix(domain),
        sub_domain(domain),
        ssl_final_state(url),
        domain_registration_length(whois_info),
        favicon(),
        port(),
        https_token(domain),
        request_url(url, domain),
        url_of_anchor(url, domain),
        links_in_tags(url),
        sfh(url),
        submitting_to_email(url),
        abnormal_url(domain, whois_info),
        redirect(url),
        on_mouseover(url),
        right_click(url),
        popup_window(url),
        iframe(url),
        age_of_domain(whois_info),
        dns_record(domain),
        web_traffic(),
        page_rank(),
        google_index(url),
        links_pointing(),
        statistical_report()
    ]

    return pd.DataFrame([features], columns=FEATURE_COLUMNS)

# --- Prediction Function ---

def predict_url(url):
    X = extract_features(url)
    result = model.predict(X)[0]
    print(f"\n🔎 URL: {url}")
    print("✅ Result: SAFE" if result == 1 else "⚠️ Result: PHISHING")

# --- Test Prompt ---

if __name__ == "__main__":
    test_url = input("Enter URL to check: ")
    predict_url(test_url)
