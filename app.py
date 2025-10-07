
from flask import Flask, request, jsonify
import sqlite3
import requests
from flask_cors import CORS
from urllib.parse import urlparse
from datetime import datetime
import ssl
import socket
import OpenSSL
import re
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
import joblib
import os

app = Flask(__name__)
CORS(app)

# 🔥 Hardcoded API Keys (For testing; replace with env variables for production)
SAFE_BROWSING_API_KEY = ""
WHOIS_API_KEY = ""
VIRUSTOTAL_API_KEY = ""
IP_GEOLOCATION_API_KEY = ""

# Function to connect to SQLite database
def get_db_connection():
    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row
    return conn

# Function to extract relevant WHOIS data
def extract_whois_data(whois_data):
    if "error" in whois_data:
        return "WHOIS data unavailable"
    
    return {
        "domainName": whois_data.get("domainName", "Unknown"),
        "createdDate": whois_data.get("createdDate", "Unknown"),
        "registrarName": whois_data.get("registrarName", "Unknown")
    }

# Function to extract relevant VirusTotal data
def extract_virustotal_data(virus_total_report):
    if "error" in virus_total_report:
        return "VirusTotal data unavailable"

    attributes = virus_total_report.get("data", {}).get("attributes", {})
    analysis_stats = attributes.get("last_analysis_stats", {})

    return {
        "malicious": analysis_stats.get("malicious", 0),
        "suspicious": analysis_stats.get("suspicious", 0),
        "harmless": analysis_stats.get("harmless", 0),
        "undetected": analysis_stats.get("undetected", 0)
    }

# Function to extract relevant IP Geolocation data
def extract_ip_geolocation_data(ip_geo_location):
    if "error" in ip_geo_location:
        return "IP Geolocation data unavailable"

    return {
        "country": ip_geo_location.get("country_name", "Unknown"),
        "isp": ip_geo_location.get("isp", "Unknown"),
        "organization": ip_geo_location.get("organization", "Unknown")
    }

# WHOIS API Function
def fetch_whois_data(domain):
    url = f"https://www.whoisxmlapi.com/whoisserver/WhoisService?apiKey={WHOIS_API_KEY}&domainName={domain}&outputFormat=JSON"
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        return response.json()
    except requests.RequestException as e:
        return {"error": f"WHOIS API Error: {e}"}

# VirusTotal API Function
def fetch_virus_total_report(domain):
    url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    try:
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()
        return response.json()
    except requests.RequestException as e:
        return {"error": f"VirusTotal API Error: {e}"}

# IP Geolocation API Function
def fetch_ip_geo_location(domain):
    url = f"https://api.ipgeolocation.io/ipgeo?apiKey={IP_GEOLOCATION_API_KEY}&domain={domain}"
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        return response.json()
    except requests.RequestException as e:
        return {"error": f"IP Geolocation API Error: {e}"}

def check_ssl_certificate(url):
    try:
        # Parse URL to get hostname
        parsed_url = urlparse(url)
        hostname = parsed_url.netloc
        
        # Create SSL context
        context = ssl.create_default_context()
        
        # Connect to the server
        with socket.create_connection((hostname, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                # Get certificate
                cert = ssock.getpeercert()
                cert_openssl = OpenSSL.crypto.load_certificate(
                    OpenSSL.crypto.FILETYPE_ASN1,
                    ssock.getpeercert(binary_form=True)
                )
                
                # Extract certificate details
                issuer = dict(x[0] for x in cert['issuer'])
                subject = dict(x[0] for x in cert['subject'])
                not_before = datetime.strptime(cert['notBefore'], '%b %d %H:%M:%S %Y %Z')
                not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                
                # Check if certificate is valid
                is_valid = datetime.now() > not_before and datetime.now() < not_after
                
                return {
                    "is_valid": is_valid,
                    "issuer": issuer.get('organizationName', 'Unknown'),
                    "subject": subject.get('commonName', 'Unknown'),
                    "valid_from": not_before.strftime('%Y-%m-%d'),
                    "valid_until": not_after.strftime('%Y-%m-%d'),
                    "days_until_expiry": (not_after - datetime.now()).days,
                    "protocol": ssock.version(),
                    "cipher": ssock.cipher()[0]
                }
    except Exception as e:
        return {
            "error": str(e),
            "is_valid": False
        }

def extract_url_features(url):
    """Extract features from URL for ML classification"""
    features = {
        'length': len(url),
        'num_dots': url.count('.'),
        'num_hyphens': url.count('-'),
        'num_underscore': url.count('_'),
        'num_slash': url.count('/'),
        'num_question': url.count('?'),
        'num_equal': url.count('='),
        'num_at': url.count('@'),
        'num_and': url.count('&'),
        'num_exclamation': url.count('!'),
        'num_space': url.count(' '),
        'num_tilde': url.count('~'),
        'num_comma': url.count(','),
        'num_plus': url.count('+'),
        'num_asterisk': url.count('*'),
        'num_hash': url.count('#'),
        'num_dollar': url.count('$'),
        'num_percent': url.count('%'),
        'has_https': 1 if url.startswith('https://') else 0,
        'has_http': 1 if url.startswith('http://') else 0,
        'has_www': 1 if 'www.' in url else 0,
        'has_ip': 1 if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', urlparse(url).netloc) else 0
    }
    return list(features.values())

def load_or_train_model():
    """Load or train the ML model"""
    model_path = 'url_classifier.joblib'
    if os.path.exists(model_path):
        return joblib.load(model_path)
    
    # Sample training data (in production, use a larger dataset)
    X_train = [
        'https://www.google.com',
        'https://www.facebook.com',
        'https://www.amazon.com',
        'http://malicious-site.com',
        'http://phishing-attempt.com',
        'https://www.microsoft.com',
        'https://www.apple.com',
        'http://scam-website.com'
    ]
    y_train = [0, 0, 0, 1, 1, 0, 0, 1]  # 0: safe, 1: malicious
    
    # Extract features
    X_features = [extract_url_features(url) for url in X_train]
    
    # Train model
    model = RandomForestClassifier(n_estimators=100, random_state=42)
    model.fit(X_features, y_train)
    
    # Save model
    joblib.dump(model, model_path)
    return model

def predict_url_safety(url):
    """Predict if URL is safe or malicious"""
    try:
        model = load_or_train_model()
        features = extract_url_features(url)
        prediction = model.predict([features])[0]
        probability = model.predict_proba([features])[0]
        
        return {
            "is_malicious": bool(prediction),
            "confidence": float(probability[1]),
            "features_used": len(features)
        }
    except Exception as e:
        return {
            "error": str(e),
            "is_malicious": None,
            "confidence": None
        }

# /check-url Endpoint (Enhanced Scoring System)
@app.route('/check-url', methods=['POST'])
def check_url():
    data = request.json
    url = data.get('url')

    if not url:
        return jsonify({"error": "No URL provided"}), 400

    parsed_url = urlparse(url)
    domain = parsed_url.netloc or parsed_url.path

    # Initialize score
    safety_score = 100

    # Fetch & Extract API Data
    whois_data = extract_whois_data(fetch_whois_data(domain))
    virus_total_report = extract_virustotal_data(fetch_virus_total_report(domain))
    ip_geo_location = extract_ip_geolocation_data(fetch_ip_geo_location(domain))
    ssl_info = check_ssl_certificate(url)
    ml_prediction = predict_url_safety(url)

    # ML Prediction Analysis
    if ml_prediction.get("is_malicious", False):
        safety_score -= 40
        threat_details = f"⚠️ ML model predicts malicious URL (confidence: {ml_prediction['confidence']:.2%})"
    else:
        threat_details = f"✅ ML model predicts safe URL (confidence: {ml_prediction['confidence']:.2%})"

    # SSL Certificate Analysis
    if not ssl_info.get("is_valid", False):
        safety_score -= 30
        threat_details += " ⚠️ Invalid or expired SSL certificate."
    elif ssl_info.get("days_until_expiry", 0) < 30:
        safety_score -= 15
        threat_details += " ⚠️ SSL certificate expiring soon."
    else:
        threat_details += " ✅ Valid SSL certificate."

    # Google Safe Browsing API Request
    payload = {
        "client": {"clientId": "CyberSafe", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }

    response = requests.post(f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={SAFE_BROWSING_API_KEY}", json=payload)
    result = response.json()

    # Google Safe Browsing Threat Analysis
    if "matches" in result:
        safety_score -= 50
        threat_details += " ⚠️ Malicious URL detected!"
    else:
        threat_details += " ✅ No threats found."

    # VirusTotal Analysis
    if virus_total_report["malicious"] > 0:
        safety_score -= 50
        threat_details += " 🚨 VirusTotal flagged this URL."

    # WHOIS Analysis (Newly registered domains are riskier)
    if whois_data["createdDate"] != "Unknown":
        try:
            creation_date = datetime.strptime(whois_data["createdDate"], "%Y-%m-%dT%H:%M:%S")
            if (datetime.now() - creation_date).days < 365:
                safety_score -= 30
                threat_details += " ⚠️ Domain is newly registered."
        except ValueError:
            pass  # Ignore parsing errors

    # IP Geolocation Analysis
    if ip_geo_location["country"] in ["China", "Russia", "North Korea"]:
        safety_score -= 20
        threat_details += " 🚨 IP is linked to suspicious regions."

    # Ensure score is within valid range
    safety_score = max(0, min(safety_score, 100))

    # Save results to database
    conn = get_db_connection()
    conn.execute(
        'INSERT INTO url_checks (url, domain, safety_score, threat_details, whois_info, virustotal_info, ip_geolocation_info, ssl_info, ml_prediction) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
        (url, domain, safety_score, threat_details, str(whois_data), str(virus_total_report), str(ip_geo_location), str(ssl_info), str(ml_prediction))
    )
    conn.commit()
    conn.close()

    return jsonify({
        "message": "URL checked successfully!",
        "safety_score": safety_score,
        "threat_details": threat_details,
        "whois_data": whois_data,
        "virus_total_report": virus_total_report,
        "ip_geolocation": ip_geo_location,
        "ssl_info": ssl_info,
        "ml_prediction": ml_prediction
    }), 201
if __name__ == '__main__':
    app.run(debug=True)

