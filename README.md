# cybersafe-url-checker


🛡️ CyberSafe+ URL Checker

CyberSafe+ URL Checker is a web-based security application designed to analyze and detect potentially malicious or phishing URLs in real time. It validates website safety using multiple checks like SSL certificate verification, domain age analysis, blacklist scanning, and geolocation details.

🚀 Features

✅ Real-Time URL Safety Check – Instantly analyze URLs for phishing or malicious content.

🔒 SSL Certificate Validation – Verifies the website’s SSL security status.

🕒 Domain Age Verification – Detects newly created domains often used in scams.

🧾 Blacklist Comparison – Matches URLs against stored and known blacklists using SQLite.

🌍 IP Geolocation Lookup – Provides geographic location of the server hosting the site.

📊 Detailed Safety Reports – Displays clear, interactive safety summaries through React.js UI.

🧩 Tech Stack
Component	Technology
Frontend	React.js
Backend	Python Flask
Database	SQLite
APIs Used	SSL Validation API, WHOIS/Domain Age API, IP Geolocation API