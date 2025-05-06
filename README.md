# N0aziXss NetRecon 🍓
# NetRecon - Professional Network Reconnaissance Tool

## 🌟 Introduction
**N0aziXss NetRecon**
A powerful yet ethical WHOIS and network reconnaissance tool for security professionals.

## Features
- Comprehensive WHOIS lookups for domains and IPs
- DNS record retrieval (A, MX, TXT, SOA, etc.)
- Reverse IP lookups to find associated domains
- Common port scanning
- Beautiful console output with rich formatting
- Rate limiting to prevent abuse
- Proxy support for anonymity
- JSON output support


# clone the repository
git clone https://github.com/NazaninNazari/NetRecon.git
cd N0aziXss-NetRecon

# install dependencies
pip install -r requirements.txt

# run the scanner
python netrecon.py

# Usage Example:
python netrecon.py -d example.com  # Basic domain lookup
python netrecon.py -d 8.8.8.8     # IP address lookup
python netrecon.py -d example.com --dns A MX TXT  # With DNS records
python netrecon.py -d example.com -o result.json  # Save to JSON
python netrecon.py --ethics       # Show ethical guidelines

# Options
-h, --help            show help message
-d DOMAIN, --domain   target domain or IP
-o OUTPUT, --output   save results to JSON file
--raw                 show raw response
--proxy PROXY         use proxy (http://user:pass@host:port)
--dns [RECORDS...]    get DNS records (A, MX, TXT, etc.)
--ethics              show ethical guidelines

# Sample Output
## Domain Lookup
🍓Professional NetRecon Tool - Secure & Ethical🍓
<!-- 
╭──────────────────────── WHOIS Results ────────────────────────╮
│ Field           Value                                         │
│ Domain Name     example.com                                   │
│ Registrar       NameCheap, Inc.                               │
│ Creation Date   1995-08-14T04:00:00Z                          │
│ Update          2022-07-31T07:34:38Z                          │
│ Expiry Date     2023-08-13T04:00:00Z                          │
│ Organization    Example Inc.                                  │
│ City            Los Angeles                                   │
│ Country         US                                            │
│ Email           admin@example.com                             │
│ Phone           +1.5551234567                                 │
│ Name Servers    ns1.example.com                               │
│                 ns2.example.com                               │
│ Status          clientTransferProhibited                      │
╰───────────────────────────────────────────────────────────────╯ -->

<!-- 
╭──────────────────────── DNS Records ──────────────────────────╮
│ Record Type   Value                                           │
│ A            93.184.216.34                                    │
│ MX           10 mail.example.com                              │
│ TXT          "v=spf1 include:_spf.example.com ~all"           │
│ TXT          "google-site-verification=ABC123"                │
╰───────────────────────────────────────────────────────────────╯ -->

## IP Lookup
<!-- ╭────────────────── IP Information for 8.8.8.8 ──────────────────╮
│ Field               Value                                      │
│ IP Address         8.8.8.8                                     │
│ PTR Record         dns.google                                  │
│ Network Name       GOOGLE                                      │
│ Organization       Google LLC                                  │
│ Country            US                                          │
│ Description        Google Public DNS                           │
│ AS Number          AS15169                                     │
│ Last Updated       2023-05-01T00:00:00Z                        │
│ Domain Count       150                                         │
│ Sample Domains     google.com                                  │
│                    mail.google.com                             │
│                    docs.google.com                             │
│                    drive.google.com                            │
│                    calendar.google.com                         │
│ Open Ports         53, 80, 443                                 │
╰────────────────────────────────────────────────────────────────╯ -->

## JSON Format
<!-- {
  "Domain Name": "example.com",
  "Registrar": "NameCheap, Inc.",
  "Creation Date": "1995-08-14T04:00:00Z",
  "Update": "2022-07-31T07:34:38Z",
  "Expiry Date": "2023-08-13T04:00:00Z",
  "Organization": "Example Inc.",
  "City": "Los Angeles",
  "Country": "US",
  "Email": "admin@example.com",
  "Phone": "+1.5551234567",
  "Name Servers": [
    "ns1.example.com",
    "ns2.example.com"
  ],
  "Status": "clientTransferProhibited",
  "DNS Records": {
    "A": ["93.184.216.34"],
    "MX": ["10 mail.example.com"],
    "TXT": [
      "\"v=spf1 include:_spf.example.com ~all\"",
      "\"google-site-verification=ABC123\""
    ]
  }
} -->

## Ethics
<!-- [ Ethical Guidelines ]
1. Use this tool ONLY for authorized security assessments.
2. Never scan domains/IPs without explicit permission.
3. Respect data privacy laws (GDPR, HIPAA).
4. Do not use for malicious purposes.
5. Limit query rates to avoid overloading servers.
6. Always comply with local and international laws. -->