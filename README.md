# Automated Threat Intelligence Feed

A Python tool that queries multiple threat intelligence 
sources to identify and report on malicious IPs, domains, 
and file hashes. Built as part of a cybersecurity learning 
portfolio to demonstrate threat intelligence concepts used 
in real-world SOC environments.

## Features
- Queries AbuseIPDB for IP reputation and abuse confidence score
- Queries AlienVault OTX for IP, domain, and file hash indicators
- Generates a risk verdict (MALICIOUS / CLEAN) for each indicator
- Exports results to a timestamped CSV report
- Supports bulk indicator checking in a single run
- Secure API key management using environment variables

## Requirements
- Python 3.x
- requests
- python-dotenv

Install dependencies:
```bash
pip install -r requirements.txt
```

## Setup

1. Create free accounts at:
   - [AbuseIPDB](https://www.abuseipdb.com)
   - [AlienVault OTX](https://otx.alienvault.com)

2. Generate your API keys from each platform

3. Create a `.env` file in the project root:
```
ABUSEIPDB_API_KEY=your_abuseipdb_key_here
OTX_API_KEY=your_otx_key_here
```

4. Never commit your `.env` file — it is excluded via `.gitignore`

## Usage
```bash
python threat_intel.py
```

Edit the `targets` list in `threat_intel.py` to add 
your own indicators:
```python
targets = [
    {"indicator": "185.220.101.1", "type": "IPv4"},
    {"indicator": "malware.wicar.org", "type": "domain"},
    {"indicator": "abc123...", "type": "hash"},
]
```

Supported indicator types:
- `IPv4` — checked against both AbuseIPDB and AlienVault OTX
- `domain` — checked against AlienVault OTX
- `hash` — checked against AlienVault OTX

## Example Output
```
[*] Starting Threat Intelligence Feed...
[*] Checking 3 indicator(s)...

============================================================
       THREAT INTELLIGENCE REPORT
============================================================

[🔴 MALICIOUS]
  Indicator : 185.220.101.1
  Type      : IPv4
  Source    : AbuseIPDB
  Score     : 100
  Country   : DE
  Checked   : 2025-11-01 14:23:01

[🟢 CLEAN]
  Indicator : 8.8.8.8
  Type      : IPv4
  Source    : AbuseIPDB
  Score     : 0
  Country   : US
  Checked   : 2025-11-01 14:23:02

============================================================
  SUMMARY: 1 MALICIOUS / 2 CLEAN
============================================================

[✓] Report saved: threat_intel_report_20251101_142302.csv
```

## Project Structure
```
threat-intelligence-feed/
│
├── threat_intel.py        # Main script
├── config.py              # API configuration
├── requirements.txt       # Dependencies
├── .env                   # API keys (not tracked by git)
├── .gitignore             # Excludes .env and generated reports
├── README.md
└── sample_data/
    └── sample_output.csv  # Example report output
```

## Key Concepts Demonstrated
- Threat intelligence gathering and aggregation
- REST API integration (AbuseIPDB, AlienVault OTX)
- Indicator of Compromise (IoC) analysis
- Automated report generation
- Secure API key management using environment variables

## Disclaimer
This tool is for educational purposes only.
Only analyse indicators you have permission to investigate.
Do not use against systems or networks without authorisation.

## Author
Jin Hyuck Kim
