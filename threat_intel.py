# threat_intel.py
# Automated Threat Intelligence Feed
# Queries AbuseIPDB and AlienVault OTX to identify malicious indicators

import requests
import csv
from datetime import datetime
from config import (
    ABUSEIPDB_API_KEY,
    OTX_API_KEY,
    ABUSEIPDB_URL,
    OTX_URL,
    ABUSE_SCORE_THRESHOLD
)


# ─────────────────────────────────────────
# AbuseIPDB - Check IP reputation
# ─────────────────────────────────────────

def check_ip_abuseipdb(ip):
    """
    Query AbuseIPDB API to check if an IP is malicious.
    Returns a dict containing ip, abuse score, verdict, and metadata.
    """
    headers = {
        "Key": ABUSEIPDB_API_KEY,
        "Accept": "application/json"
    }
    params = {
        "ipAddress": ip,
        "maxAgeInDays": 90  # Only consider reports from the last 90 days
    }

    try:
        response = requests.get(
            ABUSEIPDB_URL,
            headers=headers,
            params=params,
            timeout=10
        )
        data = response.json()["data"]

        score = data["abuseConfidenceScore"]

        # Flag as malicious if score exceeds defined threshold
        verdict = "MALICIOUS" if score >= ABUSE_SCORE_THRESHOLD else "CLEAN"

        return {
            "indicator": ip,
            "type": "IP",
            "source": "AbuseIPDB",
            "score": score,
            "verdict": verdict,
            "country": data.get("countryCode", "N/A"),
            "isp": data.get("isp", "N/A"),
            "last_reported": data.get("lastReportedAt", "N/A"),
            "checked_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }

    except Exception as e:
        print(f"[ERROR] AbuseIPDB check failed for {ip}: {e}")
        return None


# ─────────────────────────────────────────
# AlienVault OTX - Check IP, domain, or file hash
# ─────────────────────────────────────────

def check_indicator_otx(indicator, indicator_type):
    """
    Query AlienVault OTX API to check an indicator of compromise (IoC).
    Supports indicator types: IPv4, domain, file (hash).
    Returns a dict containing indicator details and verdict.
    """
    headers = {
        "X-OTX-API-KEY": OTX_API_KEY
    }

    # Build endpoint URL based on indicator type
    url = f"{OTX_URL}/{indicator_type}/{indicator}/general"

    try:
        response = requests.get(url, headers=headers, timeout=10)

        if response.status_code == 200:
            data = response.json()

            # Pulse count indicates how many threat reports reference this indicator
            pulse_count = data.get("pulse_info", {}).get("count", 0)

            # Flag as malicious if referenced in any threat pulse
            verdict = "MALICIOUS" if pulse_count > 0 else "CLEAN"

            return {
                "indicator": indicator,
                "type": indicator_type,
                "source": "AlienVault OTX",
                "pulse_count": pulse_count,
                "verdict": verdict,
                "score": pulse_count,
                "country": data.get("country_name", "N/A"),
                "isp": "N/A",
                "last_reported": "N/A",
                "checked_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }
        else:
            print(f"[ERROR] OTX returned status {response.status_code} for {indicator}")
            return None

    except Exception as e:
        print(f"[ERROR] OTX check failed for {indicator}: {e}")
        return None


# ─────────────────────────────────────────
# Save results to CSV report
# ─────────────────────────────────────────

def save_to_csv(results, filename=None):
    """
    Export threat intelligence results to a timestamped CSV file.
    If no filename is provided, one is auto-generated with current timestamp.
    """
    if not results:
        print("[WARNING] No results to save.")
        return

    # Auto-generate filename if not provided
    if not filename:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"threat_intel_report_{timestamp}.csv"

    fieldnames = [
        "indicator", "type", "source", "score",
        "verdict", "country", "isp",
        "last_reported", "checked_at"
    ]

    with open(filename, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for result in results:
            if result:
                # Remove pulse_count as it is not in the CSV schema
                result.pop("pulse_count", None)
                writer.writerow(result)

    print(f"\n[✓] Report saved: {filename}")


# ─────────────────────────────────────────
# Print results to terminal
# ─────────────────────────────────────────

def print_results(results):
    """
    Display threat intelligence results in a formatted terminal output.
    Includes a summary count of malicious vs clean indicators.
    """
    print("\n" + "="*60)
    print("       THREAT INTELLIGENCE REPORT")
    print("="*60)

    # Separate results by verdict for summary
    malicious = [r for r in results if r and r["verdict"] == "MALICIOUS"]
    clean = [r for r in results if r and r["verdict"] == "CLEAN"]

    for result in results:
        if not result:
            continue

        status = "🔴 MALICIOUS" if result["verdict"] == "MALICIOUS" else "🟢 CLEAN"
        print(f"\n[{status}]")
        print(f"  Indicator : {result['indicator']}")
        print(f"  Type      : {result['type']}")
        print(f"  Source    : {result['source']}")
        print(f"  Score     : {result['score']}")
        print(f"  Country   : {result['country']}")
        print(f"  Checked   : {result['checked_at']}")

    # Print summary
    print("\n" + "="*60)
    print(f"  SUMMARY: {len(malicious)} MALICIOUS / {len(clean)} CLEAN")
    print("="*60 + "\n")


# ─────────────────────────────────────────
# Main execution function
# ─────────────────────────────────────────

def run_threat_intel(targets):
    """
    Main function to run threat intelligence checks on a list of indicators.
    Each target should be a dict with 'indicator' and 'type' keys.
    Supported types: IPv4, domain, hash
    """
    print(f"\n[*] Starting Threat Intelligence Feed...")
    print(f"[*] Checking {len(targets)} indicator(s)...\n")

    results = []

    for target in targets:
        indicator = target["indicator"]
        itype = target["type"]

        print(f"[*] Checking: {indicator} ({itype})")

        if itype == "IPv4":
            # Query both sources for IP indicators
            result_abuse = check_ip_abuseipdb(indicator)
            result_otx = check_indicator_otx(indicator, "IPv4")
            if result_abuse:
                results.append(result_abuse)
            if result_otx:
                results.append(result_otx)

        elif itype == "domain":
            # Query OTX only for domain indicators
            result_otx = check_indicator_otx(indicator, "domain")
            if result_otx:
                results.append(result_otx)

        elif itype == "hash":
            # Query OTX only for file hash indicators
            result_otx = check_indicator_otx(indicator, "file")
            if result_otx:
                results.append(result_otx)

    print_results(results)
    save_to_csv(results)
    return results


# ─────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────

if __name__ == "__main__":
    # Define indicators to analyse
    # Add your own IPs, domains, or file hashes here
    targets = [
        {"indicator": "185.220.101.1", "type": "IPv4"},      # Known Tor exit node
        {"indicator": "8.8.8.8", "type": "IPv4"},             # Google DNS (expected clean)
        {"indicator": "malware.wicar.org", "type": "domain"}, # Test malicious domain
    ]

    run_threat_intel(targets)
```

---

## requirements.txt
```
requests==2.31.0
python-dotenv==1.0.0
