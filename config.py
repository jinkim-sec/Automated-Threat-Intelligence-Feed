# config.py
# API key configuration for threat intelligence sources

import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# API Keys
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")
OTX_API_KEY = os.getenv("OTX_API_KEY")

# API Endpoints
ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"
OTX_URL = "https://otx.alienvault.com/api/v1/indicators"

# Threshold - IPs with abuse score above this are flagged as malicious
ABUSE_SCORE_THRESHOLD = 50
