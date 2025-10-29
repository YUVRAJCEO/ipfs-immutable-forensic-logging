"""
generate_ical_dataset.py
------------------------------------
Generates the synthetic Immutable Cyber Alert Log Dataset (ICAL-Set v1.0).
Each record simulates a honeypot-style intrusion alert, serialized to JSON,
hashed using SHA-256, and assigned a pseudo IPFS Content Identifier (CID).

Author: Yuvraj Yadav
Mentor: Ms. Namrata Marium Chacko
Institution: Manipal Institute of Technology, MAHE
License: CC BY 4.0
Version: 1.0
"""

import json
import hashlib
import random
import datetime
import os
from tqdm import tqdm

# =========================================================
# Configuration
# =========================================================
OUTPUT_FILE = "ical_dataset.jsonl"
NUM_RECORDS = 1000
SEED = 42
random.seed(SEED)

# =========================================================
# Data Pools
# =========================================================
PROTOCOLS = ["TCP", "UDP", "ICMP", "HTTP", "HTTPS"]
EVENT_TYPES = [
    "SSH Brute Force",
    "SQL Injection",
    "DDoS SYN Flood",
    "FTP Login Attempt",
    "Port Scanning",
    "Ransomware Beacon",
    "Cross-Site Scripting",
    "Malware Download"
]
COUNTRIES = [
    "United States", "India", "Germany", "Australia", "Brazil",
    "Singapore", "France", "Canada", "Japan", "United Kingdom"
]

# =========================================================
# Utility Functions
# =========================================================
def generate_ip():
    """Generate a random IPv4 address."""
    return ".".join(str(random.randint(1, 254)) for _ in range(4))

def generate_timestamp():
    """Generate ISO 8601 UTC timestamp within the last year."""
    base_date = datetime.datetime(2024, 1, 1)
    delta_days = random.randint(0, 600)
    delta_seconds = random.randint(0, 86400)
    dt = base_date + datetime.timedelta(days=delta_days, seconds=delta_seconds)
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")

def deterministic_hash(data: dict) -> str:
    """Generate SHA-256 hash for a serialized JSON record."""
    json_str = json.dumps(data, sort_keys=True)
    return hashlib.sha256(json_str.encode("utf-8")).hexdigest()

def generate_cid(hash_value: str) -> str:
    """Generate pseudo IPFS CID from hash (for simulation)."""
    return f"Qm{hash_value[:44]}"

# =========================================================
# Record Generator
# =========================================================
def generate_record():
    """Generate a single synthetic alert record."""
    record = {
        "timestamp": generate_timestamp(),
        "src_ip": generate_ip(),
        "dst_ip": generate_ip(),
        "src_port": random.randint(1024, 65535),
        "dst_port": random.randint(20, 9999),
        "protocol": random.choice(PROTOCOLS),
        "event_type": random.choice(EVENT_TYPES),
        "severity": random.randint(1, 10),
        "country_src": random.choice(COUNTRIES),
        "country_dst": random.choice(COUNTRIES),
    }

    # Compute hash and CID
    sha256_hash = deterministic_hash(record)
    record["sha256_hash"] = sha256_hash
    record["ipfs_cid"] = generate_cid(sha256_hash)

    return record

# =========================================================
# Main Generator
# =========================================================
def main():
    """Main dataset generation function."""
    print("\n📘 Generating Immutable Cyber Alert Log Dataset (ICAL-Set v1.0)...")
    print(f"Target File: {OUTPUT_FILE}")
    records = []

    with open(OUTPUT_FILE, "w") as outfile:
        for _ in tqdm(range(NUM_RECORDS), desc="Generating alerts", ncols=80):
            record = generate_record()
            json.dump(record, outfile)
            outfile.write("\n")
            records.append(record)

    print(f"\n✅ Dataset successfully generated: {OUTPUT_FILE}")
    print(f"📦 Total Records: {len(records)}")
    print(f"🔒 Example Record:\n{json.dumps(records[0], indent=2)}")

# =========================================================
# Entry Point
# =========================================================
if __name__ == "__main__":
    main()
