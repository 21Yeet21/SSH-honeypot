"""
generate_mock_data.py - Populate the honeypot database with realistic fake attack logs

Cybersecurity concept: Real honeypots collect real-world data, but for portfolio and
demo purposes, realistic mock data is essential to showcase dashboard capabilities.
This script generates attacks that mimic real-world SSH brute-force campaigns:

  - Common usernames: attackers scan for default accounts (root, admin, ubuntu, etc.)
  - Common passwords: automated bots try dictionaries of simple credentials
  - Geographic distribution: most SSH brute-force comes from China, Russia, USA, Brazil
  - Temporal patterns: attacks come in waves, not uniformly spread
  - Random source IPs from common attacker IP ranges

The data is designed to look authentic and produce visually interesting charts.
"""

import sqlite3
import random
import os
from datetime import datetime, timedelta

# Path to the database (same level as this script)
DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "attacks.db")

# ─── Realistic attacker profiles ───────────────────────────────────────
# These reflect actual SSH brute-force campaigns seen in wild honeypot data.

COMMON_USERNAMES = [
    "root",       # The most targeted account — always the first try
    "admin",      # Second most common — generic privileged account
    "ubuntu",     # Default user on Ubuntu-based servers
    "pi",          # Raspberry Pi default user
    "user",        # Generic fallback
    "ftpuser",     # FTP-related service accounts
    "www-data",   # Web server daemon account
    "test",        # Test/dev accounts often left on systems
    "oracle",      # Database server admin
    "postgres",    # PostgreSQL default superuser
    "jenkins",     # CI/CD server admin
    "git",         # GitLab/Git service account
    "deploy",      # Deployment automation accounts
    "tomcat",      # Tomcat application server
    "mysql",       # MySQL database user
]

COMMON_PASSWORDS = [
    "admin",           # Default password matching username
    "123456",          # Most common password globally
    "password",        # Classic weak password
    "root",            # Password == username
    "ubuntu",          # Matches the Ubuntu default user
    "12345678",        # Numeric sequence
    "qwerty",          # Keyboard pattern
    "123456789",       # Another numeric seqence
    "1234567890",      # Full numeric key sequence
    "passw0rd",        # Leet-speak variant of password
    "admin123",        # Username + numbers
    "letmein",         # Classic weak password
    "111111",          # Repeated digit
    "changeme",        # Factory default prompt often used as PW
    "P@ssw0rd",        # Another leet-speak variant
    "default",         # Default default
    "test",            # Test/test combo
    "toor",            # "root" backwards — common in Linux defaults
    "guest",           # Guest account password
    "1q2w3e4r",        # Keyboard walk pattern
]

# Country distribution weights (approximate real-world SSH honeypot data)
COUNTRY_DATA = [
    ("China", 0.35),
    ("Russia", 0.20),
    ("USA", 0.12),
    ("Brazil", 0.08),
    ("India", 0.07),
    ("South Korea", 0.05),
    ("Germany", 0.04),
    ("Japan", 0.03),
    ("Nigeria", 0.02),
    ("Vietnam", 0.02),
    ("Iran", 0.01),
    ("Ukraine", 0.01),
]

WEBSERVER_VERSIONS = [
    "libssh_0.6.3",       # Older OpenSSH server fingerprint
    "libssh_0.8.9",       # Mid-range server
    "OpenSSH_7.4",        # Debian Stretch default
    "OpenSSH_8.2p1",      # Recent Ubuntu Server
    "Dropbear_2022.82",   # Lightweight SSH for embedded/IoT
]


def weighted_choice(population, weights):
    """Pick a random item weighted by the given distribution."""
    return random.choices(population, weights=weights, k=1)[0]


def generate_fake_ip(country=None):
    """
    Generate a realistic-looking fake IP address.

    Cybersecurity note: Real honeypot data includes many different source IPs.
    We simulate this by generating addresses from realistic public ranges.
    """
    if country is None:
        countries = [c for c, _ in COUNTRY_DATA]
        weights = [w for _, w in COUNTRY_DATA]
        country = weighted_choice(countries, weights)

    # Use CIDR-like assignments that loosely match real ASN allocations
    ip_map = {
        "China":      (42, 106, 113, 180),   # Major Chinese ISPs ranges
        "Russia":     (31, 45, 77, 93),       # Russian ISP blocks
        "USA":        (35, 52, 64, 104),      # Cloud provider ranges
        "Brazil":     (177, 186, 191, 200),   # Brazilian ISP prefixes
        "India":      (49, 122, 153, 163),    # Indian broadband ranges
        "South Korea": (211, 213, 218, 223),  # Korean telecom ranges
        "Germany":    (37, 80, 85, 91),       # German IP space
        "Japan":      (60, 110, 119, 157),    # Japanese ISP blocks
        "Nigeria":    (41, 82, 105, 154),     # Nigerian ISPs
        "Vietnam":    (14, 27, 113, 171),     # Vietnamese ranges
        "Iran":       (5, 37, 78, 94),        # Iranian ranges
        "Ukraine":    (62, 78, 91, 109),      # Ukrainian ranges
    }

    prefix = ip_map.get(country, (42, 45, 77, 93))
    return f"{random.randint(prefix[0], prefix[0]+10)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"


def generate_attacks(num_attacks=80):
    """
    Generate realistic fake attack logs spanning the last 24 hours.

    Cybersecurity concepts modeled:
      1. Credential stuffing: repeated password attempts across many usernames
      2. Time-based patterns: attacks cluster in bursts (automated scanners)
      3. Geographic distribution: attacker IPs from multiple countries
      4. Protocol fingerprinting: SSH client version leaks info about the tool used

    Returns a list of attack records ready for insertion.
    """
    random.seed(int(datetime.now().timestamp()))  # Use unix timestamp as seed (3.14+ compatible)
    now = datetime.now()

    attacks = []

    # ─── Phase A: Spike patterns (real SSH honeypot traffic is bursty) ──
    # Attacks come in "campaigns" — a scanner hits for 2 hours, then rests.
    spike_times = [now - timedelta(hours=random.randint(1, 5)) for _ in range(4)]

    for i in range(num_attacks):
        # Decide if this attack is part of a spike (more likely) or background noise
        if spike_times and random.random() < 0.5:
            base = spike_times[i % len(spike_times)]
            delta_minutes = random.randint(-60, 60)  # Clustered around the spike
            timestamp = base + timedelta(minutes=delta_minutes)
        else:
            # Background scanning — roughly uniform over last 24 hours
            delta_hours = random.uniform(0.5, 23)
            timestamp = now - timedelta(hours=delta_hours)

        source_ip = generate_fake_ip()
        username = random.choice(COMMON_USERNAMES)
        password = random.choice(COMMON_PASSWORDS)
        version = random.choice(WEBSERVER_VERSIONS)

        attacks.append({
            "timestamp": timestamp.strftime("%Y-%m-%d %H:%M:%S"),
            "source_ip": source_ip,
            "username": username,
            "password": password,
            "protocol_version": version,
        })

    # Sort by timestamp ascending for realistic chronological insertion
    attacks.sort(key=lambda a: a["timestamp"])
    return attacks


def insert_attacks(attacks):
    """Insert the generated attacks into the SQLite database."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS attacks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            source_ip TEXT NOT NULL,
            username TEXT NOT NULL,
            password TEXT NOT NULL,
            protocol_version TEXT DEFAULT ''
        )
    """)
    conn.commit()

    inserted = 0
    for a in attacks:
        cursor.execute(
            "INSERT INTO attacks (timestamp, source_ip, username, password, protocol_version) VALUES (?, ?, ?, ?, ?)",
            (
                a["timestamp"],
                a["source_ip"],
                a["username"],
                a["password"],
                a["protocol_version"],
            ),
        )
        inserted += 1

    conn.commit()
    conn.close()
    return inserted


def main():
    """Main entry point — generate and insert mock data if DB doesn't already have records."""
    # Check that the DB file exists to avoid creating a new dummy DB
    if not os.path.exists(DB_PATH):
        # Initialize database first (empty)
        import database as db_mod
        db_mod.init_db()

    # Count existing records — don't flood with duplicates on reruns
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM attacks")
    count = cursor.fetchone()[0]
    conn.close()

    if count > 0:
        print(f"Database already has {count} records. Skipping mock data generation.")
        print("To clear and regenerate, run: rm attacks.db && python generate_mock_data.py\n")
        return

    print("╔════════════════════════════════════════════╗")
    print("║   SSH Honeypot — Mock Data Generator       ║")
    print("╚════════════════════════════════════════════╝\n")
    print(f"Generating {80} realistic SSH brute-force attacks...")

    attacks = generate_attacks(num_attacks=80)
    inserted = insert_attacks(attacks)

    # Print summary statistics for verification
    unique_ips = len(set(a["source_ip"] for a in attacks))
    top_user = max(set(
        ((u, attacks.count({"username": u})) for a in attacks for u in {a["username"]})
    ), key=lambda x: x[1])[0] if attacks else "N/A"

    print(f"\n✓ Inserted {inserted} attack records into {DB_PATH}\n")
    print("Summary of generated data:")
    print(f"  - Unique attacker IPs : {unique_ips}")
    print(f"  - Time range          : {attacks[0]['timestamp']} → {attacks[-1]['timestamp']}")
    user_counts = {}
    for a in attacks:
        user_counts[a["username"]] = user_counts.get(a["username"], 0) + 1
    top_username = max(user_counts, key=user_counts.get)
    print(f"  - Top targeted user   : {top_username} ({user_counts[top_username]} attempts)")
    pw_counts = {}
    for a in attacks:
        pw_counts[a["password"]] = pw_counts.get(a["password"], 0) + 1
    top_pw = max(pw_counts, key=pw_counts.get)
    print(f"  - Top password tried  : {top_pw} ({pw_counts[top_pw]} times)")
    print()


if __name__ == "__main__":
    main()
