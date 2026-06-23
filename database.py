"""
database.py - SQLite database layer for the SSH Honeypot

Cybersecurity concept: Centralized logging of failed authentication attempts is critical
for threat intelligence. By storing attack data in a persistent database, we can perform
forensic analysis and identify patterns in attacker behavior.
"""

import sqlite3
import os
from datetime import datetime

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "attacks.db")


def get_connection():
    """Get a connection to the SQLite database."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """
    Initialize the database schema.

    The attacks table stores:
      - timestamp: When the login attempt occurred (for temporal analysis)
      - source_ip: Attacker's IP address (for geographic correlation)
      - username: Account attempted to access
      - password: Credential tried by attacker
      - protocol_version: SSH version string reported by client (fingerprinting)

    These fields enable:
      1. Credential stuffing pattern detection (repeated passwords across IPs)
      2. Targeted account enumeration (most attacked usernames)
      3. Brute-force timing analysis (attacks per hour)
      4. Geographic threat mapping (IP to country correlation)
    """
    conn = get_connection()
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
    conn.close()


def insert_attack(timestamp: str, source_ip: str, username: str, password: str, protocol_version: str = ""):
    """Insert a failed login attempt into the database."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO attacks (timestamp, source_ip, username, password, protocol_version) VALUES (?, ?, ?, ?, ?)",
        (timestamp, source_ip, username, password, protocol_version),
    )
    conn.commit()
    conn.close()


def get_all_attacks(limit: int = 100):
    """Get the most recent attacks for the live feed table."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT timestamp, source_ip, username, password FROM attacks ORDER BY id DESC LIMIT ?",
        (limit,),
    )
    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]


def get_total_attacks():
    """Get the total number of recorded attack attempts."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) as count FROM attacks")
    result = cursor.fetchone()["count"]
    conn.close()
    return result


def get_unique_ips():
    """Get the count of unique attacker IP addresses."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(DISTINCT source_ip) as count FROM attacks")
    result = cursor.fetchone()["count"]
    conn.close()
    return result


def get_top_username():
    """Get the most targeted username across all attacks."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT username, COUNT(*) as count FROM attacks GROUP BY username ORDER BY count DESC LIMIT 1")
    result = cursor.fetchone()
    conn.close()
    return result["username"] if result else "N/A"


def get_top_password():
    """Get the most commonly tried password across all attacks."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT password, COUNT(*) as count FROM attacks GROUP BY password ORDER BY count DESC LIMIT 1")
    result = cursor.fetchone()
    conn.close()
    return result["password"] if result else "N/A"


def get_attacks_per_hour():
    """
    Get attack counts grouped by the last 24 hours (one row per hour).

    Cybersecurity use: Identifies attack spikes and temporal patterns,
    helping determine if attackers operate from specific timezones or campaigns.
    """
    conn = get_connection()
    cursor = conn.cursor()
    # Get the most recent hour in the dataset to anchor our 24h window
    cursor.execute("SELECT MAX(timestamp) as max_ts FROM attacks")
    row = cursor.fetchone()
    if not row or not row["max_ts"]:
        conn.close()
        return []

    max_ts = row["max_ts"]
    # Parse the max timestamp and go back 24 hours
    now = datetime.strptime(max_ts, "%Y-%m-%d %H:%M:%S")
    from datetime import timedelta

    cuts = []
    for i in range(24):
        hour_start = (now - timedelta(hours=23 - i)).replace(minute=0, second=0)
        hour_end = hour_start.replace(hour=hour_start.hour + 1) if hour_start.hour + 1 < 24 else hour_start.replace(hour=23, minute=59, second=59)
        label = hour_start.strftime("%H:00")
        cuts.append((label, hour_start, hour_end))

    # For each cut compute count of attacks in that window
    result = []
    for label, h_start, h_end in cuts:
        cursor.execute(
            "SELECT COUNT(*) as cnt FROM attacks WHERE timestamp >= ? AND timestamp < ?",
            (h_start.strftime("%Y-%m-%d %H:%M:%S"), h_end.strftime("%Y-%m-%d %H:%M:%S")),
        )
        count = cursor.fetchone()["cnt"]
        result.append({"label": label, "value": count})

    conn.close()
    return result


def get_top_5_usernames():
    """Get the top 5 most targeted usernames for the pie chart."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT username, COUNT(*) as value FROM attacks GROUP BY username ORDER BY value DESC LIMIT 5"
    )
    rows = cursor.fetchall()
    conn.close()
    return [{"label": row["username"], "value": row["value"]} for row in rows]


def get_top_10_usernames():
    """Get the top 10 most targeted usernames (for a detailed bar chart)."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT username, COUNT(*) as value FROM attacks GROUP BY username ORDER BY value DESC LIMIT 10"
    )
    rows = cursor.fetchall()
    conn.close()
    return [{"label": row["username"], "value": row["value"]} for row in rows]


def get_top_10_passwords():
    """Get the top 10 most tried passwords (for a detailed bar chart)."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT password, COUNT(*) as value FROM attacks GROUP BY password ORDER BY value DESC LIMIT 10"
    )
    rows = cursor.fetchall()
    conn.close()
    return [{"label": row["password"], "value": row["value"]} for row in rows]


def get_source_ip_countries():
    """
    Return a sample mapping of IPs to fake countries for geographical visualization.

    In production, this would use a GeoIP database (e.g., maxminddb) to do real IP->country lookups.
    Cybersecurity concept: Geographic correlation helps identify attack campaigns from specific regions.
    """
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT DISTINCT source_ip FROM attacks ORDER BY source_ip")
    rows = cursor.fetchall()
    conn.close()
    result = []
    for row in rows:
        ip = row["source_ip"]
        # Generate a deterministic fake country based on IP octets for visual interest
        parts = ip.split(".")
        idx = (int(parts[0]) + int(parts[-1])) % 8
        countries = ["China", "Russia", "USA", "Brazil", "India", "South Korea", "Germany", "Nigeria"]
        result.append({"ip": ip, "country": countries[idx]})
    return result
