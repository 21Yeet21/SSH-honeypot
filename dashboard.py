"""
dashboard.py - Flask web application for the SSH Honeypot analytics dashboard.

Cybersecurity Concept: Security Operations Centers (SOCs) rely on dashboards to
visualize threat intelligence data in real-time. This dashboard mirrors what a
professional SIEM (Security Information and Event Management) system would display:
  - Aggregate statistics for situational awareness
  - Temporal analysis for identifying attack campaigns
  - Credential analysis for understanding attacker TTPs (Tactics, Techniques, Procedures)
"""

import os
import sys
import sqlite3
from datetime import datetime

# Add parent directory to path for database imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from flask import Flask, render_template, jsonify
import database as db_mod

app = Flask(__name__)

# Configure template and static folders
app.jinja_env.trim_blocks = True
app.jinja_env.lstrip_blocks = True

# Database path - use absolute path to avoid issues
DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "attacks.db")


def get_db_connection():
    """Create a database connection with timeout to prevent locking issues."""
    conn = sqlite3.connect(DB_PATH, timeout=5.0)
    conn.row_factory = sqlite3.Row
    return conn


@app.route("/")
def dashboard():
    """Render the main dashboard page."""
    return render_template("index.html")


@app.route("/api/stats")
def api_stats():
    """
    Return summary statistics as JSON.
    
    These metrics help SOC analysts:
      - Total attacks: Overall threat level
      - Unique IPs: Scope of the attack campaign
      - Top username: Most targeted account (prioritize hardening)
      - Top password: Most common credential (inform password policy)
    """
    try:
        stats = {
            "total_attacks": db_mod.get_total_attacks(),
            "unique_ips": db_mod.get_unique_ips(),
            "top_username": db_mod.get_top_username(),
            "top_password": db_mod.get_top_password(),
        }
        return jsonify(stats)
    except Exception as e:
        print(f"Error in /api/stats: {e}")
        return jsonify({"error": str(e)}), 500


@app.route("/api/attacks-per-hour")
def api_attacks_per_hour():
    """
    Return attack counts grouped by hour for the last 24 hours.
    
    Cybersecurity use: Identifying attack spikes helps determine if attackers
    operate from specific timezones or if there are coordinated campaigns.
    """
    try:
        data = db_mod.get_attacks_per_hour()
        # Ensure data is in array format [{label, value}]
        if isinstance(data, dict):
            data = [{"label": k, "value": v} for k, v in data.items()]
        return jsonify(data)
    except Exception as e:
        print(f"Error in /api/attacks-per-hour: {e}")
        return jsonify([]), 500


@app.route("/api/top-usernames")
def api_top_usernames():
    """Return top 5 targeted usernames for the pie chart."""
    try:
        data = db_mod.get_top_5_usernames()
        # Ensure data is in array format [{label, value}]
        if isinstance(data, dict):
            data = [{"label": k, "value": v} for k, v in data.items()]
        return jsonify(data)
    except Exception as e:
        print(f"Error in /api/top-usernames: {e}")
        return jsonify([]), 500


@app.route("/api/top-passwords")
def api_top_passwords():
    """Return top 10 tried passwords for the bar chart."""
    try:
        data = db_mod.get_top_10_passwords()
        # Ensure data is in array format [{label, value}]
        if isinstance(data, dict):
            data = [{"label": k, "value": v} for k, v in data.items()]
        return jsonify(data)
    except Exception as e:
        print(f"Error in /api/top-passwords: {e}")
        return jsonify([]), 500


@app.route("/api/attacks-per-username")
def api_attacks_per_username():
    """Return attack counts per username for the bar chart."""
    try:
        data = db_mod.get_top_10_usernames()
        # Ensure data is in array format [{label, value}]
        if isinstance(data, dict):
            data = [{"label": k, "value": v} for k, v in data.items()]
        return jsonify(data)
    except Exception as e:
        print(f"Error in /api/attacks-per-username: {e}")
        return jsonify([]), 500


@app.route("/api/live-feed")
def api_live_feed():
    """
    Return the most recent attack logs for the scrolling table.
    
    In a production system this would use WebSockets for real-time updates.
    Here we use periodic polling (every 5 seconds via frontend).
    """
    try:
        attacks = db_mod.get_all_attacks(limit=20)
        # Ensure field names match what frontend expects
        formatted_attacks = []
        for attack in attacks:
            formatted_attacks.append({
                "timestamp": attack.get("timestamp", "N/A"),
                "source_ip": attack.get("source_ip", "unknown"),
                "username": attack.get("username", "N/A"),
                "password": attack.get("password", "N/A"),
                "protocol_version": attack.get("protocol_version", "SSH")
            })
        return jsonify(formatted_attacks)
    except Exception as e:
        print(f"Error in /api/live-feed: {e}")
        return jsonify([]), 500


if __name__ == "__main__":
    # Initialize the database schema on startup
    db_mod.init_db()
    
    # Verify database exists and has data
    if os.path.exists(DB_PATH):
        conn = sqlite3.connect(DB_PATH)
        count = conn.execute("SELECT COUNT(*) FROM attacks").fetchone()[0]
        conn.close()
        print(f"  Database: {DB_PATH}")
        print(f"  Records in database: {count}")
    else:
        print(f"  WARNING: Database not found at {DB_PATH}")
    
    print("=" * 50)
    print("  SSH Honeypot Dashboard")
    print("  Opening http://127.0.0.1:5000")
    print("=" * 50)
    
    app.run(debug=True, host="127.0.0.1", port=5000)