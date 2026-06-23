"""
honeypot.py - Interactive SSH Honeypot Server
"""

import paramiko
import sqlite3
import os
import sys
import time
import socket
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from database import DB_PATH, init_db

HONEYPOT_PORT = 8000
HOST_KEYS_DIR = "host_keys"


def generate_host_keys():
    """Generate RSA host keys automatically on startup."""
    os.makedirs(HOST_KEYS_DIR, exist_ok=True)

    rsa_path = os.path.join(HOST_KEYS_DIR, "host_rsa_key")
    ecdsa_path = os.path.join(HOST_KEYS_DIR, "host_ecdsa_key")

    if not os.path.exists(rsa_path):
        key = paramiko.RSAKey.generate(2048)
        key.write_private_key_file(rsa_path)
        print(f"[*] Primary RSA host key generated: {rsa_path}")

    if not os.path.exists(ecdsa_path):
        key = paramiko.RSAKey.generate(2048)
        key.write_private_key_file(ecdsa_path)
        print(f"[*] Secondary RSA host key generated: {ecdsa_path}")


def write_attack_log(timestamp, source_ip, username, password, protocol_version=""):
    """Insert attack log entry into SQLite database."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO attacks (timestamp, source_ip, username, password, protocol_version) VALUES (?, ?, ?, ?, ?)",
        (timestamp, source_ip, username[:200], password[:200], str(protocol_version)[:50] or ""),
    )
    conn.commit()
    conn.close()


class HoneypotServer(paramiko.ServerInterface):
    def __init__(self, client_ip):
        self.client_ip = client_ip
        self.transport = None

    def check_channel_request(self, kind, chanid):
        if kind == "session":
            return paramiko.Channel.OPEN_SUCCESS
        return paramiko.Channel.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def get_allowed_auths(self, username):
        return "password"

    def _dump_attack(self, username, password, pv="N/A"):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"\n[!] LOGIN ATTEMPT | IP={self.client_ip} User={username} Pass={password} Tool={pv}")
        write_attack_log(timestamp, self.client_ip, username, password, pv)

    def check_auth_publickey(self, username, key):
        self._dump_attack(username, "<public-key>", "public-key-auth")
        return paramiko.AUTH_FAILED

    def check_auth_password(self, username, password):
        pv = "N/A"
        try:
            transport = self.get_transport()
            if transport:
                pv = str(transport.get_remote_version() or "")[:60]
        except Exception:
            pass

        self._dump_attack(username, password, pv)
        return paramiko.AUTH_FAILED

    def get_username(self):
        return "unknown"

    def auth_password(self, username, password):
        return paramiko.AUTH_DENIED


def run_honeypot():
    """Start the honeypot SSH server."""
    init_db()
    generate_host_keys()

    print("=" * 50)
    print("  SSH Honeypot Server")
    print(f"  Listening on port {HONEYPOT_PORT}")
    print(f"  Logs to: {DB_PATH}")
    print("=" * 50)

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("0.0.0.0", HONEYPOT_PORT))
    sock.listen(100)

    print(f"[*] Honeypot activated! Listening on port {HONEYPOT_PORT}...")
    print("[*] Press Ctrl+C to stop.\n")

    try:
        while True:
            client, addr = sock.accept()
            print(f"[+] Connection from {addr[0]}:{addr[1]}")
            
            try:
                transport = paramiko.Transport(client)
                transport.local_version = "SSH-2.0-HoneypotServer"
                transport.add_server_key(paramiko.RSAKey.from_private_key_file(os.path.join(HOST_KEYS_DIR, "host_rsa_key")))
                
                handler = HoneypotServer(client_ip=addr[0])
                transport.start_server(server=handler)
                
                while transport.is_active():
                    time.sleep(1)
                    
            except (EOFError, ConnectionResetError, OSError, paramiko.SSHException) as e:
                print(f"[-] Connection closed or dropped: {e}")
            except Exception as e:
                print(f"[-] Unexpected error: {e}")

    except KeyboardInterrupt:
        print("\n[*] Honeypot shutting down...")
    finally:
        sock.close()


if __name__ == "__main__":
    run_honeypot()