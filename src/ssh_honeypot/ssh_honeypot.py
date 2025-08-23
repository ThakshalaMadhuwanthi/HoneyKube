import socket
import threading
import datetime
import os
import yaml
from collections import defaultdict
from typing import Dict, List

# Load configuration from config.yaml
with open("config.yaml", "r") as f:
    config = yaml.safe_load(f)

SSH_PORT = config["ssh"]["port"]
LOG_FILE = config["ssh"]["log_file"]

# Brute-force detection values from config.yaml
THRESHOLD = config.get("brute_force", {}).get("max_attempts", 5)   # default=5
WINDOW = config.get("brute_force", {}).get("window_seconds", 60)  # default=60

# Track failed login attempts per IP
FAILED_ATTEMPTS: Dict[str, List[datetime.datetime]] = defaultdict(list)

def log_event(message: str):
    """Log honeypot events to file with timestamp"""
    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
    with open(LOG_FILE, "a") as f:
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        f.write(f"{timestamp} | SSH_Honeypot | {message}\n")
    print(message)

def detect_bruteforce(ip: str):
    """Check if an IP exceeded brute-force threshold"""
    now = datetime.datetime.now()
    FAILED_ATTEMPTS[ip] = [
        t for t in FAILED_ATTEMPTS[ip] if (now - t).seconds <= WINDOW
    ]
    if len(FAILED_ATTEMPTS[ip]) >= THRESHOLD:
        log_event(f"[BRUTEFORCE DETECTED] IP: {ip} exceeded {THRESHOLD} failed attempts in {WINDOW}s")
        return True
    return False

def handle_client(client_socket: socket.socket, client_address: tuple):
    ip = client_address[0]
    log_event(f"Connection from {ip}:{client_address[1]}")

    try:
        client_socket.send(b"login: ")
        username = client_socket.recv(1024).decode().strip()
        client_socket.send(b"password: ")
        password = client_socket.recv(1024).decode().strip()

        log_event(f"Attempted login | Username: {username} | Password: {password}")

        # Record failed attempt
        now = datetime.datetime.now()
        FAILED_ATTEMPTS[ip].append(now)

        # Check brute-force detection
        detect_bruteforce(ip)

        client_socket.send(b"Permission denied\n")
        client_socket.close()

    except Exception as e:
        log_event(f"Exception: {e}")
        client_socket.close()

def start_honeypot():
    """Start SSH honeypot"""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("0.0.0.0", SSH_PORT))
    server.listen(5)
    log_event(f"SSH Honeypot running on port {SSH_PORT}")

    while True:
        client_socket, client_address = server.accept()
        client_handler = threading.Thread(
            target=handle_client,
            args=(client_socket, client_address)
        )
        client_handler.start()

if __name__ == "__main__":
    start_honeypot()

