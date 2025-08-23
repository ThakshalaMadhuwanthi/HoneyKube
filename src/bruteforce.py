import time
from collections import defaultdict

# Dictionary to track failed attempts per IP
_failed_attempts = defaultdict(list)

# Configuration
BLOCK_THRESHOLD = 5      # number of failed attempts before blocking
BLOCK_TIME = 300         # seconds window to track attempts

def record_failed_attempt(ip):
    """Record a failed login attempt for an IP."""
    now = time.time()
    _failed_attempts[ip].append(now)
    # Keep only recent attempts within BLOCK_TIME
    _failed_attempts[ip] = [t for t in _failed_attempts[ip] if now - t < BLOCK_TIME]

def is_ip_blocked(ip):
    """Check if IP has exceeded failed attempt threshold."""
    return len(_failed_attempts[ip]) >= BLOCK_THRESHOLD

def get_blocked_ips():
    """Return all currently blocked IPs."""
    now = time.time()
    return [ip for ip, attempts in _failed_attempts.items() 
            if len([t for t in attempts if now - t < BLOCK_TIME]) >= BLOCK_THRESHOLD]
