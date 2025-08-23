from flask import Flask, request
from src.utils.logger import setup_logger
from src.utils.config_parser import read_config
from collections import defaultdict
import time

# Load config
config = read_config("config.yaml")["http"]  # <-- only http section
PORT = config["port"]
LOG_FILE = config["log_file"]

# Setup logger
logger = setup_logger("HTTP_Honeypot", LOG_FILE)

# Track requests for brute-force / flood detection
request_tracker = defaultdict(list)
BLOCK_TIME = 60      # seconds to block after threshold exceeded
THRESHOLD = 20       # max requests in WINDOW
WINDOW = 30          # seconds to check request frequency

# Store blocked IPs with unblock timestamp
blocked_ips = {}

app = Flask(__name__)

def is_ip_blocked(ip):
    """Check if IP is currently blocked."""
    if ip in blocked_ips:
        if time.time() < blocked_ips[ip]:
            return True
        else:
            del blocked_ips[ip]  # unblock after time expires
    return False

@app.before_request
def check_rate_limit():
    ip = request.remote_addr

    if is_ip_blocked(ip):
        logger.warning(f"Blocked request from {ip}")
        return "Access Denied", 403

    now = time.time()
    request_tracker[ip].append(now)

    # Keep only requests within the WINDOW
    request_tracker[ip] = [t for t in request_tracker[ip] if now - t < WINDOW]

    if len(request_tracker[ip]) > THRESHOLD:
        blocked_ips[ip] = now + BLOCK_TIME
        logger.warning(f"IP {ip} blocked for {BLOCK_TIME} seconds (too many requests)")
        return "Too Many Requests", 429


@app.route("/", defaults={"path": ""}, methods=["GET", "POST"])
@app.route("/<path:path>", methods=["GET", "POST"])
def catch_all(path):
    ip = request.remote_addr
    method = request.method
    headers = dict(request.headers)
    data = request.get_data(as_text=True)

    logger.info(
        f"Request from {ip} | Path: /{path} | Method: {method} | "
        f"Headers: {headers} | Data: {data}"
    )
    return "Welcome to HoneyKube HTTP Honeypot!", 200


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=PORT)  # external connections enabled

