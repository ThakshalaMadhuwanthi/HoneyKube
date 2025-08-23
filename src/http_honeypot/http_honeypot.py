from flask import Flask, request
from src.utils.logger import setup_logger
from src.utils.config_parser import read_config

# Load config
config = read_config("config.yaml")["http"]  # <-- pick only http section
PORT = config["port"]
LOG_FILE = config["log_file"]

# Setup logger
logger = setup_logger("HTTP_Honeypot", LOG_FILE)

app = Flask(__name__)

@app.route("/", defaults={"path": ""}, methods=["GET", "POST"])
@app.route("/<path:path>", methods=["GET", "POST"])
def catch_all(path):
    ip = request.remote_addr
    method = request.method
    headers = dict(request.headers)
    data = request.get_data(as_text=True)
    logger.info(f"Request from {ip} | Path: /{path} | Method: {method} | Data: {data}")
    return "Welcome to HoneyKube!", 200

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=PORT)

