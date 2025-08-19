import socket
import threading
import paramiko
from src.utils.logger import setup_logger
from src.utils.config_parser import read_config


# Load config
config = read_config("config.yaml")
PORT = config["port"]
LOG_FILE = config["log_file"]

# Setup logger
logger = setup_logger("SSH_Honeypot", LOG_FILE)

# Generate host key for SSH server
host_key = paramiko.RSAKey.generate(2048)

class SSHServer(paramiko.ServerInterface):
    def check_auth_password(self, username, password):
        logger.info(f"Attempted login | Username: {username} | Password: {password}")
        return paramiko.AUTH_FAILED

    def get_allowed_auths(self, username):
        return "password"

def handle_client(client_socket):
    transport = paramiko.Transport(client_socket)
    transport.add_server_key(host_key)
    server = SSHServer()
    try:
        transport.start_server(server=server)
        channel = transport.accept(20)
        if channel is not None:
            channel.send("SSH Honeypot - Fake Shell\n")
            channel.close()
    except Exception as e:
        logger.info(f"Exception: {e}")
    finally:
        client_socket.close()

def start_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(("", PORT))
    server_socket.listen(100)
    logger.info(f"SSH Honeypot running on port {PORT}")

    while True:
        client, addr = server_socket.accept()
        logger.info(f"Connection from {addr[0]}")
        threading.Thread(target=handle_client, args=(client,)).start()

if __name__ == "__main__":
    start_server()
