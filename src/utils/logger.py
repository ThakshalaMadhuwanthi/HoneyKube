import logging
import os

# Ensure log folder exists
os.makedirs("logs", exist_ok=True)

def setup_logger(name, log_file):
    # Ensure the directory exists
    os.makedirs(os.path.dirname(log_file), exist_ok=True)

    logger = logging.getLogger(name)
    logger.setLevel(logging.INFO)
    formatter = logging.Formatter('%(asctime)s | %(name)s | %(message)s')

    file_handler = logging.FileHandler(log_file)
    file_handler.setFormatter(formatter)

    if not logger.handlers:
        logger.addHandler(file_handler)
    return logger
