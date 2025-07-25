# utils/logger.py

from datetime import datetime

def log(message, tag="INFO"):
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{now}] [{tag}] {message}")
