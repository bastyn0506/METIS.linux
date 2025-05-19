import json
import os
import threading

config = {}
trusted_ips = set()
config_path = "config.json"
config_lock = threading.Lock()
last_mtime = 0

def load_config():
    global config, trusted_ips
    try:
        with open(config_path, "r") as f:
            config = json.load(f)
            trusted_ips = set(config.get("trusted_ips", []))
    except Exception as e:
        print(f"[!] Config load error: {e}")

def config_watcher(interval=5):
    global last_mtime
    while True:
        try:
            current_mtime = os.path.getmtime(config_path)
            if current_mtime != last_mtime:
                last_mtime = current_mtime
                load_config()
        except Exception as e:
            print(f"[!] Config watcher error: {e}")
        import time
        time.sleep(interval)