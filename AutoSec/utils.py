# Description: Utility functions for the fresh module.

import requests
from var import HASH_FILE
import os

CMD = "python3 /etc/AutoSec/AutoSec/index.py -l"


def load_processed_hashes():
    """
    Loads processed hashes from a file.

    Returns
    -------
    list
        A list of processed hashes.
    """
    if os.path.exists(HASH_FILE):
        with open(HASH_FILE, "r") as file:
            return [line.strip() for line in file]
    return []


def save_processed_hashes(hashes):
    """
    Saves processed hashes to a file.

    Parameters
    ----------
    hashes : list
        A list of hashes to save.
    """
    with open(HASH_FILE, "w") as file:
        for hash in hashes:
            file.write(f"{hash}\n")


def load_welcome():
    with open("/etc/AutoSec/welcome.txt") as f:
        return f.read()


def load_version():
    with open("/etc/AutoSec/version.txt") as f:
        return f.read()

def run_in():
    """
    Command to unzip the auth logs and run them all into the fresh module.
    """
    temp_dir = "/etc/AutoSec/temp"

    # Create the temp directory if it doesn't exist
    if not os.path.exists(temp_dir):
        os.makedirs(temp_dir)

    # Walk the directory and get all the files
    for root, dirs, files in os.walk("/var/log/"):
        for file in files:
            if file.endswith(".gz") and "auth" in file:
                # Unzip the file
                temp_file = os.path.join(temp_dir, file[:-3])  # Remove .gz extension
                os.system(f"gunzip -c {os.path.join(root, file)} > {temp_file}")
                os.system(f"{CMD} {temp_file}")

            elif file.endswith(".log") and "auth" in file:
                # Run the file into the fresh module
                os.system(f"{CMD} {os.path.join(root, file)}")

    # Create a flag file to indicate that the logs have been processed
    with open("/etc/AutoSec/processed", "w") as file:
        file.write("done")

import subprocess
import logging
import requests

def fetch_banned_ips():
    """
    Fetches the banned IPs from the central blacklist.
    Returns (banned_ips, unbanned_ips)
    """
    url = "https://core.security.luova.club/api/blacklist?text=true"
    result = requests.get(url, timeout=10)

    banned = {ip.strip() for ip in result.text.split("\n") if ip.strip()}
    return list(banned), []  # Whitelist not in use yet


def iptables_rule_exists(ip):
    """Check if a DROP rule already exists for an IP/CIDR."""
    cmd = f"sudo iptables -C INPUT -s {ip} -j DROP"
    result = subprocess.run(cmd, shell=True,
                            stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL)
    return result.returncode == 0


def run_car():
    """
    Fetch, compare, and apply iptables bans safely.
    """
    try:
        banned_ips, unbanned_ips = fetch_banned_ips()

        # Deduplicate automatically since we used a set
        banned_ips = list(set(banned_ips))
        unbanned_ips = list(set(unbanned_ips))

        # --- UNBAN FIRST ---
        for ip in unbanned_ips:
            if iptables_rule_exists(ip):
                cmd = f"sudo iptables -D INPUT -s {ip} -j DROP"
                subprocess.run(cmd, shell=True)
                logging.info(f"[car] Unbanned {ip}")

        # --- BAN ---
        for ip in banned_ips:
            if not iptables_rule_exists(ip):
                cmd = f"sudo iptables -A INPUT -s {ip} -j DROP"
                subprocess.run(cmd, shell=True)
                logging.info(f"[car] Banned {ip}")

        logging.info("[car] Ban sync complete.")

    except Exception as exc:
        logging.error(f"[car] Failed: {exc}")


VERSION = load_version()
