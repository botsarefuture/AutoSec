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
                os.system(f"{CMD} {temp_file} -a")
                
            elif file.endswith(".log") and "auth" in file:
                # Run the file into the fresh module
                os.system(f"{CMD} {os.path.join(root, file)} -a")
                
def fetch_banned_ips():
    """
    Fetches the banned IPs from the fresh module.
    """
    url = "https://core.security.luova.club/api/blacklist?text=true"
    url_2 = "https://core.security.luova.club/api/whitelist?text=true"
    result = requests.get(url)
    try:
        result_2 = requests.get(url_2, timeout=10).text
    except requests.exceptions.Timeout:
        result_2 = ""   
    
    except Exception as e:
        result_2 = ""     
    
    return result.text.strip().split("\n"), result_2.strip().split("\n")
    
def build_commands_for_banned_ips(banned_ips, unbanned_ips):
    """
    Builds a list of commands to ban the given IPs.

    Parameters
    ----------
    banned_ips : list
        A list of banned IPs.

    Returns
    -------
    list
        A list of commands to ban the given IPs.
    """
    return [f"sudo iptables -A INPUT -s {ip} -j DROP" for ip in banned_ips], [f"sudo iptables -D INPUT -s {ip} -j DROP" for ip in unbanned_ips]

def run_car():
    build_commands_for_banned_ips(*fetch_banned_ips())
    
