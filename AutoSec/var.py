import requests

def get_ip():
    result = requests.get("https://checkip.amazonaws.com/")
    return result.text.strip()

def fetch_mode():
    """
    Fetches the mode of the fresh module.
    """
    url = "https://core.security.luova.club/visualizer/api/alertlevel"
    result = requests.get(url)
    
    return result.json().get("alert_level", 0)

def init_mode(fetch_mode):
    m = fetch_mode()

    if m == 0:
        mode = "pink"

    elif m == 1:
        mode = "blue"
    
    elif m == 2:
        mode = "red"
    
    elif m == 3:
        mode = "violet"
    
    elif m == 4:
        mode = "darkred"
    
    elif m == 5:
        mode = "black"

    return mode

MODE = init_mode(fetch_mode)

COMMANDS = []

PROCESSED_IPS = []
PROCESSED_LINES = []

HASH_FILE = "processed_hashes.txt"
SERVER_IP = get_ip()

