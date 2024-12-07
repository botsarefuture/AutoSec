import requests

def get_ip():
    result = requests.get("https://checkip.amazonaws.com/")
    return result.text.strip()

MODE = "green" or "yellow" or "red" or "black"
COMMANDS = []

PROCESSED_IPS = []
PROCESSED_LINES = []

HASH_FILE = "processed_hashes.txt"
SERVER_IP = get_ip()

