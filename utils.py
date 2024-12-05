# Description: Utility functions for the fresh module.

from log_anal.fresh.var import HASH_FILE
import os

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
    with open("welcome.txt") as f:
        return f.read()