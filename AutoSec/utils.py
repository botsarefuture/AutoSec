# Description: Utility functions for the fresh module.

from var import HASH_FILE
import os

CMD = "python3 AutoSec/index.py -l"

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
    
def run_in():
    """
    Command to un gzip the auth logs and run them all into the fresh module.
    """

    # first walk the directory and get all the files
    for root, dirs, files in os.walk("/var/log/"):
        for file in files:
            if file.endswith(".gz") and "auth" in file:
                # unzip the file
                temp_file = os.path.join("./temp", file[:-3])  # Remove .gz extension
                os.system(f"gunzip -c {os.path.join(root, file)} > {temp_file}")
                os.system(f"{CMD} -l {temp_file} -a ")
            elif file.endswith(".log") and "auth" in file:
                # run the file into the fresh module
                os.system(f"{CMD} {os.path.join(root, file)} -a")