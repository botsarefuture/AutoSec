import requests
import time
import logging
import os

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger("watchthecat")

def check_internet():
    """
    Checks internet connectivity by sending a GET request to Google.

    Returns
    -------
    bool
        True if internet is accessible, False otherwise.
    """
    logger.debug("Checking internet connectivity")
    try:
        response = requests.get("https://www.google.com", timeout=5)
        response.raise_for_status()
        logger.info("Internet connection is available.")
        return True
    except requests.exceptions.RequestException as e:
        logger.error(f"Internet connectivity check failed: {e}")
        return False

def get_mode():
    """
    Fetches the alert level from the SECORE API.

    If the SECORE API is unreachable but internet is available, returns an alert level of 5.

    Returns
    -------
    int or None
        The alert level fetched from the API, or 5 if the server is unreachable and internet is available.
    """
    logger.debug("Entering get_mode function")
    url = "https://core.security.luova.club/visualizer/api/alertlevel"
    try:
        logger.debug(f"Sending GET request to {url}")
        response = requests.get(url, timeout=5)  # Added timeout to avoid hanging requests
        response.raise_for_status()  # Raise an HTTPError for bad responses
        json_data = response.json()
        logger.debug(f"Received response: {json_data}")
        return int(json_data.get('alert_level', 0))
    except requests.exceptions.RequestException as e:
        logger.error(f"Request failed: {e}")
        if check_internet():
            logger.warning("Server is unreachable, but internet is available. Returning alert level 5.")
            return 5
    except ValueError as e:
        logger.error(f"Invalid JSON received: {e}")
    except (KeyError, TypeError) as e:
        logger.error(f"Unexpected data format: {e}")
    logger.debug("Exiting get_mode function with None")
    return None

def no_cat_found(alert_level):
    """
    Determines if a cat is not detected based on the alert level.

    Parameters
    ----------
    alert_level : int or None
        The current alert level.

    Returns
    -------
    bool
        True if no cat is detected (alert level < 4 or None), False otherwise.
    """
    logger.debug(f"Checking no_cat_found with alert_level: {alert_level}")
    return alert_level is None or alert_level < 4

def cat_found(alert_level):
    """
    Determines if a cat is detected based on the alert level.

    Parameters
    ----------
    alert_level : int or None
        The current alert level.

    Returns
    -------
    bool
        True if a cat is detected (alert level >= 4), False otherwise.
    """
    logger.debug(f"Checking cat_found with alert_level: {alert_level}")
    return not no_cat_found(alert_level)

def restrict_access_to_port_22():
    """
    Restricts access to port 22 by adding iptables rules:
    - Rejects all incoming traffic to port 22 except from the 10.x.x.x subnet.

    Returns
    -------
    None
    """
    logger.info("Restricting access to port 22.")
    try:
        os.system("iptables -A INPUT -p tcp --dport 22 -s 10.0.0.0/8 -j ACCEPT")
        os.system("iptables -A INPUT -p tcp --dport 22 -j REJECT")
        logger.info("Port 22 access restricted successfully, except for 10.x.x.x subnet.")
    except Exception as e:
        logger.error(f"Failed to restrict port 22: {e}")

def allow_access_to_port_22():
    """
    Allows access to port 22 by removing the iptables rule that rejects incoming traffic.

    Returns
    -------
    None
    """
    logger.info("Allowing access to port 22.")
    try:
        os.system("iptables -D INPUT -p tcp --dport 22 -j REJECT")
        os.system("iptables -D INPUT -p tcp --dport 22 -s 10.0.0.0/8 -j ACCEPT")
        logger.info("Port 22 access allowed successfully.")
    except Exception as e:
        logger.error(f"Failed to allow port 22: {e}")

def main():
    """
    Main function that monitors the SECORE API for alert levels and adjusts security measures accordingly.

    Returns
    -------
    None
    """
    logger.debug("Starting main loop")
    suicide_time = False
    alert_level = 0

    while not suicide_time:
        logger.debug("Fetching alert level")
        alert_level = get_mode() if (new_alert_level := get_mode()) is not None else alert_level
        logger.debug(f"Current alert_level: {alert_level}")

        if no_cat_found(alert_level):
            logger.info(f"No cat found. Alert level is: {alert_level}")
            allow_access_to_port_22()
            time.sleep(5)
        else:
            logger.warning(f"Cat detected! Alert level is: {alert_level}. Initiating security measures.")
            restrict_access_to_port_22()
            time.sleep(10)
    logger.debug("Exiting main loop")

if __name__ == "__main__":
    logger.debug("Starting script")
    main()
    logger.debug("Script ended")
