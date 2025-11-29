import asyncio
import aiohttp
import logging
import subprocess
from datetime import datetime

# ----------------- Config -----------------
SECURE_API = "https://core.security.luova.club/visualizer/api/alertlevel"
CHECK_INTERVAL_NO_CAT = 5    # seconds
CHECK_INTERVAL_CAT = 10      # seconds
ALERT_LEVEL_SELF_DESTRUCT = 6

# ----------------- Logging -----------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger("watchthecat")

# ----------------- State -----------------
RESTRICTED_ACCESS = False

# ----------------- Helpers -----------------
async def fetch_alert_level(session):
    """Fetch alert level from SECORE API."""
    try:
        async with session.get(SECURE_API, timeout=5) as resp:
            resp.raise_for_status()
            data = await resp.json()
            level = int(data.get("alert_level", 0))
            logger.debug(f"Fetched alert level: {level}")
            return level
    except Exception as e:
        logger.warning(f"Failed to fetch alert level: {e}")
        return None

def restrict_port_22():
    global RESTRICTED_ACCESS
    if RESTRICTED_ACCESS:
        logger.debug("Port 22 already restricted.")
        return
    try:
        logger.info("Restricting access to port 22 (except 10.x.x.x)...")
        subprocess.run(
            ["sudo", "iptables", "-D", "INPUT", "-p", "tcp", "--dport", "22", "-j", "ACCEPT"],
            check=False
        )
        subprocess.run(
            ["sudo", "iptables", "-A", "INPUT", "-p", "tcp", "--dport", "22", "-s", "10.0.0.0/8", "-j", "ACCEPT"],
            check=True
        )
        subprocess.run(
            ["sudo", "iptables", "-A", "INPUT", "-p", "tcp", "--dport", "22", "-j", "REJECT"],
            check=True
        )
        RESTRICTED_ACCESS = True
        logger.info("Port 22 restricted successfully.")
    except Exception as e:
        logger.error(f"Failed to restrict port 22: {e}")

def allow_port_22():
    global RESTRICTED_ACCESS
    if not RESTRICTED_ACCESS:
        logger.debug("Port 22 already open.")
        return
    try:
        logger.info("Allowing access to port 22...")
        subprocess.run(
            ["sudo", "iptables", "-D", "INPUT", "-p", "tcp", "--dport", "22", "-j", "REJECT"],
            check=True
        )
        subprocess.run(
            ["sudo", "iptables", "-D", "INPUT", "-p", "tcp", "--dport", "22", "-s", "10.0.0.0/8", "-j", "ACCEPT"],
            check=True
        )
        subprocess.run(
            ["sudo", "iptables", "-A", "INPUT", "-p", "tcp", "--dport", "22", "-j", "ACCEPT"],
            check=True
        )
        RESTRICTED_ACCESS = False
        logger.info("Port 22 access restored.")
    except Exception as e:
        logger.error(f"Failed to allow port 22: {e}")

def handle_self_destruct():
    logger.critical("Alert level 6 detected! Triggering self-destruct!")
    # Uncomment only when intentional
    # subprocess.run(["bash", "suicide.sh", "--force"], check=True)

# ----------------- Main Loop -----------------
async def monitor_loop():
    alert_level = 0
    async with aiohttp.ClientSession() as session:
        while True:
            new_level = await fetch_alert_level(session)
            if new_level is not None:
                alert_level = new_level

            if alert_level >= ALERT_LEVEL_SELF_DESTRUCT:
                handle_self_destruct()
                break  # Stop the loop if self-destruct triggered
            elif alert_level >= 4:
                logger.warning(f"Cat detected! Alert level {alert_level}")
                restrict_port_22()
                await asyncio.sleep(CHECK_INTERVAL_CAT)
            else:
                logger.info(f"No cat detected. Alert level {alert_level}")
                allow_port_22()
                await asyncio.sleep(CHECK_INTERVAL_NO_CAT)

# ----------------- Entrypoint -----------------
if __name__ == "__main__":
    try:
        asyncio.run(monitor_loop())
    except KeyboardInterrupt:
        logger.info("Script stopped manually.")
