import asyncio
import aiohttp
import logging
import subprocess
import atexit
import signal
from datetime import datetime

# ----------------- Config -----------------
SECURE_API = "https://core.security.luova.club/visualizer/api/alertlevel"
CHECK_INTERVAL_NO_CAT = 5
CHECK_INTERVAL_CAT = 10
ALERT_LEVEL_SELF_DESTRUCT = 6

# ----------------- Logging -----------------
logging.basicConfig(
    level=logging.WARNING,
    format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger("watchthecat")

# ----------------- State -----------------
RESTRICTED_ACCESS = False

# ----------------- IPTABLES HELPERS -----------------
def run_cmd(cmd, ignore_errors=False):
    """Run a system command safely."""
    try:
        subprocess.run(cmd, check=not ignore_errors)
    except Exception as e:
        if not ignore_errors:
            logger.error(f"Command failed: {cmd} -> {e}")

def restore_baseline():
    """Restore safe baseline firewall rules."""
    global RESTRICTED_ACCESS

    logger.warning("Restoring baseline iptables rules...")

    # Remove all special rules (ignore errors)
    run_cmd(["sudo", "iptables", "-D", "INPUT", "-p", "tcp", "--dport", "22", "-j", "REJECT"], ignore_errors=True)
    run_cmd(["sudo", "iptables", "-D", "INPUT", "-p", "tcp", "--dport", "22", "-s", "10.0.0.0/8", "-j", "ACCEPT"], ignore_errors=True)

    # Ensure one and only one SSH allow rule exists
    run_cmd(["sudo", "iptables", "-D", "INPUT", "-p", "tcp", "--dport", "22", "-j", "ACCEPT"], ignore_errors=True)
    run_cmd(["sudo", "iptables", "-A", "INPUT", "-p", "tcp", "--dport", "22", "-j", "ACCEPT"], ignore_errors=False)

    RESTRICTED_ACCESS = False
    logger.warning("Baseline firewall restored.")

def restrict_port_22():
    global RESTRICTED_ACCESS
    if RESTRICTED_ACCESS:
        return

    logger.info("Restricting SSH access to 10.x.x.x only...")

    # Clean existing rules first
    restore_baseline()

    # Add restricted mode rules
    run_cmd(["sudo", "iptables", "-D", "INPUT", "-p", "tcp", "--dport", "22", "-j", "ACCEPT"], ignore_errors=True)
    run_cmd(["sudo", "iptables", "-A", "INPUT", "-p", "tcp", "--dport", "22", "-s", "10.0.0.0/8", "-j", "ACCEPT"])
    run_cmd(["sudo", "iptables", "-A", "INPUT", "-p", "tcp", "--dport", "22", "-j", "REJECT"])

    RESTRICTED_ACCESS = True
    logger.info("SSH now restricted.")

def allow_port_22():
    if not RESTRICTED_ACCESS:
        return

    logger.info("Returning SSH to open mode...")
    restore_baseline()

def handle_self_destruct():
    logger.critical("Alert level 6 detected! Triggering self-destruct!")
    # subprocess.run(["bash", "suicide.sh", "--force"], check=True)

import requests

BLACKLIST_API = "https://core.security.luova.club/api/blacklist?text=True"

blocked_cache = set()

def sync_blacklist():
    global blocked_cache
    try:
        resp = requests.get(BLACKLIST_API, timeout=5)
        resp.raise_for_status()

        new_list = set(line.strip() for line in resp.text.splitlines() if line.strip())

        # Find new IPs to block
        to_block = new_list - blocked_cache

        for ip in to_block:
            logger.warning(f"Blocking IP {ip} from blacklist...")
            subprocess.run([
                "sudo", "iptables", "-A", "INPUT", "-s", ip, "-j",
                "REJECT", "--reject-with", "icmp-port-unreachable"
            ], check=False)
        
        blocked_cache = new_list

    except Exception as e:
        logger.warning(f"Failed to sync blacklist: {e}")


# ----------------- Cleanup on exit -----------------
def cleanup_on_exit(*args):
    logger.warning("Cleanup triggered...")
    if not RESTRICTED_ACCESS:
        restore_baseline() # We shouldnt restore to baseline every time.

# Register cleanup handlers
atexit.register(cleanup_on_exit)
signal.signal(signal.SIGTERM, cleanup_on_exit)
signal.signal(signal.SIGINT, cleanup_on_exit)

# ----------------- Fetch Alert Level -----------------
async def fetch_alert_level(session):
    try:
        async with session.get(SECURE_API, timeout=5) as resp:
            resp.raise_for_status()
            return int((await resp.json()).get("alert_level", 0))
    except Exception as e:
        logger.warning(f"Failed to fetch alert level: {e}")
        return None

# ----------------- Main Loop -----------------
async def monitor_loop():
    alert_level = 0

    async with aiohttp.ClientSession() as session:
        while True:
            # --- FETCH ALERT LEVEL ---
            new_level = await fetch_alert_level(session)
            if new_level is not None:
                alert_level = new_level

            # --- HANDLE STATE ---
            if alert_level >= ALERT_LEVEL_SELF_DESTRUCT:
                handle_self_destruct()
                break

            elif alert_level >= 4:
                logger.warning(f"Cat detected! Alert level {alert_level}")
                restrict_port_22()
                sleep_time = CHECK_INTERVAL_CAT
            else:
                logger.info(f"No cat detected. Alert level {alert_level}")
                allow_port_22()
                sleep_time = CHECK_INTERVAL_NO_CAT

            # --- SYNC BLACKLIST EVERY LOOP ---
            sync_blacklist()

            # --- SLEEP ---
            await asyncio.sleep(sleep_time)



# ----------------- Entrypoint -----------------
if __name__ == "__main__":
    try:
        asyncio.run(monitor_loop())
    except KeyboardInterrupt:
        logger.info("Script stopped manually.")
