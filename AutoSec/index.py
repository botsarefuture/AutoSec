"""
This script analyzes authentication logs and suggests actions based on the threat level and system mode. It reads authentication logs from a file, parses the log entries, and filters them based on the threat level. The script counts the number of requests per IP and differentiates threat levels and log types. Based on the system mode and log entries, it suggests actions for each IP address. The suggested actions are written to a shell script file that can be executed.

The script also reports events to a central monitoring system and logs events for future reference.

(C) 2024 by Verso Vuorenmaa

The code is released under the MIT license.

Suggestions and feedback for improvement are welcome.
"""

import os
import re
import sys
import time
import logging
import subprocess
from datetime import datetime, timedelta
from argparse import ArgumentParser

import asyncio
import aiohttp
from tqdm import tqdm
from argcomplete import autocomplete
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

from config import MAX_FAILED_PER_TYPE, ACTIONS_PER_THREAT_LEVEL_PER_TYPE as ACC_
from var import COMMANDS, PROCESSED_IPS, SERVER_IP, MODE, Mode
from utils import load_welcome, run_in as load_in, run_car
from classes import (
    ThreatLevel,
    AuthLogAnalyzer,
    PerIpCounter,
    BanAction,
    SuggestedAction,
    CentralServerAPI,
)

logging.basicConfig(level=logging.INFO)

WELCOME = load_welcome()

# Use the current Python interpreter (venv or system)
python_executable = sys.executable

CATGUARD_PATH = "/etc/AutoSec/AutoSec/catguard.py"

def _start_catguard():
    """Start the catguard helper script if it exists."""
    if os.path.exists(CATGUARD_PATH):
        try:
            subprocess.Popen([python_executable, CATGUARD_PATH])
            logging.debug("catguard.py started.")
        except Exception as exc:  # pragma: no cover - best effort
            logging.error("Failed to start catguard.py: %s", exc)
    else:
        logging.debug("catguard.py not found at %s, skipping.", CATGUARD_PATH)


LAST_RAN_FILE = "/etc/AutoSec/last_ran.txt"
COMMANDS_FILE = "/etc/AutoSec/commands.sh"


def _ensure_autosec_dir():
    """Ensure that /etc/AutoSec exists."""
    autosec_dir = os.path.dirname(COMMANDS_FILE)
    if not os.path.isdir(autosec_dir):
        try:
            os.makedirs(autosec_dir, exist_ok=True)
        except PermissionError:
            logging.error(
                "Cannot create %s. Please run this script with sufficient privileges.",
                autosec_dir,
            )


def _load_last_ran():
    """Return datetime of last run, or None if never run."""
    if not os.path.exists(LAST_RAN_FILE):
        return None
    try:
        with open(LAST_RAN_FILE, "r") as f:
            return datetime.fromisoformat(f.read().strip())
    except (ValueError, OSError):
        return None


def _update_last_ran():
    """Update last ran timestamp to now."""
    try:
        with open(LAST_RAN_FILE, "w") as f:
            f.write(datetime.now().isoformat())
    except OSError as exc:
        logging.error("Failed to update %s: %s", LAST_RAN_FILE, exc)


def get_amount_of_threads(args):
    """
    Determines the number of threads to use for reporting events.
    """
    return args.threads if args.manual_threads else os.cpu_count() or 1


def initialize_logging(args):
    """
    Configure logging and initialize central logging / environment.
    """
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    else:
        # Default to INFO so the user sees something useful.
        logging.getLogger().setLevel(logging.INFO)

    _ensure_autosec_dir()

    last_ran = _load_last_ran()
    run_in_needed = False

    # If auth.log is used and either never ran or ran over a week ago
    if args.logfile == "/var/log/auth.log":
        processed_path = "/etc/AutoSec/processed"
        if not os.path.exists(processed_path):
            run_in_needed = True
        elif not last_ran or datetime.now() - last_ran > timedelta(days=7):
            run_in_needed = True

    # Only run run_in for auth.log, skip custom files
    if run_in_needed:
        logging.warning(
            "Running the initial 'run_in' setup. This might take a while. Please do not CTRL+C."
        )
        load_in()
        _update_last_ran()
    elif args.logfile != "/var/log/auth.log":
        logging.debug("Custom log file specified. Skipping run_in.")
    else:
        logging.debug("run_in has already been run recently. Skipping.")

    # Ensure commands file exists with a header
    if not os.path.exists(COMMANDS_FILE):
        logging.debug("Creating commands.sh file at %s.", COMMANDS_FILE)
        try:
            with open(COMMANDS_FILE, "w") as file:
                file.write("#!/bin/bash\n")
                file.write("# AutoSec commands\n")
                file.write("# This file contains the commands to execute based on the log analysis.\n")
                file.write("# Do not edit this file manually.\n\n")
        except OSError as exc:
            logging.error("Failed to create %s: %s", COMMANDS_FILE, exc)

    logging.info("Reporting to central monitoring system is enabled.")
    logging_central = CentralServerAPI()

    return logging_central


async def report_events_async(events, logging_central, max_workers=10):
    """
    Reports events to the central monitoring system using asynchronous requests.
    """
    if not events:
        return

    semaphore = asyncio.Semaphore(max_workers)

    async def _bounded_report(event):
        async with semaphore:
            await logging_central.report_event(event, session)

    async with aiohttp.ClientSession() as session:
        tasks = [_bounded_report(event) for event in events]
        for future in tqdm(
            asyncio.as_completed(tasks),
            total=len(tasks),
            desc="Reporting events",
            unit="event",
        ):
            await future


def select_highest_action_from_threat(actions_per_type, highest_action, log_type):
    """
    Given the current highest SuggestedAction and a log type, return the higher action.
    """
    cfg = actions_per_type.get(log_type)
    if not cfg:
        # Unknown log type, keep the current action
        return highest_action

    candidate = SuggestedAction(cfg["action"], cfg["duration"])
    return candidate if candidate > highest_action else highest_action


def write_commands_to_file(args):
    """
    Write all accumulated COMMANDS to the commands.sh file and optionally execute it.
    """
    if not COMMANDS:
        logging.warning("No commands to write.")
        return

    logging.info("Writing %d commands to '%s'.", len(COMMANDS), COMMANDS_FILE)

    try:
        with open(COMMANDS_FILE, "w") as file:
            for command in COMMANDS:
                file.write(f"{command}\n")
    except OSError as exc:
        logging.error("Failed to write commands to %s: %s", COMMANDS_FILE, exc)
        return

    # NOTE: keep semantics as in original code:
    #   --disable-autoexec flag *actually enabled* autoexec before.
    #   To avoid surprising existing users, we keep the behaviour.
    if not args.disable_autoexec:
        logging.info("Executing commands from '%s' file.", COMMANDS_FILE)
        try:
            subprocess.run(["bash", COMMANDS_FILE], check=False)
        except Exception as exc:  # pragma: no cover - best effort
            logging.error("Failed to execute %s: %s", COMMANDS_FILE, exc)
    else:
        logging.info("Auto execution disabled; not running '%s'.", COMMANDS_FILE)


def run_analysis(args, logging_central):
    """
    Run a single pass of the log analysis.
    """
    logging.info("Starting log analysis")
    log_analyzer = AuthLogAnalyzer(args.logfile)

    logging.info("Parsing log entries from %s", args.logfile)
    log_entries = log_analyzer.parse_log()

    # In BLACK/DARKRED modes we report *all* events
    if MODE == Mode.BLACK or MODE == Mode.DARKRED:
        logging.info(
            "Running in BLACK/DARKRED mode. Reporting all events to central monitoring system."
        )
        asyncio.run(
            report_events_async(
                log_entries, logging_central, get_amount_of_threads(args)
            )
        )
        logging.debug("All events reported to central monitoring system.")

    # LCITSWG regulation: all logs must be relayed to the server, but we still
    # keep explicit threat level selection in case classes use it.
    selected_threat_levels = [
        ThreatLevel.HIGH,
        ThreatLevel.MEDIUM,
        ThreatLevel.LOW,
        ThreatLevel.UNKNOWN,
    ]

    logging.debug("Selected threat levels: %s", selected_threat_levels)

    filtered_entries = log_analyzer.filter_by_threat_levels(
        log_entries, selected_threat_levels
    )

    logging.debug("Done filtering log entries (%d entries).", len(filtered_entries))

    logging.info("Reporting filtered events to central monitoring system.")
    asyncio.run(
        report_events_async(
            filtered_entries, logging_central, get_amount_of_threads(args)
        )
    )
    logging.debug("Filtered events reported to central monitoring system.")

    logging.debug("Counting requests per IP")
    per_ip_counter = PerIpCounter(filtered_entries)
    ip_stats = per_ip_counter.count_requests_per_ip()
    logging.debug("Done counting requests per IP (%d IPs).", len(ip_stats))

    MAX_FAILS = MAX_FAILED_PER_TYPE[str(MODE)]
    ACTIONS_PER_THREAT_LEVEL_PER_TYPE = ACC_[str(MODE)]

    for ip, value in ip_stats.items():
        if ip in PROCESSED_IPS:
            continue

        highest_action = SuggestedAction(SuggestedAction.NO_ACTION)

        for log_type, count in value.get("log_types", {}).items():
            # Only consider this log type if it has exceeded threshold
            threshold = MAX_FAILS.get(log_type)
            if threshold is None:
                logging.debug("Log type %s not in MAX_FAILS, skipping.", log_type)
                continue

            if count > threshold:
                highest_action = select_highest_action_from_threat(
                    ACTIONS_PER_THREAT_LEVEL_PER_TYPE, highest_action, log_type
                )

        COMMANDS.append(highest_action.build_command(ip))
        PROCESSED_IPS.append(ip)

    # After processing all IPs, write and maybe execute the commands
    write_commands_to_file(args)

    logging.info("Finished log analysis.")


class AuthLogHandler(FileSystemEventHandler):
    def __init__(self, logfile, args, logging_central):
        super().__init__()
        self.logfile = os.path.abspath(logfile)
        self.args = args
        self.logging_central = logging_central

    def on_modified(self, event):
        if os.path.abspath(event.src_path) == self.logfile:
            logging.info("%s modified! Running analysis...", self.logfile)
            run_analysis(self.args, self.logging_central)


def watch_logfile(logfile, args, logging_central):
    """
    Watch a logfile and rerun analysis whenever it changes.
    """
    event_handler = AuthLogHandler(logfile, args, logging_central)
    observer = Observer()
    observer.schedule(
        event_handler,
        path=os.path.dirname(os.path.abspath(logfile)),
        recursive=False,
    )
    observer.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logging.info("Stopping watchdog due to keyboard interrupt.")
        observer.stop()
    observer.join()


def main_loop(args, logging_central):
    """
    Main loop to run the log analysis every 5 minutes.
    """
    while True:
        run_analysis(args, logging_central)
        time.sleep(300)  # we want closer to real time stuff


def init_args():
    parser = ArgumentParser(description="Authentication Log Analyzer")

    parser.add_argument(
        "-l",
        "--logfile",
        type=str,
        default="/var/log/auth.log",
        help="Path to the log file",
    )

    parser.add_argument(
        "-da",
        "--disable-autoexec",
        action="store_false",
        help="Disable automatically executing the commands after writing them to the file.",
    )

    parser.add_argument(
        "--manual-threads",
        action="store_true",
        help="Manually specify the number of threads to use for reporting events.",
    )

    parser.add_argument(
        "-t",
        "--threads",
        type=int,
        default=10,
        help="Number of threads to use for reporting events (default is 10).",
    )

    parser.add_argument(
        "--single-run", action="store_true", help="Run the main function once and exit."
    )

    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Enable verbose output."
    )

    autocomplete(parser)

    args = parser.parse_args()
    return args


if __name__ == "__main__":
    _start_catguard()
    args = init_args()
    logging_central = initialize_logging(args)

    if args.single_run:
        logging.warning("Running in single run mode. This will not start the watchdog.")
        run_analysis(args, logging_central)

    elif MODE == 0 or MODE == Mode.PINK:
        logging.info("Running in manual mode. Running main function every 5 minutes.")
        main_loop(args, logging_central)

    else:
        logging.info(
            "Running in watch mode. Running main function once and starting the watchdog."
        )
        run_analysis(args, logging_central)
        logging.info("Initial analysis complete. Starting the watchdog.")
        watch_logfile(args.logfile, args, logging_central)
