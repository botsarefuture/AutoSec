"""
This script analyzes authentication logs and suggests actions based on the threat level and system mode. It reads authentication logs from a file, parses the log entries, and filters them based on the threat level. The script counts the number of requests per IP and differentiates threat levels and log types. Based on the system mode and log entries, it suggests actions for each IP address. The suggested actions are written to a shell script file that can be executed.

The script also reports events to a central monitoring system and logs events for future reference.

(C) 2024 by Verso Vuorenmaa

The code is released under the MIT license.

Suggestions and feedback for improvement are welcome.
"""

import os
import re
from datetime import datetime
import logging
import subprocess
import threading


from config import MAX_FAILED_PER_TYPE, ACTIONS_PER_THREAT_LEVEL_PER_TYPE as ACC_
from tqdm import tqdm
import time


from argparse import ArgumentParser
from argcomplete import autocomplete

import aiohttp
import asyncio
import hashlib

logging.basicConfig(level=logging.INFO)

from var import COMMANDS, PROCESSED_IPS, SERVER_IP, MODE, Mode
from utils import load_welcome, run_in as load_in, run_car
import sys

from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

from classes import (
    ThreatLevel,
    AuthLogAnalyzer,
    PerIpCounter,
    BanAction,
    SuggestedAction,
    CentralServerAPI,
)

WELCOME = load_welcome()

# Use the current Python interpreter (venv or system)
python_executable = sys.executable

subprocess.Popen([python_executable, "/etc/AutoSec/AutoSec/catguard.py"])

class AuthLogHandler(FileSystemEventHandler):
    def __init__(self, logfile):
        super().__init__()
        self.logfile = logfile

    def on_modified(self, event):
        if event.src_path == self.logfile:
            logging.info(f"{self.logfile} modified! Running analysis...")
            main()  # call your main function

def watch_logfile(logfile):
    event_handler = AuthLogHandler(logfile)
    observer = Observer()
    observer.schedule(event_handler, path=os.path.dirname(logfile), recursive=False)
    observer.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()


async def report_events_async(events, logging_central, max_workers=10):
    """
    Reports events to the central monitoring system using asynchronous requests.

    Parameters
    ----------
    events : list
        List of events to report.
    logging_central : CentralServerAPI
        The central server API instance.
    max_workers : int, optional
        The maximum number of concurrent requests (default is 10).

    Returns
    -------
    None
    """
    async with aiohttp.ClientSession() as session:
        tasks = [logging_central.report_event(event, session) for event in events]
        for future in tqdm(
            asyncio.as_completed(tasks),
            total=len(tasks),
            desc="Reporting events",
            unit="event",
        ):
            await future


def run_car_hourly():
    """Runs run_car() every hour in a loop."""
    while True:
        try:
            run_car()
            logging.warning("Banned IPs updated from the central server.")
            logging.info("Read more at: https://core.security.luova.club/")
        except Exception as e:
            logging.error(f"Error running run_car: {e}")
        time.sleep(3600)  # 1 hour



def main():
    """
    Main function to start the log analysis.
    """
    # Start the thread
    thread = threading.Thread(target=run_car_hourly, daemon=True)
    thread.start()

    logging.warning("Banned ips by order from the central server.")
    logging.info("Read more at: https://core.security.luova.club/")

    args = init_args()  # Initialize command-line arguments

    logging_central = initialize_logging(args)

    logging.info("Starting log analysis")
    log_analyzer = AuthLogAnalyzer(args.logfile)

    logging.info("Parsing log entries")
    log_entries = log_analyzer.parse_log()

    if MODE == Mode.BLACK or MODE == Mode.DARKRED:
        logging.info(
            "Running in black mode. Reporting all events to central monitoring system."
        )
        asyncio.run(
            report_events_async(
                log_entries, logging_central, get_amount_of_threads(args)
            )
        )
        logging.debug("All events reported to central monitoring system.")

    selected_threat_levels = [
        ThreatLevel.HIGH,
        ThreatLevel.MEDIUM,
        ThreatLevel.LOW,
        ThreatLevel.UNKNOWN
    ] # New LCITSWG regulation needs all logs relayed to the selver.

    logging.debug(f"Selected threat levels: {selected_threat_levels}")

    filtered_entries = log_analyzer.filter_by_threat_levels(
        log_entries, selected_threat_levels
    )

    logging.debug("Done filtering log entries.")

    logging.info("Reporting filtered events to central monitoring system.")
    asyncio.run(
        report_events_async(
            filtered_entries, logging_central, get_amount_of_threads(args)
        )
    )
    logging.debug("Filtered events reported to central monitoring system.")

    logging.debug("Counting requests per IP")
    per_ip_counter = PerIpCounter(filtered_entries)

    logging.debug("Done counting requests per IP.")

    MAX_FAILS = MAX_FAILED_PER_TYPE[str(MODE)]
    ACTIONS_PER_THREAT_LEVEL_PER_TYPE = ACC_[str(MODE)]

    ii = per_ip_counter.count_requests_per_ip()
    for item, value in ii.items():
        if item in PROCESSED_IPS:
            continue

        highest_saction = SuggestedAction(SuggestedAction.NO_ACTION)

        for item1, value1 in value["log_types"].items():
            if value1 > MAX_FAILS[item1]:
                highest_saction = select_highest_action_from_threat(
                    ACTIONS_PER_THREAT_LEVEL_PER_TYPE, highest_saction, item1
                )

        COMMANDS.append(highest_saction.build_command(item))
        PROCESSED_IPS.append(item)

        write_commands_to_file(args)

    else:
        logging.warning("No commands to write.")
        logging.debug("If you want to save an empty file, use the --empty-save flag.")

    logging.info("Finished log analysis.")


def main_loop():
    """
    Main loop to run the log analysis every 5 minutes.
    """
    while True:
        main()
        time.sleep(300) # we want closer to real time stuff


def write_commands_to_file(args):
    if len(COMMANDS) == 0:
        logging.warning("No commands to write.")
        return

    logging.info(f"Writing {len(COMMANDS)} commands to 'commands.sh' file.")

    with open("commands.sh", "w") as file:
        for command in COMMANDS:
            file.write(f"{command}\n")

    if not args.disable_autoexec:
        logging.info("Executing commands from 'commands.sh' file.")
        subprocess.run(["bash", "commands.sh"])


def select_highest_action_from_threat(
    ACTIONS_PER_THREAT_LEVEL_PER_TYPE, highest_saction, item1
):
    saction = SuggestedAction(
        ACTIONS_PER_THREAT_LEVEL_PER_TYPE[item1]["action"],
        ACTIONS_PER_THREAT_LEVEL_PER_TYPE[item1]["duration"],
    )

    select_highest_action(highest_saction, saction)

    highest_saction = saction if saction > highest_saction else highest_saction

    return highest_saction


def select_highest_action(highest_saction, saction):
    if (
        saction._action == highest_saction._action
    ):  # if the action is the same, choose the one with the highest duration
        if (
            saction._duration > highest_saction._duration
        ):  # if the duration is higher, choose the new action
            highest_saction = saction
import os
import logging
from datetime import datetime, timedelta

LAST_RAN_FILE = "/etc/AutoSec/last_ran.txt"

def _load_last_ran():
    """Return datetime of last run, or None if never run."""
    if not os.path.exists(LAST_RAN_FILE):
        return None
    with open(LAST_RAN_FILE, "r") as f:
        try:
            return datetime.fromisoformat(f.read().strip())
        except ValueError:
            return None

def _update_last_ran():
    """Update last ran timestamp to now."""
    with open(LAST_RAN_FILE, "w") as f:
        f.write(datetime.now().isoformat())

def initialize_logging(args):
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
        
    else:
        logging.getLogger().setLevel(logging.WARNING)
        
    last_ran = _load_last_ran()
    run_in_needed = False

    # If auth.log is used and either never ran or ran over a week ago
    if args.logfile == "/var/log/auth.log":
        if not os.path.exists("/etc/AutoSec/processed"):
            run_in_needed = True
        elif not last_ran or datetime.now() - last_ran > timedelta(days=7):
            run_in_needed = True

    # Only run in for auth.log, skip custom files
    if run_in_needed:
        logging.warning(
            "Running the run in. This might take a while. Please do not CTRL+C."
        )
        load_in()
        _update_last_ran()
    elif args.logfile != "/var/log/auth.log":
        logging.debug("Custom log file specified. Skipping run in.")
    else:
        logging.debug("Run in has already been run recently. Skipping.")

    if not os.path.exists("/etc/AutoSec/commands.sh"):
        logging.debug("Creating commands.sh file.")
        with open("/etc/AutoSec/commands.sh", "w") as file:
            file.write("#!/bin/bash\n")
            file.write("# AutoSec commands\n")
            file.write("# This file contains the commands to execute based on the log analysis.\n")
            file.write("# Do not edit this file manually.\n\n")

    logging.info("Reporting to central monitoring system is enabled.")
    logging_central = CentralServerAPI()

    return logging_central


def get_amount_of_threads(args):
    """
    Determines the number of threads to use for reporting events.

    Parameters
    ----------
    args : argparse.Namespace
        The command-line arguments.

    Returns
    -------
    int
        The number of threads to use.
    """
    return args.threads if args.manual_threads else os.cpu_count()


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
    args = init_args()

    if args.single_run:
        logging.warning("Running in single run mode. This will not start the watchdog.")
        main()

    elif MODE == 0 or MODE == Mode.PINK:
        logging.info("Running in manual mode. Running main function every 5 minutes.")
        main_loop()

    else:
        logging.info(
            "Running in watch mode. Running main function once and starting the watchdog."
        )
        main()
        logging.info("Main function ran once. Starting the watchdog.")
        initialize_logging(args)
        watch_logfile(args.logfile)
