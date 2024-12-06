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

from config import MAX_FAILED_PER_TYPE, ACTIONS_PER_THREAT_LEVEL_PER_TYPE as ACC_
from tqdm import tqdm

from argparse import ArgumentParser
from argcomplete import autocomplete

import aiohttp
import asyncio
import hashlib

logging.basicConfig(level=logging.INFO)

from var import COMMANDS, PROCESSED_IPS, PROCESSED_LINES
from utils import load_processed_hashes, save_processed_hashes, load_welcome

PROCESSED_LINES = load_processed_hashes()
WELCOME = load_welcome()


class ThreatLevel:
    """
    Detects threat level by log type.
    """

    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    NO_THREAT = "no_threat"
    UNKNOWN = "unknown"

    def __init__(self, log_type):
        self._log_type = log_type

    def get_threat_level(self):
        """
        Determines the threat level based on the log type.

        Returns
        -------
        str
            The threat level (e.g., 'high', 'medium', etc.).
        """
        if self._log_type == "failed_attempt":
            return ThreatLevel.HIGH
        elif self._log_type == "invalid_user":
            return ThreatLevel.MEDIUM
        elif self._log_type in ["session_opened", "session_closed", "successful_login"]:
            return ThreatLevel.NO_THREAT
        else:
            return ThreatLevel.UNKNOWN


class LogType:
    """
    Enum representing the type of log entry.
    """

    FAILED_ATTEMPT = "failed_attempt"
    INVALID_USER = "invalid_user"
    SESSION_OPENED = "session_opened"
    SESSION_CLOSED = "session_closed"
    SUCCESSFUL_LOGIN = "successful_login"
    UNKNOWN = "unknown"

    @staticmethod
    def get_type(message):
        """
        Identifies the type of log entry based on the message.

        Parameters
        ----------
        message : str
            The message part of the log entry.

        Returns
        -------
        str
            The type of log entry (e.g., 'failed_attempt', 'session_opened', etc.).
        """
        if "Failed password" in message:
            return LogType.FAILED_ATTEMPT
        elif "Invalid user" in message:
            return LogType.INVALID_USER
        elif "session opened" in message:
            return LogType.SESSION_OPENED
        elif "session closed" in message:
            return LogType.SESSION_CLOSED
        elif "Accepted password" in message:
            return LogType.SUCCESSFUL_LOGIN
        else:
            return LogType.UNKNOWN

class LogEntry:
    """
    Represents a log entry.
    """

    def __init__(self, date, host, service, message, ip_address):
        self._date = date
        self._host = host
        self._service = service
        self._message = message
        self._ip_address = ip_address
        self._log_type = LogType.get_type(message)
        self._threat_level = ThreatLevel(self._log_type).get_threat_level()

    def __str__(self):
        """
        Returns a string representation of the log entry.
        """
        return f"Log Entry: {self._date} {self._host} {self._service} {self._message} {self._ip_address} {self._log_type} {self._threat_level}"

    def __repr__(self):
        """
        Returns a string representation of the log entry.
        """
        return self.__str__()

    def __dict__(self):
        return self.to_dict()

    def __getitem__(self, key):
        return self.to_dict()[key]

    def get(self, key, default=None):
        return self.to_dict().get(key, default)

    def to_dict(self):
        """
        Converts the log entry to a dictionary.

        Returns
        -------
        dict
            A dictionary representation of the log entry.
        """
        return {
            "date": str(self._date),
            "host": self._host,
            "service": self._service,
            "message": self._message,
            "ip_address": self._ip_address,
            "log_type": self._log_type,
            "threat_level": self._threat_level,
        }


class AuthLogAnalyzer:
    """
    Analyzes authentication logs.

    Attributes
    ----------
    log_file : str
        Path to the log file to be analyzed.

    Methods
    -------
    parse_log():
        Parses the log file and returns a list of log entries.
    """

    def __init__(self, log_file):
        """
        Parameters
        ----------
        log_file : str
            Path to the log file to be analyzed.
        """
        self._log_file = log_file

    def _identify_log_type(self, message):
        """
        Identifies the type of log entry based on the message.

        Parameters
        ----------
        message : str
            The message part of the log entry.

        Returns
        -------
        str
            The type of log entry (e.g., 'failed_attempt', 'session_opened', etc.).
        """
        return LogType.get_type(message)

    def _hash_line(self, line):
        """
        Generates a hash for a given line.

        Parameters
        ----------
        line : str
            The line to hash.

        Returns
        -------
        str
            The hash of the line.
        """
        return hashlib.sha256(line.encode()).hexdigest()

    def parse_log(self):
        """
        Parses the log file and returns a list of log entries.

        Returns
        -------
        list of dict
            A list of dictionaries where each dictionary represents a log entry.
        """
        log_entries = []
        logging.info(f"Opening log file: {self._log_file}")
        with open(self._log_file, "r") as file:
            for line in file:
                log_entry = self._parse_line(line)
                if log_entry:
                    log_entries.append(log_entry)
                    logging.debug(f"Parsed log entry: {log_entry}")
        logging.info(f"Finished parsing log file: {self._log_file}")
        save_processed_hashes(PROCESSED_LINES)
        return log_entries

    def _parse_line(self, line):
        """
        Parses a single line of the log file.

        Parameters
        ----------
        line : str
            A single line from the log file.

        Returns
        -------
        dict or None
            A dictionary representing the log entry, or None if the line could not be parsed.
        """
        line_hash = self._hash_line(line)
        if line_hash in PROCESSED_LINES:
            logging.debug(f"Line already processed: {line.strip()}")
            return None
        PROCESSED_LINES.append(line_hash)
        patterns = [
            r"(?P<date>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+\+\d{2}:\d{2}) (?P<host>\S+) (?P<service>\S+)(?:\[\d+\])?: (?P<message>.+)",
            r"(?P<date>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}) (?P<host>\S+) (?P<service>\S+)(?:\[\d+\])?: (?P<message>.+)",
        ]

        for pattern in patterns:
            match = re.match(pattern, line)
            if match:
                date_str = match.group("date")
                try:
                    if "-" in date_str:
                        date = datetime.strptime(date_str, "%Y-%m-%dT%H:%M:%S.%f%z")
                    else:
                        date = datetime.strptime(date_str, "%b %d %H:%M:%S")
                        date = date.replace(year=datetime.now().year)
                except ValueError as e:
                    logging.warning(f"Failed to parse date: {date_str} with error: {e}")
                    continue

                message = match.group("message")
                ip_pattern = r"(\d{1,3}\.){3}\d{1,3}"
                ip_match = re.search(ip_pattern, message)
                ip_address = ip_match.group(0) if ip_match else None
                logging.debug(f"Matched log entry: {match.groupdict()}")
                return LogEntry(
                    date,
                    match.group("host"),
                    match.group("service"),
                    message,
                    ip_address,
                )
        logging.warning(f"Failed to parse line: {line.strip()}")
        return None

    def filter_high_medium_threats(self, log_entries):
        """
        Filters log entries to include only those with high or medium threat levels.

        Parameters
        ----------
        log_entries : list of dict
            A list of dictionaries where each dictionary represents a log entry.

        Returns
        -------
        list of dict
            A list of dictionaries with high or medium threat levels.
        """
        return [
            entry
            for entry in log_entries
            if entry["threat_level"] in (ThreatLevel.HIGH, ThreatLevel.MEDIUM)
        ]

    def filter_by_threat_levels(self, log_entries, threat_levels):
        """
        Filters log entries to include only those with specified threat levels.

        Parameters
        ----------
        log_entries : list of dict
            A list of dictionaries where each dictionary represents a log entry.
        threat_levels : list of str
            A list of threat levels to filter by (e.g., ['high', 'medium']).

        Returns
        -------
        list of dict
            A list of dictionaries with the specified threat levels.
        """
        return [
            entry for entry in log_entries if entry["threat_level"] in threat_levels
        ]


class PerIpCounter:
    """
    Class for counting the number of requests per IP and differentiating threat levels and log types.

    Attributes
    ----------
    log_data : list
        The log data to be analyzed.
    """

    def __init__(self, log_data):
        """
        Initialize the PerIpCounter with log data.

        Parameters
        ----------
        log_data : list
            The log data to be analyzed.
        """
        self._log_data = log_data

    def count_requests_per_ip(self):
        """
        Count the number of requests per IP and differentiate threat levels and log types.

        Returns
        -------
        dict
            A dictionary containing the number of requests per IP, threat levels, and log types.
        """
        requests_per_ip = {}
        for log_entry in self._log_data:

            ip_address = log_entry["ip_address"]
            threat_level = log_entry.get("threat_level", "unknown")
            log_type = log_entry.get("log_type", "unknown")

            if ip_address not in requests_per_ip:
                requests_per_ip[ip_address] = {
                    "total_requests": 0,
                    "threat_levels": {},
                    "log_types": {},
                }

            requests_per_ip[ip_address]["total_requests"] += 1

            if threat_level in requests_per_ip[ip_address]["threat_levels"]:
                requests_per_ip[ip_address]["threat_levels"][threat_level] += 1
            else:
                requests_per_ip[ip_address]["threat_levels"][threat_level] = 1

            if log_type in requests_per_ip[ip_address]["log_types"]:
                requests_per_ip[ip_address]["log_types"][log_type] += 1
            else:
                requests_per_ip[ip_address]["log_types"][log_type] = 1

        return requests_per_ip


class BanAction:
    """
    Suggests a ban action based on log analysis.

    Attributes
    ----------
    ip_address : str
        The IP address to ban.
    duration : int
        The duration of the ban in minutes.
    """

    def __init__(self, ip_address, duration=0):
        """
        Parameters
        ----------
        ip_address : str
            The IP address to ban.
        duration : int, optional
            The duration of the ban in minutes (default is 0, which means permanent).
        """
        self._ip_address = ip_address
        self._duration = duration

    def build_command(self):
        """
        Builds the iptables command for banning the IP address.

        Returns
        -------
        str
            The iptables command to execute.
        """
        if self._duration > 0:
            return (
                f"iptables -A INPUT -s {self._ip_address} -j DROP && "
                f"echo 'iptables -D INPUT -s {self._ip_address} -j DROP' | at now + {self._duration} minute"
            )
        else:
            return f"iptables -A INPUT -s {self._ip_address} -j DROP"


class SuggestedAction:
    """
    Suggested actions based on log analysis.

    Attributes
    ----------
    BAN : str
        Action to ban the IP.
    ALERT : str
        Action to alert the administrator.
    LOG : str
        Action to log the event.
    NO_ACTION : str
        No action required.
    action : str
        The action to be taken.
    """

    BAN = "ban"
    BLOCK = "block"
    ALERT = "alert"
    LOG = "log"
    NO_ACTION = "no_action"

    ACT_NUMS = {BAN: 5, BLOCK: 4, ALERT: 3, LOG: 2, NO_ACTION: 1}

    def __init__(self, action, duration=0):
        """
        Parameters
        ----------
        action : str
            The action to be taken.
        duration : int
            The duration of the action in minutes.
            If 0, the action is permanent.
        """
        if action.lower() in ["ban", "block"]:
            self._action = SuggestedAction.BAN
        elif action.lower() == "alert":
            self._action = SuggestedAction.ALERT
        elif action.lower() == "log":
            self._action = SuggestedAction.LOG
        else:
            self._action = SuggestedAction.NO_ACTION

        self._duration = duration

    def __str__(self):
        """
        Returns a string representation of the suggested action.
        """
        return self._action

    def build_command(self, ip_address):
        """
        Builds the iptables command based on the suggested action.

        Parameters
        ----------
        ip_address : str
            The IP address to apply the action to.

        Returns
        -------
        str
            The iptables command to execute.
        """
        if self._action == SuggestedAction.BAN:
            return BanAction(ip_address, self._duration).build_command()

        elif self._action == SuggestedAction.ALERT:
            return f"echo 'Alert: Suspicious activity from {ip_address}'"

        elif self._action == SuggestedAction.LOG:
            return f"iptables -A INPUT -s {ip_address} -j LOG --log-prefix 'Suspicious activity: '"

        else:
            return "echo 'No action required'"

    def __eq__(self, value: object) -> bool:
        return (
            SuggestedAction.ACT_NUMS[self._action]
            == SuggestedAction.ACT_NUMS[value._action]
        )

    def __lt__(self, value: object) -> bool:
        return (
            SuggestedAction.ACT_NUMS[self._action]
            < SuggestedAction.ACT_NUMS[value._action]
        )

    def __gt__(self, value: object) -> bool:
        return (
            SuggestedAction.ACT_NUMS[self._action]
            > SuggestedAction.ACT_NUMS[value._action]
        )

    def __le__(self, value: object) -> bool:
        return (
            SuggestedAction.ACT_NUMS[self._action]
            <= SuggestedAction.ACT_NUMS[value._action]
        )

    def __ge__(self, value: object) -> bool:
        return (
            SuggestedAction.ACT_NUMS[self._action]
            >= SuggestedAction.ACT_NUMS[value._action]
        )


class CentralServerAPI:
    def __init__(self, url="https://core.security.luova.club"):
        self.url = url

    async def report_event(self, event, session, retries=3):
        """
        Reports an event to the central monitoring system.

        Parameters
        ----------
        event : dict
            The event data to report.
        session : aiohttp.ClientSession
            The aiohttp session to use for the request.
        retries : int, optional
            The number of retries in case of failure (default is 3).

        Returns
        -------
        dict or None
            The response from the API, or None if the request failed.
        """
        try:
            if isinstance(event, LogEntry):
                event = event.to_dict()

            async with session.post(f"{self.url}/api/report", json=event) as response:
                response.raise_for_status()
                return await response.json()

        except aiohttp.ClientError as e:
            logging.error(f"Failed to report event to central server: {e}")
            if retries == 0:
                logging.error("Max retries exceeded. Aborting.")
                return None

            # Try again
            await asyncio.sleep(1)
            return await self.report_event(event, session, retries - 1)

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
        tasks = [
            logging_central.report_event(event, session) for event in events
        ]
        for future in tqdm(
            asyncio.as_completed(tasks),
            total=len(tasks),
            desc="Reporting events",
            unit="event",
        ):
            await future

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
    if args.auto_threads:
        return os.cpu_count()  # Use the maximum number of CPU cores available.
    return args.threads if args.threads else 10  # Default to 10 threads if not specified.

def main():
    """
    Main function to start the log analysis.
    """
    
    args = init_args()  # Initialize command-line arguments

    logging_central = initialize_logging(args)

    logging.info("Starting log analysis")
    log_analyzer = AuthLogAnalyzer(args.logfile)

    logging.info("Parsing log entries")
    log_entries = log_analyzer.parse_log()

    if MODE == "black":
        logging.info(
            "Running in black mode. Reporting all events to central monitoring system."
        )
        asyncio.run(report_events_async(log_entries, logging_central, get_amount_of_threads(args)))
        logging.debug("All events reported to central monitoring system.")

    selected_threat_levels = [
        ThreatLevel.HIGH,
        ThreatLevel.MEDIUM,
    ]

    logging.debug(f"Selected threat levels: {selected_threat_levels}")

    filtered_entries = log_analyzer.filter_by_threat_levels(
        log_entries, selected_threat_levels
    )

    logging.debug("Done filtering log entries.")

    if REPORTING_ENABLED:
        logging.info("Reporting filtered events to central monitoring system.")
        asyncio.run(report_events_async(filtered_entries, logging_central, get_amount_of_threads(args)))
        logging.debug("Filtered events reported to central monitoring system.")

    logging.debug("Counting requests per IP")
    per_ip_counter = PerIpCounter(filtered_entries)

    logging.debug("Done counting requests per IP.")

    MAX_FAILS = MAX_FAILED_PER_TYPE[MODE]
    ACTIONS_PER_THREAT_LEVEL_PER_TYPE = ACC_[MODE]

    print("Per IP counter:")
    ii = per_ip_counter.count_requests_per_ip()
    for item, value in ii.items():
        if item in PROCESSED_IPS:
            continue

        highest_threat_level = ThreatLevel.UNKNOWN
        highest_saction = SuggestedAction(SuggestedAction.NO_ACTION)

        for item1, value1 in value["log_types"].items():
            if value1 > MAX_FAILS[item1]:
                highest_saction = select_highest_action_from_threat(ACTIONS_PER_THREAT_LEVEL_PER_TYPE, highest_saction, item1)

        COMMANDS.append(highest_saction.build_command(item))
        PROCESSED_IPS.append(item)

    if len(COMMANDS) > 0 or SAVE_EMPTY:
        write_commands_to_file(args)

    else:
        logging.warning("No commands to write.")
        logging.debug("If you want to save an empty file, use the --empty-save flag.")

    logging.info("Finished log analysis.")

def write_commands_to_file(args):
    if len(COMMANDS) > 0:
        logging.info(f"Writing {len(COMMANDS)} commands to 'commands.sh' file.")

    elif len(COMMANDS) == 0 and SAVE_EMPTY:
        logging.warning("No commands to write, but saving empty file.")

    with open("commands.sh", "w") as file:
        for command in COMMANDS:
            file.write(f"{command}\n")

    if args.autoexec:
        logging.info("Executing commands from 'commands.sh' file.")
        import subprocess

        subprocess.run(["bash", "commands.sh"])

def select_highest_action_from_threat(ACTIONS_PER_THREAT_LEVEL_PER_TYPE, highest_saction, item1):
    saction = SuggestedAction(
                    ACTIONS_PER_THREAT_LEVEL_PER_TYPE[item1]["action"],
                    ACTIONS_PER_THREAT_LEVEL_PER_TYPE[item1]["duration"],
                )

    update_highest_action(highest_saction, saction)

    select_highest_action(highest_saction, saction)

    highest_saction = (
                    saction if saction > highest_saction else highest_saction
                )
    
    return highest_saction

def update_highest_action(highest_saction, saction):
    highest_threat_level = (
                    ThreatLevel.HIGH
                    if saction > highest_saction
                    else highest_threat_level
                )

def select_highest_action(highest_saction, saction):
    if (
                    saction._action == highest_saction._action
                ):  # if the action is the same, choose the one with the highest duration
        if (
                        saction._duration > highest_saction._duration
                    ):  # if the duration is higher, choose the new action
            highest_saction = saction

def initialize_logging(args):
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    global MODE
    MODE = args.mode

    global SAVE_EMPTY
    SAVE_EMPTY = args.empty_save

    global REPORTING_ENABLED
    if MODE == "black":
        REPORTING_ENABLED = True

        if args.disable_reporting:
            logging.warning(
                "Running in black mode. Enabling central logging forcefully"
            )

    else:
        REPORTING_ENABLED = args.disable_reporting == False

    # Enable reporting if running in black mode
    # This is to ensure that all events are reported to the central monitoring system

    if REPORTING_ENABLED:
        logging.info("Reporting to central monitoring system is enabled.")
        logging_central = CentralServerAPI()

    else:
        if MODE == "black":
            logging.warning(
                "Running in black mode. Enabling central logging forcefully."
            )

            REPORTING_ENABLED = True
            logging_central = CentralServerAPI()

        else:
            logging.critical("Reporting to central monitoring system is disabled.")
            logging_central = None
    return logging_central

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
        "-m",
        "--mode",
        type=str,
        choices=["green", "yellow", "red", "black"],
        default="green",
        help="Mode of the system, e.g., 'green', 'yellow', 'red', 'black'\n Only run black mode if you know what you are doing.",
    )

    parser.add_argument(
        "--disable-reporting",
        action="store_true",
        help="Disable reporting to central monitoring system (default: False)",
        default=False,
    )

    parser.add_argument(
        "--empty-save",
        action="store_true",
        help="Save commands even if there are no commands to run (default: False)",
        default=False,
    )

    parser.add_argument(
        "-a",
        "--autoexec",
        action="store_true",
        help="Automatically execute the commands after writing them to the file.",
    )
    
    parser.add_argument(
        "-t",
        "--threads",
        type=int,
        default=10,
        help="Number of threads to use for reporting events (default is 10)."
    )
    
    # Enable experimental features
    parser.add_argument(
        "--auto-threads",
        action="store_true",
        help="Automatically determine the number of threads to use for reporting events.",
    )
    
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output.")
    
    autocomplete(parser)

    args = parser.parse_args()
    return args

if __name__ == "__main__":
    main()