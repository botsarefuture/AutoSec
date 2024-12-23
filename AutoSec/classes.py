from datetime import datetime
import hashlib
import re
import logging
import aiohttp
import asyncio
import os
from var import HASH_FILE, SERVER_IP

from utils import save_processed_hashes, load_processed_hashes

PROCESSED_LINES = load_processed_hashes()


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
    last_position : int
        The last read position in the log file.

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
        self._last_position = 0

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
            file.seek(self._last_position)
            for line in file:
                log_entry = self._parse_line(line)
                if log_entry:
                    log_entries.append(log_entry)
                    logging.debug(f"Parsed log entry: {log_entry}")
                    
                    # Save the hash of the processed line
                    line_hash = self._hash_line(line)
                    PROCESSED_LINES.append(line_hash)
                    
            self._last_position = file.tell()
                    
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

            data = {
                'server_ip': SERVER_IP,
                **event}
            async with session.post(f"{self.url}/api/report", json=data) as response:
                response.raise_for_status()
                return await response.json()

        except aiohttp.ClientError as e:
            logging.error(f"Failed to report event to central server: {e}")
            if retries == 0:
                # save the event to a file, so it can be reported later
                with open("failed_events.log", "a") as file:
                    file.write(f"{event}\n")
                
                logging.error("Max retries exceeded. Aborting.")
                return None

            # Try again
            await asyncio.sleep(1)
            return await self.report_event(event, session, retries - 1)
