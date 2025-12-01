"""
Ultra-light AutoSec
Optimized for minimal CPU & IO load
© 2024–2025 Verso Vuorenmaa, MIT
"""

import os
import re
import asyncio
import aiohttp
import logging
import time
import subprocess
from datetime import datetime
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import threading
import sys

from config import ACTIONS_PER_THREAT_LEVEL_PER_TYPE
from config import MAX_FAILED_PER_TYPE, ACTIONS_PER_THREAT_LEVEL_PER_TYPE as ACC_
from var import COMMANDS, PROCESSED_IPS, MODE, Mode
from classes import (
    ThreatLevel,
    AuthLogAnalyzer,
    PerIpCounter,
    SuggestedAction,
    CentralServerAPI,
)

logging.basicConfig(level=logging.INFO)

LOGFILE = "/var/log/auth.log"
COMMANDS_FILE = "/etc/AutoSec/commands.sh"
CATGUARD = "/etc/AutoSec/AutoSec/catguard.py"

#############################################
#  LAUNCH CATGUARD SAFELY (ONCE)
#############################################

_catguard_started = False
def start_catguard_once():
    global _catguard_started
    if _catguard_started:
        return
    _catguard_started = True
    subprocess.Popen([sys.executable, CATGUARD], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    logging.info("CatGuard started.")


#############################################
#  BETTER: PROCESS ONLY NEW LINES
#############################################

class IncrementalAuthLog:
    """Reads only new log lines (tail -F optimized)"""

    def __init__(self, path):
        self.path = path
        self._seek = 0

    def get_new_lines(self):
        if not os.path.exists(self.path):
            return []

        with open(self.path, "r") as f:
            f.seek(self._seek)
            new = f.readlines()
            self._seek = f.tell()
        return new


#############################################
#  FILE WATCHER (LIGHTWEIGHT)
#############################################

class LogEvent(FileSystemEventHandler):
    def __init__(self, callback):
        self.callback = callback
    def on_modified(self, event):
        if event.src_path.endswith("auth.log"):
            self.callback()


#############################################
#  BATCH REPORTER TO CENTRAL SERVER
#############################################

class BatchReporter:
    def __init__(self, central, interval=1.0):
        self.central = central
        self.pending = []
        self.interval = interval
        self._task = None  # don't start yet

    def add(self, evt):
        self.pending.append(evt)
        # ensure async worker is running
        if self._task is None:
            loop = asyncio.get_event_loop()
            self._task = loop.create_task(self._worker())

    async def _worker(self):
        async with aiohttp.ClientSession() as session:
            while True:
                if self.pending:
                    batch = self.pending[:]
                    self.pending.clear()
                    tasks = [self.central.report_event(e, session) for e in batch]
                    await asyncio.gather(*tasks, return_exceptions=True)
                await asyncio.sleep(self.interval)


#############################################
#  OPTIMIZED MAIN ANALYSIS PIPELINE
#############################################

log_reader = IncrementalAuthLog(LOGFILE)
central = CentralServerAPI()
reporter = BatchReporter(central)

def analyze_lines(lines):
    """Process ONLY the new log lines & generate actions."""
    if not lines:
        return

    # incrementally feed lines into analyzer
    analyzer = AuthLogAnalyzer(None)
    entries = []
    for line in lines:
        evt = analyzer._parse_line(line)
        if evt:
            entries.append(evt)


    # report all events
    for e in entries:
        reporter.add(e)

    # filter levels
    selected = [
        ThreatLevel.HIGH,
        ThreatLevel.MEDIUM,
        ThreatLevel.LOW,
        ThreatLevel.UNKNOWN
    ]

    filtered = [e for e in entries if e._threat_level in selected]

    # count per IP
    counter = PerIpCounter(filtered)
    data = counter.count_requests_per_ip()

    MAX_FAILS = MAX_FAILED_PER_TYPE[str(MODE)]
    MAP = ACTIONS_PER_THREAT_LEVEL_PER_TYPE[str(MODE)]

    updated = False

    for ip, v in data.items():
        if ip in PROCESSED_IPS:
            continue

        highest = SuggestedAction(SuggestedAction.NO_ACTION)

        for t, amount in v["log_types"].items():
            if amount > MAX_FAILS[t]:
                sa = SuggestedAction(
                    MAP[t]["action"],
                    MAP[t]["duration"],
                )
                if sa > highest:
                    highest = sa

        COMMANDS.append(highest.build_command(ip))
        PROCESSED_IPS.append(ip)
        updated = True

    # only write file if something changed
    if updated:
        write_commands()


#############################################
#  WRITE COMMANDS (ONLY WHEN CHANGED)
#############################################

def write_commands():
    with open(COMMANDS_FILE, "w") as f:
        f.write("#!/bin/bash\n")
        for cmd in COMMANDS:
            f.write(cmd + "\n")
    os.chmod(COMMANDS_FILE, 0o755)
    subprocess.run([COMMANDS_FILE])


#############################################
#  MAIN EVENT LOOP
#############################################

def start_watcher():
    observer = Observer()
    observer.schedule(LogEvent(on_log_changed), "/var/log", recursive=False)
    observer.start()
    return observer

def on_log_changed():
    new = log_reader.get_new_lines()
    analyze_lines(new)

def start_async_loop():
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    threading.Thread(target=loop.run_forever, daemon=True).start()

#############################################
#  ENTRY
#############################################

def run():
    start_async_loop()  # <-- NEW
    start_catguard_once()
    # process existing tail once
    on_log_changed()

    obs = start_watcher()
    try:
        while True:
            time.sleep(0.1)
    except KeyboardInterrupt:
        obs.stop()
        obs.join()


if __name__ == "__main__":
    run()
