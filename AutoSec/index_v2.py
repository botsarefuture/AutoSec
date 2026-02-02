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
import json
from datetime import datetime
from collections import deque
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
FAILED_EVENTS_FILE = "/etc/AutoSec/failed_events.jsonl"
MAX_FAILED_EVENTS = 5000
REPORT_INTERVAL = 1.2
MAX_BATCH = 100

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
    def __init__(self, central, loop, interval=REPORT_INTERVAL, max_batch=MAX_BATCH):
        self.central = central
        self.loop = loop
        self.interval = interval
        self.max_batch = max_batch
        self.queue = asyncio.Queue()
        self._failed = deque(maxlen=MAX_FAILED_EVENTS)
        self._worker_future = asyncio.run_coroutine_threadsafe(self._worker(), self.loop)

    def add(self, evt):
        try:
            asyncio.run_coroutine_threadsafe(self.queue.put(self._serialize_event(evt)), self.loop)
        except RuntimeError as exc:
            logging.error("Reporter loop not running: %s", exc)

    async def _worker(self):
        async with aiohttp.ClientSession() as session:
            await self._load_failed()
            while True:
                batch = []
                try:
                    evt = await asyncio.wait_for(self.queue.get(), timeout=self.interval)
                    batch.append(evt)
                except asyncio.TimeoutError:
                    pass

                while len(batch) < self.max_batch:
                    try:
                        batch.append(self.queue.get_nowait())
                    except asyncio.QueueEmpty:
                        break

                while self._failed and len(batch) < self.max_batch:
                    batch.append(self._failed.popleft())

                if batch:
                    results = await asyncio.gather(
                        *[self.central.report_event(e, session) for e in batch],
                        return_exceptions=True
                    )
                    if any(isinstance(r, Exception) or r is None for r in results):
                        for evt, res in zip(batch, results):
                            if isinstance(res, Exception) or res is None:
                                self._failed.append(evt)
                        await self._persist_failed()
                await asyncio.sleep(self.interval)

    async def _load_failed(self):
        if not os.path.exists(FAILED_EVENTS_FILE):
            return
        try:
            with open(FAILED_EVENTS_FILE, "r") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        self._failed.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
        except OSError as exc:
            logging.warning("Failed to load failed events: %s", exc)

    async def _persist_failed(self):
        if not self._failed:
            return
        try:
            os.makedirs(os.path.dirname(FAILED_EVENTS_FILE), exist_ok=True)
            with open(FAILED_EVENTS_FILE, "w") as f:
                for evt in list(self._failed)[-MAX_FAILED_EVENTS:]:
                    f.write(json.dumps(evt, ensure_ascii=True) + "\n")
        except OSError as exc:
            logging.warning("Failed to persist failed events: %s", exc)

    def _serialize_event(self, evt):
        if hasattr(evt, "to_dict"):
            return evt.to_dict()
        if isinstance(evt, dict):
            return evt
        return {"raw": str(evt)}


#############################################
#  OPTIMIZED MAIN ANALYSIS PIPELINE
#############################################

log_reader = IncrementalAuthLog(LOGFILE)
central = CentralServerAPI()
reporter = None
_last_change = 0.0

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
        if reporter:
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
    global _last_change
    now = time.time()
    if now - _last_change < 0.4:
        return
    _last_change = now
    new = log_reader.get_new_lines()
    analyze_lines(new)

def start_async_loop():
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    threading.Thread(target=loop.run_forever, daemon=True).start()
    return loop

#############################################
#  ENTRY
#############################################

def run():
    global reporter
    loop = start_async_loop()
    reporter = BatchReporter(central, loop)
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
