
import unittest
from datetime import datetime
from classes import ThreatLevel, LogType, LogEntry, AuthLogAnalyzer, PerIpCounter, BanAction, SuggestedAction
import hashlib

class TestThreatLevel(unittest.TestCase):
    def test_get_threat_level(self):
        self.assertEqual(ThreatLevel("failed_attempt").get_threat_level(), ThreatLevel.HIGH)
        self.assertEqual(ThreatLevel("invalid_user").get_threat_level(), ThreatLevel.MEDIUM)
        self.assertEqual(ThreatLevel("session_opened").get_threat_level(), ThreatLevel.NO_THREAT)
        self.assertEqual(ThreatLevel("unknown_type").get_threat_level(), ThreatLevel.UNKNOWN)

class TestLogType(unittest.TestCase):
    def test_get_type(self):
        self.assertEqual(LogType.get_type("Failed password"), LogType.FAILED_ATTEMPT)
        self.assertEqual(LogType.get_type("Invalid user"), LogType.INVALID_USER)
        self.assertEqual(LogType.get_type("session opened"), LogType.SESSION_OPENED)
        self.assertEqual(LogType.get_type("session closed"), LogType.SESSION_CLOSED)
        self.assertEqual(LogType.get_type("Accepted password"), LogType.SUCCESSFUL_LOGIN)
        self.assertEqual(LogType.get_type("Unknown message"), LogType.UNKNOWN)

class TestLogEntry(unittest.TestCase):
    def test_log_entry(self):
        date = datetime.now()
        log_entry = LogEntry(date, "localhost", "sshd", "Failed password", "192.168.1.1")
        self.assertEqual(log_entry._date, date)
        self.assertEqual(log_entry._host, "localhost")
        self.assertEqual(log_entry._service, "sshd")
        self.assertEqual(log_entry._message, "Failed password")
        self.assertEqual(log_entry._ip_address, "192.168.1.1")
        self.assertEqual(log_entry._log_type, LogType.FAILED_ATTEMPT)
        self.assertEqual(log_entry._threat_level, ThreatLevel.HIGH)

class TestAuthLogAnalyzer(unittest.TestCase):
    def test_identify_log_type(self):
        analyzer = AuthLogAnalyzer("dummy.log")
        self.assertEqual(analyzer._identify_log_type("Failed password"), LogType.FAILED_ATTEMPT)

    def test_hash_line(self):
        analyzer = AuthLogAnalyzer("dummy.log")
        self.assertEqual(analyzer._hash_line("test line"), hashlib.sha256("test line".encode()).hexdigest())

class TestPerIpCounter(unittest.TestCase):
    def test_count_requests_per_ip(self):
        log_data = [
            LogEntry(datetime.now(), "localhost", "sshd", "Failed password", "192.168.1.1").to_dict(),
            LogEntry(datetime.now(), "localhost", "sshd", "Invalid user", "192.168.1.1").to_dict(),
        ]
        counter = PerIpCounter(log_data)
        result = counter.count_requests_per_ip()
        self.assertEqual(result["192.168.1.1"]["total_requests"], 2)
        self.assertEqual(result["192.168.1.1"]["threat_levels"][ThreatLevel.HIGH], 1)
        self.assertEqual(result["192.168.1.1"]["threat_levels"][ThreatLevel.MEDIUM], 1)

class TestBanAction(unittest.TestCase):
    def test_build_command(self):
        ban_action = BanAction("192.168.1.1", 10)
        self.assertIn("iptables -A INPUT -s 192.168.1.1 -j DROP", ban_action.build_command())

class TestSuggestedAction(unittest.TestCase):
    def test_build_command(self):
        action = SuggestedAction("ban", 10)
        self.assertIn("iptables -A INPUT -s 192.168.1.1 -j DROP", action.build_command("192.168.1.1"))

if __name__ == "__main__":
    unittest.main()