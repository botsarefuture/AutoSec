import unittest
from unittest.mock import patch, mock_open, MagicMock
import os
import requests
from utils import (
    load_processed_hashes,
    save_processed_hashes,
    load_welcome,
    run_in,
    fetch_banned_ips,
    build_commands_for_banned_ips,
)

from var import HASH_FILE


class TestUtils(unittest.TestCase):

    @patch("builtins.open", new_callable=mock_open, read_data="hash1\nhash2\n")
    @patch("os.path.exists", return_value=True)
    def test_load_processed_hashes(self, mock_exists, mock_open):
        hashes = load_processed_hashes()
        self.assertEqual(hashes, ["hash1", "hash2"])

    @patch("builtins.open", new_callable=mock_open)
    def test_save_processed_hashes(self, mock_open):
        hashes = ["hash1", "hash2"]
        save_processed_hashes(hashes)
        mock_open.assert_called_once_with(HASH_FILE, "w")
        mock_open().write.assert_any_call("hash1\n")
        mock_open().write.assert_any_call("hash2\n")

    @patch("builtins.open", new_callable=mock_open, read_data="Welcome to AutoSec!")
    def test_load_welcome(self, mock_open):
        welcome_message = load_welcome()
        self.assertEqual(welcome_message, "Welcome to AutoSec!")

    @patch("os.system")
    @patch("os.makedirs")
    @patch("os.path.exists", return_value=False)
    @patch("os.walk", return_value=[("/var/log/", [], ["auth.log.gz", "auth.log"])])
    def test_run_in(self, mock_walk, mock_exists, mock_makedirs, mock_system):
        run_in()
        mock_makedirs.assert_called_once_with("/etc/AutoSec/temp")
        mock_system.assert_any_call(
            "gunzip -c /var/log/auth.log.gz > /etc/AutoSec/temp/auth.log"
        )
        mock_system.assert_any_call(
            "python3 /etc/AutoSec/AutoSec/index.py -l /etc/AutoSec/temp/auth.log"
        )
        mock_system.assert_any_call(
            "python3 /etc/AutoSec/AutoSec/index.py -l /var/log/auth.log"
        )

    @patch("requests.get")
    def test_fetch_banned_ips(self, mock_get):
        mock_get.side_effect = [
            MagicMock(text="192.168.0.1\n192.168.0.2"),
            MagicMock(text="192.168.0.3\n192.168.0.4"),
        ]
        banned_ips, unbanned_ips = fetch_banned_ips()
        self.assertEqual(banned_ips, ["192.168.0.1", "192.168.0.2"])
        self.assertEqual(unbanned_ips, ["192.168.0.3", "192.168.0.4"])

    def test_build_commands_for_banned_ips(self):
        banned_ips = ["192.168.0.1", "192.168.0.2"]
        unbanned_ips = ["192.168.0.3", "192.168.0.4"]
        ban_commands, unban_commands = build_commands_for_banned_ips(
            banned_ips, unbanned_ips
        )
        self.assertEqual(
            ban_commands,
            [
                "sudo iptables -A INPUT -s 192.168.0.1 -j DROP",
                "sudo iptables -A INPUT -s 192.168.0.2 -j DROP",
            ],
        )
        self.assertEqual(
            unban_commands,
            [
                "sudo iptables -D INPUT -s 192.168.0.3 -j DROP",
                "sudo iptables -D INPUT -s 192.168.0.4 -j DROP",
            ],
        )


if __name__ == "__main__":
    unittest.main()
