import unittest
from unittest.mock import patch, MagicMock
import asyncio
from index import (
    main,
    report_events_async,
    get_amount_of_threads,
    init_args,
    write_commands_to_file,
)
import os


class TestAuthLogAnalyzer(unittest.TestCase):

    @patch("index.run_car")
    @patch("index.initialize_logging")
    @patch("index.AuthLogAnalyzer")
    @patch("index.asyncio.run")
    @patch("index.get_amount_of_threads")
    @patch("index.init_args")
    def test_main(
        self,
        mock_init_args,
        mock_get_amount_of_threads,
        mock_asyncio_run,
        mock_AuthLogAnalyzer,
        mock_initialize_logging,
        mock_run_car,
    ):
        mock_args = MagicMock()
        mock_args.logfile = "/var/log/auth.log"
        mock_args.single_run = True
        mock_init_args.return_value = mock_args
        mock_get_amount_of_threads.return_value = 10
        mock_log_analyzer = MagicMock()
        mock_AuthLogAnalyzer.return_value = mock_log_analyzer
        mock_log_analyzer.parse_log.return_value = []
        mock_log_analyzer.filter_by_threat_levels.return_value = []

        main()

        mock_run_car.assert_called_once()
        mock_initialize_logging.assert_called_once_with(mock_args)
        mock_AuthLogAnalyzer.assert_called_once_with(mock_args.logfile)
        mock_log_analyzer.parse_log.assert_called_once()
        mock_log_analyzer.filter_by_threat_levels.assert_called_once()
        mock_asyncio_run.assert_called()

    @patch("index.aiohttp.ClientSession")
    @patch("index.tqdm")
    def test_report_events_async(self, mock_tqdm, mock_ClientSession):
        mock_session = MagicMock()
        mock_ClientSession.return_value.__aenter__.return_value = mock_session
        mock_logging_central = MagicMock()
        events = ["event1", "event2"]
        mock_tqdm.asyncio.as_completed.return_value = [
            asyncio.Future(),
            asyncio.Future(),
        ]

        asyncio.run(report_events_async(events, mock_logging_central))

        mock_ClientSession.assert_called_once()
        mock_logging_central.report_event.assert_any_call("event1", mock_session)
        mock_logging_central.report_event.assert_any_call("event2", mock_session)

    def test_get_amount_of_threads(self):
        mock_args = MagicMock()
        mock_args.manual_threads = True
        mock_args.threads = 5
        self.assertEqual(get_amount_of_threads(mock_args), 5)

        mock_args.manual_threads = False
        self.assertEqual(get_amount_of_threads(mock_args), os.cpu_count())

    @patch("index.subprocess.run")
    @patch("builtins.open", new_callable=unittest.mock.mock_open)
    def test_write_commands_to_file(self, mock_open, mock_subprocess_run):
        mock_args = MagicMock()
        mock_args.disable_autoexec = False
        COMMANDS = ["command1", "command2"]

        with patch("index.COMMANDS", COMMANDS):
            write_commands_to_file(mock_args)

        mock_open.assert_called_once_with("commands.sh", "w")
        mock_open().write.assert_any_call("command1\n")
        mock_open().write.assert_any_call("command2\n")
        mock_subprocess_run.assert_called_once_with(["bash", "commands.sh"])


if __name__ == "__main__":
    unittest.main()
