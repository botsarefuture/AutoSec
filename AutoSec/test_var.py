import unittest
from unittest.mock import patch
from var import get_ip, init_mode, Mode


class TestVar(unittest.TestCase):

    @patch("var.requests.get")
    def test_get_ip(self, mock_get):
        mock_get.return_value.text = "127.0.0.1\n"
        self.assertEqual(get_ip(), "127.0.0.1")

    def test_init_mode(self):
        self.assertEqual(init_mode(lambda: 0), "pink")
        self.assertEqual(init_mode(lambda: 1), "blue")
        self.assertEqual(init_mode(lambda: 2), "red")
        self.assertEqual(init_mode(lambda: 3), "violet")
        self.assertEqual(init_mode(lambda: 4), "darkred")
        self.assertEqual(init_mode(lambda: 5), "black")
        self.assertEqual(init_mode(lambda: 6), "pink")

    @patch("var.requests.get")
    def test_mode_class(self, mock_get):
        mock_get.return_value.json.return_value = {"alert_level": 1}
        mode_instance = Mode()
        self.assertEqual(str(mode_instance), "blue")
        self.assertEqual(int(mode_instance), 1)

        mode_instance._update()
        self.assertEqual(int(mode_instance), 1)

        mode_instance.mode = 2
        self.assertEqual(str(mode_instance), "red")
        self.assertEqual(mode_instance._upper(), "RED")


if __name__ == "__main__":
    unittest.main()
