import requests


def get_ip():
    result = requests.get("https://checkip.amazonaws.com/")
    return result.text.strip()




def init_mode(fetch_mode):
    m = fetch_mode()

    if m == 0:
        mode = "pink"

    elif m == 1:
        mode = "blue"

    elif m == 2:
        mode = "red"

    elif m == 3:
        mode = "violet"

    elif m == 4:
        mode = "darkred"

    elif m == 5:
        mode = "black"

    else:
        mode = "pink"

    return mode


class Mode:
    """
    Represents the mode.

    Attributes
    ----------
    mode : int
        The mode as int:
            - 0: pink
            - 1: blue
            - 2: red
            - 3: violet
            - 4: darkred
            - 5: black

    Methods
    -------
    __str__()
        Returns the mode as a string.

    __repr__()
        Returns the mode as a string.

    __int__()
        Returns the mode as an int.

    _update()
        Updates the mode.

    _upper()
        returns mode with big
    """

    PINK = 0
    BLUE = 1
    RED = 2
    VIOLET = 3
    DARKRED = 4
    BLACK = 5

    def __init__(self, mode=None):
        self.mode = mode

        if self.mode is None:
            self._init_mode()

    def _init_mode(self):
        self.mode = self.fetch_mode()

    def _as_real_string(self):
        # if type(self.mode) == str:
        #    self.mode = int(self.mode)

        if self.mode == 0:
            return "pink"

        elif self.mode == 1:
            return "blue"

        elif self.mode == 2:
            return "red"

        elif self.mode == 3:
            return "violet"

        elif self.mode == 4:
            return "darkred"

        elif self.mode == 5:
            return "black"

        else:
            return "black"

    def fetch_mode(self):
        """
        Fetches the mode of the fresh module.
        """
        try:
            url = "https://core.security.luova.club/visualizer/api/alertlevel"
            result = requests.get(url)
            resp = int(result.json().get("alert_level", 0))
            return resp
        except:
            return 5  # If the request fails, return black mode.

    def __str__(self):
        return str(self._as_real_string())

    def __repr__(self):
        return self.mode

    def __int__(self):
        return int(self.mode)

    def _update(self):
        self.mode = self.fetch_mode()

    def _upper(self):
        return self._as_real_string().upper()

    def __eq__(self, value: int):
        return self.mode == value


MODE = Mode()

COMMANDS = []

PROCESSED_IPS = []
PROCESSED_LINES = []

HASH_FILE = "processed_hashes.txt"
SERVER_IP = get_ip()
