MAX_FAILED_PER_TYPE = {
    "green": {
        "invalid_user": 5,
        "failed_attempt": 3,
    },
    "yellow": {
        "invalid_user": 3,
        "failed_attempt": 2,
    },
    "red": {
        "invalid_user": 1,
        "failed_attempt": 1,
    },
    "black": {
        "invalid_user": 0,
        "failed_attempt": 0,
    },
}

ACTIONS_PER_THREAT_LEVEL_PER_TYPE = {
    "green": {
        "invalid_user": {"action": "BAN", "duration": 900},
        "failed_attempt": {"action": "BAN", "duration": 600},
    },
    "yellow": {
        "invalid_user": {"action": "BAN", "duration": 1800},
        "failed_attempt": {"action": "BAN", "duration": 1200},
    },
    "red": {
        "invalid_user": {"action": "BAN", "duration": 3600},
        "failed_attempt": {"action": "BAN", "duration": 2700},
    },
    "black": {
        "invalid_user": {"action": "BAN", "duration": 0},
        "failed_attempt": {"action": "BAN", "duration": 0},
    },
}
