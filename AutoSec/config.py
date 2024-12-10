MAX_FAILED_PER_TYPE = {
    "pink": {
        "invalid_user": 10,
        "failed_attempt": 7,
    },
    "blue": {
        "invalid_user": 8,
        "failed_attempt": 5,
    },
    "red": {
        "invalid_user": 5,
        "failed_attempt": 3,
    },
    "violet": {
        "invalid_user": 3,
        "failed_attempt": 2,
    },
    "darkred": {
        "invalid_user": 2,
        "failed_attempt": 1,
    },
    "black": {
        "invalid_user": 1,
        "failed_attempt": 1,
    },
}

ACTIONS_PER_THREAT_LEVEL_PER_TYPE = {
    "pink": {
        "invalid_user": {"action": "BAN", "duration": 3600},
        "failed_attempt": {"action": "BAN", "duration": 1800},
    },
    "blue": {
        "invalid_user": {"action": "BAN", "duration": 7200},
        "failed_attempt": {"action": "BAN", "duration": 3600},
    },
    "red": {
        "invalid_user": {"action": "BAN", "duration": 14400},
        "failed_attempt": {"action": "BAN", "duration": 7200},
    },
    "violet": {
        "invalid_user": {"action": "BAN", "duration": 28800},
        "failed_attempt": {"action": "BAN", "duration": 14400},
    },
    "darkred": {
        "invalid_user": {"action": "BAN", "duration": 43200},
        "failed_attempt": {"action": "BAN", "duration": 2419200},
    },
    "black": {
        "invalid_user": {"action": "BAN", "duration": 0},
        "failed_attempt": {"action": "BAN", "duration": 0},
    },
}
