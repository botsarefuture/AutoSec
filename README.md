# AutoSec

AutoSec is a Python-based project designed to enhance security measures through a suite of tools and scripts. This repository provides robust implementations aimed at safeguarding various systems.

## Features
- **Comprehensive Security Tools**: Identify and mitigate security risks effectively.
- **Python-Powered**: Built with Python for flexibility, efficiency, and ease of use.
- **Automated Operations**: Includes tools that run periodically for continuous monitoring.

---

## Getting Started

### Prerequisites
- Python **3.7** or higher.

---

### Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/botsarefuture/autosec.git
   cd autosec
   bash install.sh
   ```

2. **One-liner Installation**:
   ```bash
   curl -sSL https://raw.githubusercontent.com/botsarefuture/AutoSec/refs/heads/main/install.sh | sudo bash
   ```

---

## Usage

### Automatic Operation
By default, AutoSec tools execute automatically every 5 minutes.

### Manual Execution
To run AutoSec tools manually, use:
```bash
python3 AutoSec/index.py
```

---

### Command-Line Arguments

| Argument                | Type   | Description                                                                                   | Default                      |
|-------------------------|--------|-----------------------------------------------------------------------------------------------|------------------------------|
| `-l`, `--logfile`       | str    | Path to the log file.                                                                         | `/var/log/auth.log`          |
| `-m`, `--mode`          | str    | System mode: `'green'`, `'yellow'`, `'red'`, `'black'`.                                       | `green`                      |
|                         |        | **Caution**: Use `'black'` mode only if you fully understand its implications.                |                              |
| `--disable-reporting`   | bool   | Disable reporting to the central monitoring system.                                           | `False`                      |
| `--empty-save`          | bool   | Save commands even if no commands are detected to run.                                        | `False`                      |
| `-a`, `--autoexec`      | bool   | Automatically execute commands after saving them to a file.                                   |                              |
| `-t`, `--threads`       | int    | Number of threads for reporting events.                                                      | `10`                         |
| `--auto-threads`        | bool   | Automatically determine the number of threads for reporting.                                  |                              |
| `-v`, `--verbose`       | bool   | Enable verbose output.                                                                        |                              |
| `-h`, `--help`          |        | Display help message and exit.                                                               |                              |

> **Tip**: Use verbose mode (`-v`) for debugging or detailed outputs.

---

## Contributing

Contributions are highly encouraged! To contribute:
1. Fork this repository.
2. Create a new branch with your feature or fix.
3. Submit a pull request with a clear description of your changes.

---

## License

This project is currently not licensed. For licensing inquiries, please contact the repository owner.

---

## Contact

For support or further questions, reach out to the repository owner on [GitHub](https://github.com/botsarefuture).
