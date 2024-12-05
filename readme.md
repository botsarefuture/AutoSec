# Authentication Log Analysis

## Description
This project is a comprehensive log analysis tool designed to read authentication logs and output the number of failed login attempts per user. It is implemented in Python and utilizes the `re` module for log parsing.

## Usage
To use the tool, execute the `log_anal.py` script and provide the path to the log file as an argument. For example:
```
python log_anal.py /var/log/auth.log
```

## Output
The tool will output the number of failed login attempts per user in the log file. For example:
```
