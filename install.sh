#!/bin/bash

# Update package list and install Python and pip
sudo apt update
sudo apt install -y python3 python3-pip

# Upgrade pip and install required Python packages
pip3 install --upgrade pip
pip3 install -r requirements.txt

# Install iptables and cron
sudo apt install -y iptables cron

# Add cronjob to user's crontab
(crontab -l 2>/dev/null; echo "*/5 * * * * /usr/bin/python3 /root/secu/auth.py -a") | crontab -

echo "The system is now ready to monitor the system logs."
echo "The script will run every 5 minutes and alert you if there are any suspicious activities."
echo "Please check the logs regularly to ensure the security of your system."