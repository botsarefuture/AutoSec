#!/bin/bash

# Define constants
INSTALL_DIR="/etc/AutoSec"
FLAG_FILE="$INSTALL_DIR/.installed_flag"
CRONJOB_PATTERN="AutoSec/index.py"

# Check if the installation directory exists
if [ ! -d "$INSTALL_DIR" ]; then
    echo "Installation directory does not exist. Nothing to clean."
    exit 1
fi

# Remove the cronjobs related to AutoSec
echo "Removing cronjobs..."
crontab -l | grep -v "$CRONJOB_PATTERN" | crontab -

# Remove the installation directory
echo "Removing the installation directory at $INSTALL_DIR..."
sudo rm -rf "$INSTALL_DIR"
# force remove the directory
sudo rm -rf "$INSTALL_DIR"

# if failed to remove the directory, wait for 5 seconds and try again
if [ -d "$INSTALL_DIR" ]; then
    echo "Failed to remove the installation directory. Waiting for 5 seconds and trying again..."
    sleep 5
    sudo rm -rf "$INSTALL_DIR"
fi

# Remove the flag file
if [ -f "$FLAG_FILE" ]; then
    echo "Removing the flag file at $FLAG_FILE..."
    sudo rm -f "$FLAG_FILE"
fi

echo "Cleanup completed. AutoSec has been removed from the system."