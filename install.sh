#!/bin/bash

# Define constants
INSTALL_DIR="/etc/AutoSec"
FLAG_FILE="$INSTALL_DIR/.installed_flag"
REPO_URL="https://github.com/botsarefuture/AutoSec.git"

# Check for -y flag
AUTO_AGREE=false
if [ "$1" == "-y" ]; then
    AUTO_AGREE=true
fi

# Ensure the install directory exists
if [ ! -d "$INSTALL_DIR" ]; then
    echo "Creating the installation directory at $INSTALL_DIR..."
    sudo mkdir -p "$INSTALL_DIR"
fi

# Clone or update the repository
if [ ! -d "$INSTALL_DIR/.git" ]; then
    echo "Cloning the repository to $INSTALL_DIR..."
    sudo git clone "$REPO_URL" "$INSTALL_DIR"
else
    echo "Updating the repository in $INSTALL_DIR..."
    sudo git -C "$INSTALL_DIR" pull
fi

# Update package list and install Python and pip
if [ "$AUTO_AGREE" = true ]; then
    sudo apt update -y
    sudo apt install -y python3 python3-pip
else
    sudo apt update
    sudo apt install python3 python3-pip
fi

# Upgrade pip and install required Python packages
sudo pip3 install --upgrade pip
sudo pip3 install --break-system-packages -r "$INSTALL_DIR/requirements.txt"

# Install iptables and cron
if [ "$AUTO_AGREE" = true; then
    sudo apt install -y iptables cron
else
    sudo apt install iptables cron
fi

echo "Running the initial loading of the logs..."
sudo python3 "$INSTALL_DIR/AutoSec/index.py" -li

echo "Setting up the cronjob..."

# Add cronjob to user's crontab
(crontab -l 2>/dev/null; echo "*/5 * * * * /usr/bin/python3 $INSTALL_DIR/AutoSec/index.py -a") | crontab -
(crontab -l 2>/dev/null; echo "0 * * * * bash $INSTALL_DIR/update.sh") | crontab -

# Create or overwrite the flag file
echo "Installation completed on $(date)" | sudo tee "$FLAG_FILE"

echo "The system is now ready to monitor the system logs."
echo "The script will run every 5 minutes and alert you if there are any suspicious activities."
echo "Please check the logs regularly to ensure the security of your system."
