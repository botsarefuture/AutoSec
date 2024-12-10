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



# Clone or update the repository
if [ ! -d "$INSTALL_DIR/.git" ]; then
    echo "Cloning the repository to $INSTALL_DIR..."
    sudo git clone "$REPO_URL" "$INSTALL_DIR"
    # give permission to the directory and its contents to the current user
    sudo chown -R $USER:$USER $INSTALL_DIR
else
    echo "Updating the repository in $INSTALL_DIR..."
    sudo git -C "$INSTALL_DIR" pull

    # give permission to the directory and its contents to the current user
    sudo chown -R $USER:$USER $INSTALL_DIR
fi

# Update package list and install Python and pip
if [ "$AUTO_AGREE" = true ]; then
    sudo apt update -y
    sudo apt install -y python3 python3-pip
else
    sudo apt update
    sudo apt install python3 python3-pip
fi



# Ensure the install directory exists
if [ ! -d "$INSTALL_DIR" ]; then
    echo "Installation failed. The directory $INSTALL_DIR does not exist."
    exit 1
fi

# This is to fix the issue with the temp directory not being created
if [ ! -d "$INSTALL_DIR/temp" ]; then
    echo "Creating the temp directory at $INSTALL_DIR/temp..."
    sudo mkdir -p "$INSTALL_DIR/temp"
    sudo mkdir -p "$INSTALL_DIR/AutoSec/temp"
fi

# Create a virtual environment and install required Python packages
sudo apt install -y python3-venv
python3 -m venv "$INSTALL_DIR/venv"
source "$INSTALL_DIR/venv/bin/activate"
pip install --upgrade pip
pip install -r "$INSTALL_DIR/requirements.txt" --b
deactivate

# Install iptables and cron
if [ "$AUTO_AGREE" = true ]; then
    sudo apt install -y iptables cron
else
    sudo apt install iptables cron
fi

echo "Setting up the cronjob for updating the repository..."

# Add cronjob to user's crontab
(crontab -l 2>/dev/null; echo "0 * * * * bash $INSTALL_DIR/update.sh") | crontab -

# Create systemd service file
SERVICE_FILE="/etc/systemd/system/autosec.service"
sudo bash -c "cat > $SERVICE_FILE" <<EOL
[Unit]
Description=AutoSec Service
After=network.target

[Service]
Type=simple
User=$USER
WorkingDirectory=$INSTALL_DIR
ExecStart=/usr/bin/python3 $INSTALL_DIR/AutoSec/index.py
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOL

# Reload systemd, enable and start the service
sudo systemctl daemon-reload
sudo systemctl enable autosec.service
sudo systemctl start autosec.service

# Create or overwrite the flag file
echo "Installation completed on $(date)" | sudo tee "$FLAG_FILE"

echo "The system is now ready to monitor the system logs."
echo "The script will run as a systemd service and alert you if there are any suspicious activities."
echo "Please check the logs regularly to ensure the security of your system."
