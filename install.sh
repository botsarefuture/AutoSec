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

# Function to install dependencies
install_dependencies() {
    if [ "$AUTO_AGREE" = true ]; then
        sudo apt update -y
        sudo apt install -y python3 python3-pip python3-venv iptables cron
    else
        sudo apt update
        sudo apt install python3 python3-pip python3-venv iptables cron
    fi
}

# Function to setup virtual environment and install Python packages
setup_python_env() {
    python3 -m venv "$INSTALL_DIR/venv"
    source "$INSTALL_DIR/venv/bin/activate"
    pip install --upgrade pip
    pip install -r "$INSTALL_DIR/requirements.txt"
    deactivate
}

# Function to setup systemd service
setup_systemd_service() {
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

    sudo systemctl daemon-reload
    sudo systemctl enable autosec.service
    sudo systemctl start autosec.service
}

# Clone or update the repository
if [ ! -d "$INSTALL_DIR/.git" ]; then
    echo "Cloning the repository to $INSTALL_DIR..."
    sudo git clone "$REPO_URL" "$INSTALL_DIR"
    sudo chown -R $USER:$USER $INSTALL_DIR
    install_dependencies
    setup_python_env
    setup_systemd_service
else
    echo "Updating the repository in $INSTALL_DIR..."
    sudo git -C "$INSTALL_DIR" pull
    sudo chown -R $USER:$USER $INSTALL_DIR
    install_dependencies
    setup_python_env
    sudo systemctl restart autosec.service
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

echo "Setting up the cronjob for updating the repository..."

# Add cronjob to user's crontab
(crontab -l 2>/dev/null; echo "0 * * * * bash $INSTALL_DIR/install.sh") | crontab -

# Create or overwrite the flag file
echo "Installation completed on $(date)" | sudo tee "$FLAG_FILE"

echo "The system is now ready to monitor the system logs."
echo "The script will run as a systemd service and alert you if there are any suspicious activities."
echo "Please check the logs regularly to ensure the security of your system."
