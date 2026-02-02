#!/bin/bash

# Define constants
INSTALL_DIR="/etc/AutoSec"
FLAG_FILE="$INSTALL_DIR/.installed_flag"
REPO_URL="https://github.com/botsarefuture/AutoSec.git"
USER="autosec"
LOG_FILE="/var/log/autosec-install.log"

git config --global --add safe.directory /etc/AutoSec

# Redirect all output to log file
exec > >(tee -a "$LOG_FILE") 2>&1

# Check for -y flag
AUTO_AGREE=true
if [ "$1" == "-d" ]; then
    AUTO_AGREE=false
fi

# Function to create user
create_user() {
    if id "$USER" &>/dev/null; then
        echo "User $USER already exists."
    else
        sudo useradd -m -s /bin/bash "$USER"
        echo "User $USER created."
        echo "$USER:autosec" | sudo chpasswd
        sudo usermod -aG sudo "$USER"
        echo "$USER ALL=(ALL) NOPASSWD:ALL" | sudo tee /etc/sudoers.d/$USER
    fi
}

# Function to install dependencies
install_dependencies() {
    if [ "$AUTO_AGREE" = true ]; then
        sudo apt update -y
        sudo apt install -y python3 python3-pip python3-venv iptables cron git
    else
        sudo apt update
        sudo apt install python3 python3-pip python3-venv iptables cron git
    fi
}

# Function to setup virtual environment and install Python packages
setup_python_env() {
    sudo -u "$USER" python3 -m venv "$INSTALL_DIR/venv"
    sudo -u "$USER" bash -c "source $INSTALL_DIR/venv/bin/activate && pip install --upgrade pip && pip install -r $INSTALL_DIR/requirements.txt && deactivate"
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
ExecStart=$INSTALL_DIR/venv/bin/python $INSTALL_DIR/AutoSec/index_v2.py
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOL

    sudo systemctl daemon-reload
    sudo systemctl enable autosec.service
    sudo systemctl start autosec.service
}

# Function to grant log file access
grant_log_access() {
    sudo usermod -aG adm "$USER"
    sudo usermod -aG syslog "$USER"
}

# Create user
create_user

# Grant log file access
grant_log_access

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
    sudo systemctl daemon-reload
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
    sudo chown -R $USER:$USER "$INSTALL_DIR/temp" "$INSTALL_DIR/AutoSec/temp"
fi

echo "Setting up the cronjob for updating the repository..."

# Remove cronjob for updating the repository if it exists
(crontab -l 2>/dev/null | grep -v "/etc/AutoSec/update.sh" || true) | crontab -

# Add cronjob to user's crontab if it doesn't already exist
(crontab -l 2>/dev/null | grep -q "$INSTALL_DIR/install.sh" || (crontab -l 2>/dev/null; echo "0 * * * * bash $INSTALL_DIR/install.sh")) | crontab -

# Create or overwrite the flag file
echo "Installation completed on $(date)" | sudo tee "$FLAG_FILE"

echo "The system is now ready to monitor the system logs."
echo "The script will run as a systemd service and alert you if there are any suspicious activities."
echo "Please check the logs regularly to ensure the security of your system."
