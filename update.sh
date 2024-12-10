#!/bin/bash

# Function to check for updates and pull the latest version from git
check_for_updates() {
    # Checks if the local version hash is different from the remote version hash.
    # If different, pulls the latest version from the git repository.
    #
    # Parameters
    # ----------
    # None
    #
    # Returns
    # -------
    # None
    local repo_url="https://github.com/botsarefuture/AutoSec.git"
    local version_file="version.txt"
    local temp_version_file="/tmp/version.txt"

    # Download the latest version file from the repository
    if curl -o "$temp_version_file" "$repo_url/raw/main/$version_file"; then
        # Compare the local version file with the downloaded version file
        if ! cmp -s "$version_file" "$temp_version_file"; then
            echo "New version available. Updating..."
            if git pull origin main; then
                echo "Update completed."
                systemctl restart autosec.service
            else
                echo "Failed to pull the latest version."
                exit 1
            fi
        else
            echo "You are already using the latest version."
        fi
        rm "$temp_version_file"
    else
        echo "Failed to check for updates."
        exit 1
    fi
}

# Call the check_for_updates function
check_for_updates