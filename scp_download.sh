#!/bin/bash

if [ "$#" -ne 6 ]; then
    echo "Usage: $0 <remote_host> <remote_port> <remote_user> <remote_password> <remote_folder_path> <local_target_directory>"
    exit 1
fi


# Assign parameters to variables
remote_host="$1"
remote_port="$2"
remote_user="$3"
remote_password="$4"
remote_folder_path="$5"
local_target_directory="$6"

# shellcheck disable=SC2089
sftp_command="sshpass -p \"$remote_password\" sftp -oPort=$remote_port $remote_user@$remote_host <<EOF
get -r $remote_folder_path $local_target_directory
bye
EOF"

# Execute the SFTP command
echo "Copying folder to $remote_user@$remote_host on port $remote_port..."
eval "$sftp_command"

echo "Folder copy completed."
