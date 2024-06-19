#!/bin/bash
# Set the repository URL and destination path
repository_url="https://github.com/CAELESTIS-Project-EU/Workflows.git"
dest_path="/home/ubuntu/installDir/"
requested_branch="${1:-main}"  # Default to 'main' if no argument is provided

# Create a folder with the name of the branch inside the destination path
branch_folder="${dest_path}${requested_branch}"
if [ ! -d "$branch_folder" ]; then
  echo "Creating directory for branch: $requested_branch"
  mkdir -p "$branch_folder"
fi

# Navigate to the branch folder
cd "$branch_folder" || { echo "Failed to navigate to directory: $branch_folder"; exit 1; }

# Check if the repository is already cloned
if [ -d ".git" ]; then
  echo "Checking for updates in the existing repository..."
  git fetch origin "$requested_branch"
  local_commit=$(git rev-parse HEAD)
  remote_commit=$(git rev-parse FETCH_HEAD)
  if [ "$local_commit" != "$remote_commit" ]; then
    echo "Changes detected. Pulling latest changes..."
    git pull origin "$requested_branch"
  else
    echo "No changes detected. Repository is up to date."
  fi
else
  echo "Repository not found. Cloning repository..."
  git clone -b "$requested_branch" "$repository_url" .
fi

# Navigate to the final directory
cd /var/www/API_REST || { echo "Failed to navigate to final directory: /var/www/API_REST"; exit 1; }
