#!/bin/bash

# Fixed directory
DIRECTORY="/var/www/API_REST/documents/"

# Check if the directory exists
if [ ! -d "$DIRECTORY" ]; then
  echo "Directory $DIRECTORY does not exist."
  exit 1
fi

# Find and delete .yaml files older than 30 minutes
find "$DIRECTORY" -name "*.yaml" -mmin +30 -type f -exec rm -f {} \;

echo "Deleted .yaml files older than 30 minutes in directory: $DIRECTORY"

