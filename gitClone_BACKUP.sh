repository_url="https://github.com/CAELESTIS-Project-EU/Workflows"
dest_path="/home/ubuntu/installDir/"

if [ -d "$dest_path" ]; then
    echo "Deleting existing folder: $dest_path"
    rm -rf "$dest_path"
fi

# Clone the GitHub repository into the target folder
echo "Cloning repository into $dest_path"
git clone "$repository_url" "$dest_path"


# Check if the cloning was successful
if [ $? -eq 0 ]; then
    echo "Repository cloned successfully."
else
    echo "Error: Cloning failed."
fi

