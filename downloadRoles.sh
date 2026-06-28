#!/bin/bash

URL_FILE="Roles link.txt" 

# Get current directory path
CURRENT_DIR="$(pwd)"

# Check if url file exists
if [ ! -f "$URL_FILE" ]; then
    echo "Error: $URL_FILE not found in current directory!"
    echo "Create $URL_FILE with one Google Drive URL per line"
    exit 1
fi


# Set up Python virtual environment for gdown
VENV_DIR=".gdown-venv"
if [ ! -d "$VENV_DIR" ]; then
    echo "Creating Python virtual environment for gdown..."
    python3 -m venv "$VENV_DIR"
fi

# Activate venv and install gdown if needed
source "$VENV_DIR/bin/activate"
if ! python -m gdown --help &> /dev/null; then
    echo "Installing gdown in venv..."
    pip install --upgrade pip
    pip install gdown
fi

# Count valid URLs
TOTAL=$(grep -vE '^\s*$|^\s*#' "$URL_FILE" | wc -l)
COUNT=0

echo "Found $TOTAL URLs to download"
echo "Download destination: $CURRENT_DIR"
echo "--------------------------------"

# Read each line and download
while IFS= read -r url; do
    # Skip empty lines and comments
    if [[ -z "$url" ]] || [[ "$url" =~ ^[[:space:]]*# ]]; then
        continue
    fi
    
    COUNT=$((COUNT + 1))
    echo "[$COUNT/$TOTAL] Processing: $url"

    FILENAME="$(basename "$url")"

    if [ -f "$CURRENT_DIR/$FILENAME" ]; then
        echo "✓ File already exists: $FILENAME. Skipping download."
    else
        echo "Downloading: $url -> $FILENAME"
        FILE_ID="$(echo "$url" | sed -n 's|.*drive.google.com/file/d/\([^/]*\)/.*|\1|p')"
        if [[ -n "$FILE_ID" ]]; then
            DOWNLOAD_URL="https://drive.google.com/uc?id=$FILE_ID"
        else
            DOWNLOAD_URL="$url"
        fi

        if gdown "$DOWNLOAD_URL" -O "$CURRENT_DIR/$FILENAME"; then
            echo "✓ Successfully downloaded"
        else
            echo "✗ Failed to download: $url"
        fi
    fi
    echo "--------------------------------"
    
done < "$URL_FILE"

echo "================================="
echo "Download complete!"
echo "Files saved in: $CURRENT_DIR"
echo "================================="
# Unzip any .zip files downloaded
for zipfile in "$CURRENT_DIR"/*.zip; do
    if [ -f "$zipfile" ]; then
        echo "Unzipping $zipfile ..."
        unzip -o "$zipfile"
        if [ $? -eq 0 ]; then
            echo "✓ Unzipped: $zipfile"
        else
            echo "✗ Failed to unzip: $zipfile"
        fi
    fi
done

# Deactivate venv
deactivate
