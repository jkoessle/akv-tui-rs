#!/bin/sh
# install.sh - Install akv-tui-rs from GitHub Releases

set -e

REPO="jkoessle/akv-tui-rs"
BINARY_NAME="akv"
DEST_DIR="/usr/local/bin"

# Detect OS and Architecture
OS="$(uname -s)"
ARCH="$(uname -m)"

case "$OS" in
    Linux)
        OS_TYPE="unknown-linux-gnu"
        ;;
    Darwin)
        OS_TYPE="apple-darwin"
        ;;
    *)
        echo "Unsupported OS: $OS"
        exit 1
        ;;
esac

case "$ARCH" in
    x86_64)
        ARCH_TYPE="x86_64"
        ;;
    aarch64|arm64)
        ARCH_TYPE="aarch64"
        ;;
    *)
        echo "Unsupported Architecture: $ARCH"
        exit 1
        ;;
esac

TARGET="$ARCH_TYPE-$OS_TYPE"
echo "Detected platform: $TARGET"

# Determine latest version
LATEST_TAG=$(curl -s "https://api.github.com/repos/$REPO/releases/latest" | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')

if [ -z "$LATEST_TAG" ]; then
    echo "Could not determine latest version."
    exit 1
fi

echo "Installing $BINARY_NAME $LATEST_TAG for $TARGET..."

# Construct download URL
# The binary is named azure-keyvault-tui-<target>
DOWNLOAD_URL="https://github.com/$REPO/releases/download/$LATEST_TAG/$BINARY_NAME-$TARGET"

# Download and install
echo "Downloading from $DOWNLOAD_URL..."
curl -L -o "$BINARY_NAME" "$DOWNLOAD_URL"
chmod +x "$BINARY_NAME"

echo "Moving binary to $DEST_DIR (requires sudo)..."
if command -v sudo >/dev/null 2>&1; then
    sudo mv "$BINARY_NAME" "$DEST_DIR/$BINARY_NAME"
else
    mv "$BINARY_NAME" "$DEST_DIR/$BINARY_NAME"
fi

echo "Successfully installed $BINARY_NAME to $DEST_DIR/$BINARY_NAME"

