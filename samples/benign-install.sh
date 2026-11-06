#!/bin/sh
# Installs the "hello" CLI into ~/.local/bin. Synthetic sample for testing.
set -eu

VERSION="1.4.2"
DEST="${HOME}/.local/bin"

mkdir -p "$DEST"
echo "Downloading hello ${VERSION}..."
curl -fsSL "https://downloads.example.com/hello/${VERSION}/hello-linux-amd64.tar.gz" -o /tmp/hello.tar.gz
tar -xzf /tmp/hello.tar.gz -C "$DEST" hello
chmod +x "$DEST/hello"
rm -f /tmp/hello.tar.gz

case ":$PATH:" in
  *":$DEST:"*) ;;
  *) echo "Add $DEST to your PATH to use hello." ;;
esac
echo "Installed hello ${VERSION} to $DEST"
