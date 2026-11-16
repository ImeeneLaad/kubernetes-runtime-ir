#!/usr/bin/env bash
# Vendors ONLY the Shuffle apps this project uses, pinned to one commit of
# github.com/shuffle/python-apps, into soar/shuffle/apps/ (hot-loaded by Shuffle).
#
# Why not let Shuffle clone the whole library at startup?
#   - GitHub ran at 10-34 KB/s on this network: the full clone would take hours.
#   - 2 apps instead of ~200 = far less code running with Shuffle's Docker access.
#   - Pinned + committed = reviewable and reproducible.
# Usage (Ubuntu, project root):  bash soar/shuffle/fetch-apps.sh
set -euo pipefail
COMMIT=4a3d72091be4eb4f0c1e01fbbf62e4183d6dcc6d
DEST="$(cd "$(dirname "$0")" && pwd)/apps"
FILES=(
  http/1.4.0/Dockerfile http/1.4.0/api.yaml http/1.4.0/requirements.txt http/1.4.0/src/app.py
  shuffle-tools/1.2.0/Dockerfile shuffle-tools/1.2.0/api.yaml shuffle-tools/1.2.0/requirements.txt
  shuffle-tools/1.2.0/run.sh shuffle-tools/1.2.0/src/app.py shuffle-tools/1.2.0/src/concurrency.py
  shuffle-tools/1.2.0/src/switch.py
)
for f in "${FILES[@]}"; do
  mkdir -p "$DEST/$(dirname "$f")"
  curl -sfSL -H 'User-Agent: generic-client' --retry 3 -o "$DEST/$f" \
    "https://raw.githubusercontent.com/shuffle/python-apps/$COMMIT/$f"
done
echo "source: github.com/shuffle/python-apps@$COMMIT" > "$DEST/SOURCE.txt"
(cd "$DEST" && find . -type f ! -name SOURCE.txt ! -name SHA256SUMS -print0 | sort -z | xargs -0 sha256sum > SHA256SUMS)
echo "Fetched ${#FILES[@]} files into $DEST"; cat "$DEST/SHA256SUMS"
