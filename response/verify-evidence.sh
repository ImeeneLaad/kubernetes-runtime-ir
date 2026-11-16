#!/usr/bin/env bash
# Verifies an evidence package: archive hash, then every file inside it.
# Works on the ARCHIVE (the preserved artefact), extracted to a temp dir, so the
# working copy on disk is not trusted.
# Usage (Ubuntu): bash response/verify-evidence.sh evidence/<incident>/<ns>__<pod>.tar.gz
set -u
A=${1:?archive.tar.gz}
[ -f "$A" ] && [ -f "$A.sha256" ] || { echo "archive or .sha256 missing"; exit 2; }
( cd "$(dirname "$A")" && sha256sum -c --quiet "$(basename "$A").sha256" ) \
  && echo "[PASS] archive hash matches $(cut -c1-16 "$A.sha256")..." \
  || { echo "[FAIL] archive hash mismatch: archive altered"; exit 1; }
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
tar -C "$T" -xzf "$A"
D="$T/$(ls "$T")"
if ( cd "$D" && sha256sum -c --quiet SHA256SUMS ); then
  echo "[PASS] all $(wc -l < "$D/SHA256SUMS") files match SHA256SUMS"
else
  echo "[FAIL] file hash mismatch inside the archive"; exit 1
fi
python3 - "$D/manifest.json" <<'EOF'
import json, sys
m = json.load(open(sys.argv[1]))
print(f"       incident={m['incident_id']} target={m['namespace']}/{m['pod']} "
      f"collected {m['collection_start_utc']} -> {m['collection_end_utc']}")
EOF
