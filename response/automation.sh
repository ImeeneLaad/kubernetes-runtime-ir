#!/usr/bin/env bash
# Kill switch for automated response.
#   pause   : the SOAR keeps receiving and recording alerts, but triage returns
#             decision "paused" -> the playbook takes no action
#   resume  : back to normal
#   status
# Use it when the automation misbehaves, when the SOAR is suspected compromised,
# during maintenance, or while running component tests that drive the responder by hand.
# Usage (Ubuntu, project root):  bash response/automation.sh pause|resume|status ["reason"]
set -euo pipefail
FLAG="$(cd "$(dirname "$0")/.." && pwd)/evidence/.automation-paused"
case "${1:-status}" in
  pause)  printf '%s paused by %s: %s\n' "$(date -u +%FT%TZ)" "$(id -un)@$(hostname)" "${2:-no reason given}" >> "$FLAG"
          echo "automated response PAUSED" ;;
  resume) rm -f "$FLAG"; echo "automated response RESUMED" ;;
  status) if [ -f "$FLAG" ]; then echo "PAUSED:"; cat "$FLAG"; else echo "active"; fi ;;
  *) echo "usage: $0 pause|resume|status [reason]"; exit 2 ;;
esac
