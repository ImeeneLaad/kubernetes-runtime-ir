#!/usr/bin/env python3
"""Provision the Shuffle workflow "IR - Falco alert intake" (idempotent).

    Webhook trigger (requires header X-IR-Token)  ->  record_falco_alert (Shuffle Tools: repeat_back_to_me)

Step-4 scope: prove that Falco alerts reach the SOAR and start an execution.
Triage and response actions are added in later steps.

Outputs (all under soar/shuffle/secrets/, git-ignored):
  webhook-token.txt  shared secret that Falcosidekick must send (X-IR-Token)
  webhook-url.txt    URL reachable from the cluster (kind network IP)
Export (committed, token redacted): soar/shuffle/workflows/ir-falco-intake.json

Usage (Ubuntu, project root):  python3 -I soar/shuffle/workflows/provision_intake.py
"""
import json
import os
import re
import secrets
import sys
import uuid

HERE = os.path.dirname(os.path.abspath(__file__))
SHUFFLE_DIR = os.path.dirname(HERE)
sys.path.insert(0, SHUFFLE_DIR)
from shuffle_api import call  # noqa: E402

NAME = "IR - Falco alert intake"
ENVIRONMENT = "Shuffle"                      # Orborus environment name
SECRETS = os.path.join(SHUFFLE_DIR, "secrets")
TOKEN_FILE = os.path.join(SECRETS, "webhook-token.txt")
URL_FILE = os.path.join(SECRETS, "webhook-url.txt")
EXPORT = os.path.join(HERE, "ir-falco-intake.json")


def env_value(key):
    with open(os.path.join(SHUFFLE_DIR, ".env"), encoding="utf-8") as f:
        for line in f:
            if line.startswith(key + "="):
                return line.split("=", 1)[1].strip()
    sys.exit(f"{key} missing from .env")


def must(status, data, what):
    if status != 200 or (isinstance(data, dict) and data.get("success") is False):
        sys.exit(f"{what} failed: HTTP {status}: {str(data)[:300]}")
    return data


def token():
    os.makedirs(SECRETS, exist_ok=True)
    if not os.path.exists(TOKEN_FILE) or not open(TOKEN_FILE).read().strip():
        with open(TOKEN_FILE, "w") as f:
            f.write(secrets.token_urlsafe(32))
        print("generated new webhook token")
    return open(TOKEN_FILE).read().strip()


def main():
    tok = token()
    kind_ip = env_value("SHUFFLE_KIND_IP")

    # --- the app used by the single action
    _, apps = call("GET", "/api/v1/apps")
    tools = next((a for a in apps if a.get("name") == "Shuffle Tools"), None)
    if not tools:
        sys.exit("Shuffle Tools app not loaded (run fetch-apps.sh and the hotload)")

    # --- find or create the workflow
    _, wfs = call("GET", "/api/v1/workflows")
    wf = next((w for w in wfs if w.get("name") == NAME), None)
    if wf is None:
        wf = must(*call("POST", "/api/v1/workflows", {
            "name": NAME,
            "description": "Receives Falco alerts from Falcosidekick (tag ir_response) "
                           "and records them. Response logic is added in later steps.",
        }), "create workflow")
        print("created workflow", wf["id"])
    else:
        print("updating existing workflow", wf["id"])
        # stop the previous webhook so it can be re-registered with current settings
        for t in wf.get("triggers") or []:
            if t.get("trigger_type") == "WEBHOOK":
                call("DELETE", f"/api/v1/hooks/{t['id']}/delete")

    # Keep the trigger id stable across runs, so the URL (and Sidekick config) stays the same.
    old = next((t for t in (wf.get("triggers") or []) if t.get("trigger_type") == "WEBHOOK"), None)
    trigger_id = old["id"] if old else str(uuid.uuid4())
    action_id = str(uuid.uuid4())
    hook_path = f"/api/v1/hooks/webhook_{trigger_id}"
    url = f"http://{kind_ip}:5001{hook_path}"

    action = {
        "app_name": tools["name"], "app_version": tools["app_version"], "app_id": tools["id"],
        "name": "repeat_back_to_me", "label": "record_falco_alert", "id": action_id,
        "environment": ENVIRONMENT, "is_valid": True, "isStartNode": True, "errors": [],
        "position": {"x": 450, "y": 200},
        "parameters": [{
            "name": "call", "value": "$exec", "required": True, "multiline": True,
            "schema": {"type": "string"}, "example": "",
        }],
    }
    trigger = {
        "app_name": "Webhook", "app_version": "1.0.0", "name": "Webhook",
        "label": "falco_alert_webhook", "type": "TRIGGER", "trigger_type": "WEBHOOK",
        "id": trigger_id, "environment": ENVIRONMENT, "status": "running", "is_valid": True,
        "position": {"x": 100, "y": 200},
        "parameters": [
            {"name": "url", "value": url},
            {"name": "tmp", "value": f"webhook_{trigger_id}"},
            {"name": "auth_headers", "value": f"X-IR-Token: {tok}"},
            {"name": "custom_response_body", "value": ""},
            {"name": "await_response", "value": "v1"},
        ],
    }
    wf.update({
        "actions": [action], "triggers": [trigger], "start": action_id,
        "branches": [{"id": str(uuid.uuid4()), "source_id": trigger_id,
                      "destination_id": action_id, "conditions": [], "has_errors": False}],
        "tags": ["ir", "falco"],
    })
    must(*call("PUT", f"/api/v1/workflows/{wf['id']}", wf), "save workflow")

    must(*call("POST", "/api/v1/hooks/new", {
        "name": trigger["label"], "type": "webhook", "id": trigger_id, "workflow": wf["id"],
        "start": action_id, "environment": ENVIRONMENT, "auth": f"X-IR-Token: {tok}",
        "custom_response": "", "version": "v1", "version_timeout": 15,
    }), "register webhook")

    with open(URL_FILE, "w") as f:
        f.write(url)

    # --- export without the secret
    _, saved = call("GET", f"/api/v1/workflows/{wf['id']}")
    text = json.dumps(saved, indent=2).replace(tok, "<REDACTED: soar/shuffle/secrets/webhook-token.txt>")
    # personal data (e.g. "updated_by": the Shuffle admin's e-mail) stays out of git
    text = re.sub(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", "<REDACTED: user>", text)
    with open(EXPORT, "w") as f:
        f.write(text + "\n")

    print(f"workflow id : {wf['id']}")
    print(f"webhook path: {hook_path}")
    print(f"cluster URL : saved to {URL_FILE}")
    print(f"export      : {EXPORT} (token redacted)")


if __name__ == "__main__":
    main()
