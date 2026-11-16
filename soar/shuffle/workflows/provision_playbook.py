#!/usr/bin/env python3
"""Provision the Shuffle playbook "IR - Juice Shop response" (idempotent).

It REPLACES the Step-4 intake workflow in place (same workflow id, same webhook
id/URL/token), so Falcosidekick needs no change.

                                      decision == respond-dev
  webhook --> triage --> collect --+--> dev_isolate --> dev_eradicate --> dev_verify
   (token)   (correlate,   (evidence |
              claim)       FIRST)    +--> prod_approval (User Input: human) --> prod_respond
                                      decision == respond-prod             (isolate + eradicate,
                                                                            run by the responder)
  decision == duplicate / out-of-scope: the execution stops after triage
  (the alert is still recorded in the incident timeline by the responder).

The SOAR never holds a Kubernetes credential: every action is an HTTP call to
the ir-responder service (Shuffle network only), which enforces its own
safeguards and is itself constrained by RBAC + admission policy.

Usage (Ubuntu, project root):  python3 -I soar/shuffle/workflows/provision_playbook.py
Export (token values redacted): soar/shuffle/workflows/ir-juice-shop-playbook.json
"""
import json
import os
import re
import sys
import uuid

HERE = os.path.dirname(os.path.abspath(__file__))
SHUFFLE_DIR = os.path.dirname(HERE)
ROOT = os.path.dirname(os.path.dirname(SHUFFLE_DIR))
sys.path.insert(0, SHUFFLE_DIR)
from shuffle_api import call  # noqa: E402

OLD_NAME, NAME = "IR - Falco alert intake", "IR - Juice Shop response"
ENVIRONMENT = "Shuffle"
RESPONDER = "http://ir-responder:8088"
SECRETS = os.path.join(SHUFFLE_DIR, "secrets")
EXPORT = os.path.join(HERE, "ir-juice-shop-playbook.json")


def read(path):
    with open(path, encoding="utf-8-sig") as f:
        return f.read().strip()


def must(status, data, what):
    if status != 200 or (isinstance(data, dict) and data.get("success") is False):
        sys.exit(f"{what} failed: HTTP {status}: {str(data)[:300]}")
    return data


def main():
    hook_token = read(os.path.join(SECRETS, "webhook-token.txt"))
    resp_token = read(os.path.join(ROOT, "response", "secrets", "responder-token.txt"))

    _, apps = call("GET", "/api/v1/apps")
    http = next(a for a in apps if a["name"] == "http")
    _, wfs = call("GET", "/api/v1/workflows")
    wf = next((w for w in wfs if w.get("name") in (NAME, OLD_NAME)), None)
    if wf is None:
        sys.exit("intake workflow not found: run provision_intake.py first")
    old_hook = next(t for t in wf["triggers"] if t.get("trigger_type") == "WEBHOOK")
    call("DELETE", f"/api/v1/hooks/{old_hook['id']}/delete")      # re-registered below

    headers = f"Content-Type: application/json\nX-Responder-Token: {resp_token}"
    actions, x = {}, 350

    def post(label, path, body, y=200):
        nonlocal x
        aid = str(uuid.uuid4())
        actions[label] = {
            "app_name": "http", "app_version": http["app_version"], "app_id": http["id"],
            "name": "POST", "label": label, "id": aid, "environment": ENVIRONMENT,
            "is_valid": True, "errors": [], "position": {"x": x, "y": y},
            "parameters": [
                {"name": "url", "value": RESPONDER + path, "required": True},
                {"name": "body", "value": body, "multiline": True},
                {"name": "headers", "value": headers, "multiline": True},
                {"name": "verify", "value": "false"},
                {"name": "timeout", "value": "600"},
            ],
        }
        x += 250
        return aid

    target = ('"incident_id":"$triage.body.incident_id","namespace":"$triage.body.namespace",'
              '"pod":"$triage.body.pod"')
    post("triage", "/v1/triage", '{"alert": $exec}')
    post("collect", "/v1/action", '{"action":"collect",' + target + '}')
    x_branch = x
    post("dev_isolate", "/v1/action", '{"action":"isolate",' + target + '}', y=80)
    post("dev_eradicate", "/v1/action", '{"action":"eradicate",' + target + '}', y=80)
    post("dev_verify", "/v1/verify", '{"namespace":"$triage.body.namespace"}', y=80)
    x = x_branch + 250
    # Who approved and when, as recorded by Shuffle for the AUTHENTICATED user who answered.
    approval = ('"approval":"shuffle-userinput user=$prod_approval.click_info.user '
                'time=$prod_approval.click_info.time incident=$triage.body.incident_id"')
    # One fast call: Shuffle replaces its worker a few seconds after a User Input is
    # answered, and a long synchronous action in that window loses its result (observed).
    post("prod_respond", "/v1/respond-approved", '{' + target + ',' + approval + '}', y=330)
    actions["triage"]["isStartNode"] = True

    hook = {
        "app_name": "Webhook", "app_version": "1.0.0", "name": "Webhook", "label": "falco_alert_webhook",
        "type": "TRIGGER", "trigger_type": "WEBHOOK", "id": old_hook["id"], "environment": ENVIRONMENT,
        "status": "running", "is_valid": True, "position": {"x": 100, "y": 200},
        "parameters": old_hook["parameters"],
    }
    approval_node = {
        "app_name": "User Input", "app_version": "1.0.0", "name": "User Input", "label": "prod_approval",
        "type": "TRIGGER", "trigger_type": "USERINPUT", "id": str(uuid.uuid4()), "environment": ENVIRONMENT,
        "status": "running", "is_valid": True, "position": {"x": x_branch, "y": 330},
        "parameters": [
            {"name": "alertinfo", "value":
                "## PROD incident: approve isolation + replacement?\n\n"
                "- incident: $triage.body.incident_id\n- pod: $triage.body.namespace/$triage.body.pod\n"
                "- first alert: $triage.body.rule ($triage.body.priority)\n"
                "- evidence archive sha256: $collect.body.record.archive_sha256\n\n"
                "Approve = quarantine the pod, cut its connections, start a clean replacement, then delete it."},
            {"name": "options", "value": "boolean"},
            {"name": "type", "value": "subflow"},
            {"name": "email", "value": ""}, {"name": "sms", "value": ""},
            {"name": "subflow", "value": ""}, {"name": "subflow_failure", "value": ""},
        ],
    }

    def cond(src, value, op="equals"):
        cid = str(uuid.uuid4())
        return {"source": {"name": "source", "value": src, "variant": "STATIC_VALUE", "action_field": "", "id": cid},
                "condition": {"name": "condition", "value": op, "id": cid},
                "destination": {"name": "destination", "value": value, "variant": "STATIC_VALUE",
                                "action_field": "", "id": cid}}

    def branch(src, dst, *conds):
        return {"id": str(uuid.uuid4()), "source_id": src, "destination_id": dst,
                "conditions": list(conds), "has_errors": False}

    a = {k: v["id"] for k, v in actions.items()}
    ok = lambda label: cond(f"${label}.body.outcome", "ok")       # noqa: E731
    branches = [
        branch(hook["id"], a["triage"]),
        # only the FIRST alert of an in-scope incident goes further
        branch(a["triage"], a["collect"], cond("$triage.body.decision", "respond-", "startswith")),
        branch(a["collect"], a["dev_isolate"], cond("$triage.body.decision", "respond-dev"), ok("collect")),
        branch(a["dev_isolate"], a["dev_eradicate"], ok("dev_isolate")),
        branch(a["dev_eradicate"], a["dev_verify"], ok("dev_eradicate")),
        branch(a["collect"], approval_node["id"], cond("$triage.body.decision", "respond-prod"), ok("collect")),
        branch(approval_node["id"], a["prod_respond"]),
    ]

    wf.update({
        "name": NAME,
        "description": "Falco alert -> triage/correlate -> evidence -> dev: automatic isolation + "
                       "replacement; prod: human approval first. Actions via ir-responder.",
        "actions": list(actions.values()), "triggers": [hook, approval_node], "branches": branches,
        "start": a["triage"], "tags": ["ir", "falco", "juice-shop"],
    })
    must(*call("PUT", f"/api/v1/workflows/{wf['id']}", wf), "save workflow")
    must(*call("POST", "/api/v1/hooks/new", {
        "name": hook["label"], "type": "webhook", "id": hook["id"], "workflow": wf["id"],
        "start": a["triage"], "environment": ENVIRONMENT, "auth": f"X-IR-Token: {hook_token}",
        "custom_response": "", "version": "v1", "version_timeout": 15,
    }), "register webhook")

    _, saved = call("GET", f"/api/v1/workflows/{wf['id']}")
    text = json.dumps(saved, indent=2)
    for secret, where in ((hook_token, "soar/shuffle/secrets/webhook-token.txt"),
                          (resp_token, "response/secrets/responder-token.txt")):
        text = text.replace(secret, f"<REDACTED: {where}>")
    # personal data (e.g. "updated_by": the Shuffle admin's e-mail) stays out of git
    text = re.sub(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", "<REDACTED: user>", text)
    with open(EXPORT, "w") as f:
        f.write(text + "\n")
    print(f"playbook '{NAME}' saved: workflow {wf['id']}, {len(actions)} actions, "
          f"approval node {approval_node['id']}")
    print(f"export: {EXPORT} (secrets redacted)")


if __name__ == "__main__":
    main()
