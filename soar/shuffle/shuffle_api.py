#!/usr/bin/env python3
"""Minimal client for the Shuffle REST API (standard library only).

The API key is read from soar/shuffle/secrets/api-key.txt (git-ignored) and is
never printed. "utf-8-sig" strips the BOM that Windows Notepad may add.

CLI (Ubuntu, project root):
  python3 soar/shuffle/shuffle_api.py whoami
  python3 soar/shuffle/shuffle_api.py GET /api/v1/workflows
"""
import json
import os
import sys
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
KEY_FILE = os.path.join(HERE, "secrets", "api-key.txt")
BASE_URL = os.environ.get("SHUFFLE_URL", "http://127.0.0.1:5001")


def api_key() -> str:
    with open(KEY_FILE, encoding="utf-8-sig") as f:
        key = f.read().strip()
    if not key:
        sys.exit(f"empty API key file: {KEY_FILE}")
    return key


def call(method: str, path: str, body=None, timeout: int = 60):
    """Return (status, parsed JSON or raw text)."""
    data = None if body is None else json.dumps(body).encode()
    req = urllib.request.Request(
        BASE_URL + path, method=method, data=data,
        headers={"Authorization": f"Bearer {api_key()}", "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            status, raw = r.status, r.read().decode()
    except urllib.error.HTTPError as e:
        status, raw = e.code, e.read().decode()
    try:
        return status, json.loads(raw)
    except json.JSONDecodeError:
        return status, raw


def main(argv):
    if len(argv) >= 1 and argv[0] == "whoami":
        s, d = call("GET", "/api/v1/users/getinfo")
        if s != 200:
            sys.exit(f"HTTP {s}: {str(d)[:200]}")
        org = (d.get("active_org") or {}).get("name")
        print(f"OK: authenticated (role={d.get('role')}, org={org}, key length={len(api_key())})")
        return
    if len(argv) >= 2:
        body = json.loads(argv[2]) if len(argv) > 2 else None
        s, d = call(argv[0].upper(), argv[1], body)
        print(s)
        print(json.dumps(d, indent=2)[:4000] if not isinstance(d, str) else d[:4000])
        return
    print(__doc__)


if __name__ == "__main__":
    main(sys.argv[1:])
