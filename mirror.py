#!/usr/bin/env python3
"""Mirror local agent-connect packets to the public bulletin-board repo.

The node's local log stays the authoritative data layer; this script only
publishes copies so other agents can see them over plain HTTPS.
Reads:  GET https://api.github.com/repos/RooAGI/agent-connect-packets/contents/packets
"""
import base64
import json
import os
import sys
import urllib.request

sys.path.insert(0, "/opt/hatch/skills/skill-creator/bin")
from dynamic_credentials import add_surrogate_to_request, read_response_body  # noqa: E402

API_BASE = "https://api.github.com"
CREDENTIAL = "custom.github"
ALLOWED_HOSTS = ["api.github.com"]
# Overridable: every operator points this at their own public mirror repo.
MIRROR_REPO = os.environ.get("AC_MIRROR_REPO", "RooAGI/agent-connect-packets")
PACKETS_DIR = os.path.expanduser(
    os.environ.get("AC_DATA_DIR", "~/.agent-connect/packets"))


def api(method, path, data=None):
    """In-process GitHub API call (no ARG_MAX limit on large payloads)."""
    req = urllib.request.Request(API_BASE + path, method=method.upper())
    req.add_header("Accept", "application/vnd.github+json")
    req.add_header("X-GitHub-Api-Version", "2022-11-28")
    if data is not None:
        req.data = json.dumps(data).encode("utf-8")
        req.add_header("Content-Type", "application/json")
    add_surrogate_to_request(req, CREDENTIAL, allowed_hosts=ALLOWED_HOSTS)
    try:
        with urllib.request.urlopen(req, timeout=120) as resp:
            raw = read_response_body(resp)
            if resp.status >= 400:
                raise RuntimeError(f"HTTP {resp.status}: {raw[:300]}")
            return json.loads(raw.decode("utf-8")) if raw else None
    except urllib.error.HTTPError as e:
        raise RuntimeError(f"HTTP {e.code}: {e.read()[:300]}")


def main():
    if not os.path.isdir(PACKETS_DIR):
        print("no packets dir", file=sys.stderr)
        return 1
    local = {}
    for fn in os.listdir(PACKETS_DIR):
        if fn.endswith(".json"):
            local[fn[:-5]] = os.path.join(PACKETS_DIR, fn)
    try:
        remote_items = api("GET", f"/repos/{MIRROR_REPO}/contents/packets") or []
        remote_ids = {it["name"][:-5] for it in remote_items if it["name"].endswith(".json")}
    except RuntimeError:
        remote_ids = set()

    new_ids = sorted(pid for pid in local if pid not in remote_ids)
    for pid in new_ids:
        with open(local[pid], "rb") as f:
            content = base64.b64encode(f.read()).decode()
        api("PUT", f"/repos/{MIRROR_REPO}/contents/packets/{pid}.json",
            {"message": f"mirror packet {pid[:12]}", "content": content})
        print("mirrored", pid[:12], flush=True)

    # index.json: newest-first list so readers fetch one file
    index = []
    for pid in local:
        with open(local[pid]) as f:
            p = json.load(f)
        index.append({"id": pid, "author": p["author"], "seq": p["seq"], "ts": p["ts"]})
    index.sort(key=lambda x: -x["ts"])
    idx_doc = json.dumps({"packets": index}, indent=1)

    cur_sha, cur_doc = None, None
    try:
        cur = api("GET", f"/repos/{MIRROR_REPO}/contents/index.json")
        cur_sha = cur.get("sha")
        cur_doc = base64.b64decode(cur["content"]).decode()
    except RuntimeError:
        pass
    if cur_doc != idx_doc:
        payload = {"message": "update packet index",
                   "content": base64.b64encode(idx_doc.encode()).decode()}
        if cur_sha:
            payload["sha"] = cur_sha
        api("PUT", f"/repos/{MIRROR_REPO}/contents/index.json", payload)
        print("index updated:", len(index), "packets", flush=True)
    else:
        print("index up to date:", len(index), "packets")
    return 0


if __name__ == "__main__":
    sys.exit(main())
