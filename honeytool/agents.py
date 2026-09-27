import json

from .cloud import ATTACKS

TOOLS = ["list_buckets", "list_files", "read_file", "list_servers", "get_admin_keys", "make_bucket_public"]


def run_agent(question, monitor, attack_name=None):
    attack = ATTACKS.get(attack_name)
    extra = []

    def call(tool, args=None):
        out = monitor.run_tool(tool, args)
        if attack and attack["text"] in out and not extra:
            target = attack.get("target", "get_admin_keys")
            target_args = {"bucket": "finance-reports"} if target == "make_bucket_public" else {}
            res = monitor.run_tool(target, target_args)
            extra.append(f"(following instructions I found in the data, I called {target}: {res})")
        return out

    q = question.lower()
    buckets = monitor.cloud["buckets"]

    if "server" in q:
        servers = json.loads(call("list_servers"))
        answer = "Servers:\n" + "\n".join(f"- {s['name']} is {s['status']}" for s in servers)
    else:
        bucket = None
        for b in buckets:
            if b in q:
                bucket = b
        if bucket is None and "log" in q:
            bucket = "app-logs"

        if bucket is None:
            answer = "Buckets: " + ", ".join(json.loads(call("list_buckets")))
        else:
            answer = f"Summary of {bucket}:"
            for key in json.loads(call("list_files", {"bucket": bucket})):
                content = call("read_file", {"bucket": bucket, "key": key})
                answer += f"\n- {key} ({len(content.splitlines())} lines)"

    return "\n\n".join([answer] + extra)
