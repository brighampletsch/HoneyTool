import json
from datetime import datetime

from .cloud import DECOY_RESULTS
from .detector import scan

DECOYS = ["get_admin_keys", "make_bucket_public"]
REDACTED = "[removed by honeytool: looked like a prompt injection]"


def now():
    return datetime.now().strftime("%H:%M:%S")


class Monitor:
    def __init__(self, cloud):
        self.cloud = cloud
        self.tripwire = True
        self.quarantine = False

        self.log = []
        self.flags = []
        self.alerts = []

        self.last_flagged = None
        self.last_source = None

    def check_output(self, source, lines):
        out = []
        found = []
        for line in lines:
            hits = scan(line)
            if hits:
                found += hits
                out.append(REDACTED if self.quarantine else line)
            else:
                out.append(line)

        if found:
            self.flags.append({"time": now(), "source": source, "hits": found, "removed": self.quarantine})
            self.last_flagged = (source, found[0][0])
        self.last_source = source
        return out, found

    def decoy(self, name, args):
        if self.last_flagged:
            source, line = self.last_flagged
        else:
            source, line = f"{self.last_source} (scanner missed it)", ""

        ran = not self.tripwire
        self.alerts.append({"time": now(), "tool": name, "source": source, "line": line, "ran": ran})
        self.log.append({"time": now(), "tool": name, "args": json.dumps(args), "status": "RAN" if ran else "BLOCKED"})

        if ran:
            return json.dumps(DECOY_RESULTS[name])
        return json.dumps({"error": "AccessDenied (blocked by honeytool)"})

    def run_tool(self, name, args=None):
        args = args or {}
        if name in DECOYS:
            return self.decoy(name, args)

        buckets = self.cloud["buckets"]
        found = []
        try:
            if name == "list_buckets":
                result = json.dumps(list(buckets))

            elif name == "list_files":
                names, found = self.check_output(f"{args['bucket']} (file names)", list(buckets[args["bucket"]]))
                result = json.dumps(names)

            elif name == "read_file":
                text = buckets[args["bucket"]][args["key"]]
                lines, found = self.check_output(f"{args['bucket']}/{args['key']}", text.splitlines())
                result = "\n".join(lines)

            elif name == "list_servers":
                servers = json.loads(json.dumps(self.cloud["servers"]))
                for s in servers:
                    for tag, value in s["tags"].items():
                        new_value, hits = self.check_output(f"server {s['name']} tags", [value])
                        s["tags"][tag] = new_value[0]
                        found += hits
                result = json.dumps(servers, ensure_ascii=False)

            else:
                result = json.dumps({"error": "unknown tool " + name})
        except KeyError as e:
            result = json.dumps({"error": f"not found: {e}"})

        self.log.append({"time": now(), "tool": name, "args": json.dumps(args) if args else "",
                         "status": "FLAGGED" if found else "ok"})
        return result
