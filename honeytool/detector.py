import base64
import re
import unicodedata

PATTERNS = [
    (r"ignore (all )?(previous|prior) instructions", "tries to override instructions"),
    (r"system notice", "pretends to be a system message"),
    (r"\bai (assistant|agent)s?\b|note to (the )?assistant", "talks directly to the AI"),
    (r"must (call|run)", "tells it to run a tool"),
    (r"</?(system|tool_result)>", "fake chat markup"),
    (r"get_admin_keys|make_bucket_public", "mentions a decoy tool"),
]


def clean(line):
    for ch in ["\u200b", "\u200c", "\u200d", "\ufeff"]:
        line = line.replace(ch, "")
    return unicodedata.normalize("NFKC", line)


def check_line(line):
    for pattern, reason in PATTERNS:
        if re.search(pattern, line, re.IGNORECASE):
            return reason
    return None


def scan(text):
    found = []
    for line in text.splitlines():
        line = clean(line)
        reason = check_line(line)

        if not reason:
            for chunk in re.findall(r"[A-Za-z0-9+/]{20,}={0,2}", line):
                try:
                    decoded = base64.b64decode(chunk).decode()
                except Exception:
                    continue
                if check_line(decoded):
                    reason = "hidden in base64: " + check_line(decoded)
                    break

        if reason:
            found.append((line.strip(), reason))
    return found
