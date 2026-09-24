#!/usr/bin/env python3
"""Static checks that the Splunk app matches what bin/monitor.sh writes (#7).

No Splunk is involved. The checks read the alert format out of
bin/monitor.sh and config/ids.conf and compare it with splunk/*.conf and
splunk/dashboard.xml:

- inputs.conf monitors ALERT_LOG as sourcetype linux_ids, and no stanza
  points at an IDS path or script that the IDS never writes;
- props.conf parses the JSON and the timestamp format the monitor writes;
- every EXTRACT pulls the expected values out of real alert details;
- every field, category, description and severity that a linux_ids search
  uses exists in the data.

Prints one "ok" or "not ok" line per check and exits 1 on any failure.
"""

import configparser
import datetime
import os
import re
import sys
import xml.etree.ElementTree as ET

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
failed = False


def report(passed, desc, detail=""):
    global failed
    if passed:
        print(f"ok     {desc}")
    else:
        failed = True
        print(f"not ok {desc}" + (f": {detail}" if detail else ""))


def read(path):
    with open(os.path.join(REPO, path), encoding="utf-8") as f:
        return f.read()


def conf(path):
    parser = configparser.RawConfigParser(strict=False, interpolation=None,
                                          comment_prefixes=("#",), delimiters=("=",))
    parser.optionxform = str
    parser.read_string(read(path))
    return parser


# --- What the IDS writes -------------------------------------------------

ids_conf = {}
for line in read("config/ids.conf").splitlines():
    m = re.match(r'^([A-Z_]+)=(.*)$', line)
    if m:
        ids_conf[m.group(1)] = m.group(2).strip().strip('"')

alert_log = ids_conf["ALERT_LOG"]
written_paths = {ids_conf["ALERT_LOG"], ids_conf["MONITOR_LOG"]}

monitor = read("bin/monitor.sh")
fmt = re.search(r"json_log=\$\(printf '(\{[^']*)'", monitor).group(1)
json_keys = set(re.findall(r'"(\w+)":', fmt))
if "\\\"details\\\"" in monitor or '"details' in monitor:
    json_keys.add("details")

severities = {ids_conf[k] for k in ids_conf if k.startswith("SEV_")}
alerts = []  # (severity, category, description, details template)
for m in re.finditer(r'log_alert "\$(SEV_\w+)" "(\w+)" "([^"]+)" "([^"]*)"', monitor):
    alerts.append((ids_conf[m.group(1)], m.group(2), m.group(3), m.group(4)))
categories = {a[1] for a in alerts}
descriptions = {a[2] for a in alerts}
report(len(alerts) >= 15, f"found {len(alerts)} log_alert calls in bin/monitor.sh")

# Values substituted into the details templates, and the fields the
# extractions must produce from each.
SAMPLE = {
    "ip": "203.0.113.9", "count": "12", "port": "4444", "CONFIG": "/etc/ids/ids.conf",
    "file": "/etc/passwd", "perms": "4755", "user": "backdoor", "uid": "0",
    "recent_fails": "11", "sudo_count": "7", "proc": "xmrig", "pid": "4242",
    "cmd": "/tmp/.x/kworker", "{cpu_used}": "97", "{mem_used}": "93", "mount": "/",
    "{usage}": "96", "proc_count": "900", "service": "evil.service",
}
EXPECT = {
    "Possible port scan detected": {"src": "203.0.113.9", "attempt_count": "12"},
    "Brute force attack detected": {"src": "203.0.113.9", "attempt_count": "12"},
    "Unusual outbound connection": {"dest_port": "4444"},
    "Critical file modified": {"file_path": "/etc/passwd"},
    "New SUID/SGID file detected": {"file_path": "/etc/passwd"},
    "Potential webshell detected": {"file_path": "/etc/passwd"},
    "New user created": {"user": "backdoor", "uid": "0"},
    "Excessive failed login attempts": {"attempt_count": "11"},
    "Unusual sudo activity": {"attempt_count": "7"},
    "Potential cryptominer detected": {"process": "xmrig", "pid": "4242"},
    "Hidden process detected": {"pid": "4242", "process": "/tmp/.x/kworker"},
    "Process running deleted binary": {"pid": "4242", "process": "/tmp/.x/kworker"},
    "High CPU usage": {"usage_percent": "97"},
    "High memory usage": {"usage_percent": "93"},
    "High disk usage": {"usage_percent": "96"},
    "Excessive process count": {"attempt_count": "900"},
    "SSH configuration changed": {"file_path": "/etc/ssh/sshd_config"},
}


def sample_line(sev, cat, desc, details):
    text = re.sub(r"\$(\{\w+\}|\w+)", lambda m: SAMPLE.get(m.group(1), "x"), details)
    return ('{"timestamp":"2026-09-24T09:42:17Z","hostname":"web01","severity":"%s",'
            '"category":"%s","description":"%s","details":"%s"}' % (sev, cat, desc, text))


# --- inputs.conf ---------------------------------------------------------

inputs = conf("splunk/inputs.conf")
ids_stanzas = [s for s in inputs.sections() if inputs.get(s, "sourcetype", fallback="").startswith("linux_ids")]
report(ids_stanzas == [f"monitor://{alert_log}"],
       f"inputs.conf: the only linux_ids input is monitor://{alert_log}", str(ids_stanzas))
for s in inputs.sections():
    kind, _, path = s.partition("://")
    if kind == "script":
        report(False, f"inputs.conf: no scripted input ({s})", "the IDS ships no Splunk scripts")
    elif path.startswith(("/var/log/ids", "/var/lib/ids", "/opt/ids")) and path not in written_paths:
        report(False, f"inputs.conf: {s} is a file the IDS writes")
report(all(inputs.get(s, "sourcetype", fallback="") == "linux_ids" for s in ids_stanzas),
       "inputs.conf: alert log uses sourcetype linux_ids")
input_sourcetypes = {inputs.get(s, "sourcetype", fallback="") for s in inputs.sections()}

# --- props.conf ----------------------------------------------------------

props = conf("splunk/props.conf")
report(props.has_section("linux_ids"), "props.conf has a [linux_ids] stanza")
p = dict(props.items("linux_ids")) if props.has_section("linux_ids") else {}
report(p.get("KV_MODE") == "json", "props.conf: KV_MODE = json")

stamp_fmt = re.search(r"date \+(%Y[^)\s]*)\)", monitor).group(1)
stamp = datetime.datetime(2026, 9, 24, 9, 42, 17).strftime(stamp_fmt)
line = sample_line("high", "network", "x", "")
prefix = p.get("TIME_PREFIX")
try:
    start = re.search(prefix, line).end() if prefix else 0
    raw = line[start:start + int(p.get("MAX_TIMESTAMP_LOOKAHEAD", "128"))]
    parsed = None
    for n in range(len(raw), 0, -1):  # Splunk parses the longest matching prefix
        try:
            parsed = datetime.datetime.strptime(raw[:n], p.get("TIME_FORMAT", ""))
            break
        except ValueError:
            continue
    report(parsed == datetime.datetime(2026, 9, 24, 9, 42, 17),
           f"props.conf: TIME_FORMAT parses the monitor timestamp {stamp}", f"got {parsed}")
except (re.error, AttributeError) as e:
    report(False, "props.conf: TIME_PREFIX matches the alert line", str(e))
report(p.get("TZ") == "UTC" or "%z" in p.get("TIME_FORMAT", "") or "%Z" in p.get("TIME_FORMAT", ""),
       "props.conf: the UTC timestamps are read as UTC")

extracts = []
for key, value in p.items():
    if key.startswith("EXTRACT-"):
        extracts.append((key, re.compile(value.replace("(?<", "(?P<"))))
extracted = {name for _, rx in extracts for name in rx.groupindex}
aliases = set()
for key, value in p.items():
    if key.startswith("FIELDALIAS-"):
        for src, dst in re.findall(r"(\w+)\s+AS\s+(\w+)", value, re.I):
            report(src in json_keys | extracted, f"props.conf: alias source {src} exists")
            aliases.add(dst)
evals = {k[len("EVAL-"):] for k in p if k.startswith("EVAL-")}

for sev, cat, desc, details in alerts:
    if desc not in EXPECT:
        continue
    line = sample_line(sev, cat, desc, details)
    got = {}
    for _, rx in extracts:
        m = rx.search(line)
        if m:
            for k, v in m.groupdict().items():
                got.setdefault(k, v)
    want = EXPECT[desc]
    wrong = {k: got.get(k) for k in want if got.get(k) != want[k]}
    report(not wrong, f"props.conf: fields from \"{desc}\"", f"expected {want}, got {wrong}")

# --- searches ------------------------------------------------------------

DEFAULTS = {"_time", "_raw", "host", "source", "sourcetype", "index", "date_hour",
            "date_mday", "date_wday", "linecount", "splunk_server", "eventtype", "count"}
KEYWORDS = {"index", "sourcetype", "earliest", "latest", "span", "value", "limit",
            "useother", "usenull", "OR", "AND", "NOT", "IN", "by", "as", "_raw"}
FUNCS = {"case", "round", "if", "coalesce", "isnotnull", "isnull", "count", "dc", "avg",
         "max", "min", "sum", "values", "latest", "earliest", "len", "like"}


def fields_in(query):
    """Return (used, created, literal comparisons) for one SPL query."""
    created = set(re.findall(r"\(\?<(\w+)>", query))
    body = re.sub(r'"(?:[^"\\]|\\.)*"', '""', query)
    created |= set(re.findall(r"\bas\s+(\w+)", body, re.I))
    for seg in body.split("|"):
        m = re.match(r"\s*eval\s+(\w+)\s*=", seg)
        if m:
            created.add(m.group(1))
    used = set(re.findall(r"\b([A-Za-z_]\w*)\s*(?:!=|>=|<=|=|>|<)", body))
    used |= set(re.findall(r"\b([A-Za-z_]\w*)\s+IN\s*\(", body))
    used |= {a for f, a in re.findall(r"\b(\w+)\((\w+)\s*[,)]", body) if f in FUNCS}
    for seg in body.split("|"):
        seg = seg.strip()
        for m in re.finditer(r"\bby\s+([\w,\s]+)", seg):
            used |= set(re.findall(r"\w+", m.group(1)))
        m = re.match(r"(table|dedup|fields)\s+(.*)", seg)
        if m:
            used |= set(re.findall(r"\w+", m.group(2)))
        m = re.match(r"sort\s+(.*)", seg)
        if m:
            used |= set(re.findall(r"-?(\w+)", m.group(1)))
        m = re.match(r"fillnull\s+(?:value=\S+\s+)?(.*)", seg)
        if m:
            used |= set(re.findall(r"\w+", m.group(1)))
    used = {u for u in used if u not in KEYWORDS and not u.isdigit()}
    literals = re.findall(r'\b(severity|category|description)="([^"]*)"', query)
    return used, created, literals


queries = []
saved = conf("splunk/savedsearches.conf")
for s in saved.sections():
    if saved.has_option(s, "search"):
        queries.append((f"savedsearches [{s}]", saved.get(s, "search")))
for i, q in enumerate(ET.parse(os.path.join(REPO, "splunk/dashboard.xml")).iter("query")):
    queries.append((f"dashboard query {i + 1}", q.text or ""))

known = json_keys | extracted | aliases | evals | DEFAULTS
allowed = {"severity": severities, "category": categories, "description": descriptions}
checked = 0
for name, q in queries:
    for st in re.findall(r"sourcetype=(\w+)", q):
        if st not in input_sourcetypes:
            report(False, f"{name}: sourcetype {st} has an input")
    if "sourcetype=linux_ids" not in q:
        # Other sourcetypes are Splunk's; only require fields to be made in the search.
        used, created, _ = fields_in(q)
        unknown = used - created - DEFAULTS
        report(not unknown, f"{name}: fields are Splunk defaults or made by the search", str(sorted(unknown)))
        continue
    checked += 1
    used, created, literals = fields_in(q)
    unknown = used - known - created
    report(not unknown, f"{name}: every field exists in linux_ids", str(sorted(unknown)))
    bad = [(k, v) for k, v in literals if v not in allowed[k]]
    report(not bad, f"{name}: severity/category/description values are ones the monitor writes", str(bad))
    for bare in re.findall(r"\b(severity|category)=(\w+)", q):
        if bare[1] not in allowed[bare[0]]:
            report(False, f"{name}: {bare[0]}={bare[1]} is a value the monitor writes")
report(checked >= 15, f"checked {checked} linux_ids searches")

sys.exit(1 if failed else 0)
