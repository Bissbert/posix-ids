#!/usr/bin/env python3
"""Static checks that the Ansible tree only references things that exist.

Covers #8, and #12 and #13 found while fixing it:

- every role, included task file, tasks_from, template, copied script and
  notified handler resolves to a file or handler in the repository;
- calls to bin/*.sh use only the options that script's getopts accepts,
  and always pass -c so the monitor reads the Ansible configuration;
- ansible.cfg finds the roles and does not demand a vault password file,
  and group_vars sit next to the playbooks, where Ansible loads them;
- the rendered ids.conf defines every setting config/ids.conf defines.

Needs PyYAML (installed with ansible-core). Prints one "ok" or "not ok"
line per check and exits 1 on any failure.
"""

import configparser
import glob
import os
import re
import sys

import yaml

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
SERVICE_TYPES = ("systemd", "cron")
failed = False


def report(passed, desc, detail=""):
    global failed
    if passed:
        print(f"ok     {desc}")
    else:
        failed = True
        print(f"not ok {desc}" + (f": {detail}" if detail else ""))


def rel(path):
    return os.path.relpath(path, REPO)


def load(path):
    with open(path, encoding="utf-8") as f:
        return yaml.safe_load(f) or []


def module_args(task, *names):
    for name in names:
        for key in (name, "ansible.builtin." + name, "community.general." + name):
            if key in task:
                return task[key]
    return None


def walk_tasks(tasks):
    """Yield every task, descending into block/rescue/always."""
    for task in tasks or []:
        if not isinstance(task, dict):
            continue
        yield task
        for key in ("block", "rescue", "always"):
            yield from walk_tasks(task.get(key))


def expand(value, item=None):
    """Expand the few templated names the tree uses in file references."""
    values = [value]
    if "{{ ids_service_type }}" in value:
        values = [value.replace("{{ ids_service_type }}", t) for t in SERVICE_TYPES]
    if item is not None:
        values = [v.replace("{{ item }}", str(item)) for v in values]
    return [v.replace("{{ ids_source_path }}/", "").replace("{{ ids_source_path }}", "") for v in values]


handler_names = set()
for path in glob.glob(os.path.join(REPO, "roles/*/handlers/main.yml")):
    for h in load(path):
        handler_names.add(h.get("name"))
        if h.get("listen"):
            handler_names.add(h["listen"])

role_names = {os.path.basename(p) for p in glob.glob(os.path.join(REPO, "roles/*")) if os.path.isdir(p)}
getopts = {}
for path in glob.glob(os.path.join(REPO, "bin/*.sh")):
    with open(path, encoding="utf-8") as f:
        m = re.search(r'getopts\s+"([^"]+)"', f.read())
    if m:
        getopts[os.path.basename(path)] = set(re.sub(r"[:]", "", m.group(1)))


def check_role(name, where, tasks_from=None):
    report(name in role_names, f"{where}: role {name} exists")
    if tasks_from and name in role_names:
        path = os.path.join(REPO, "roles", name, "tasks", tasks_from + ("" if tasks_from.endswith(".yml") else ".yml"))
        report(os.path.isfile(path), f"{where}: {name} tasks_from {tasks_from} exists")


def check_script_calls(text, where):
    """Options passed to bin/*.sh must be ones its getopts accepts."""
    for m in re.finditer(r"(?:bin/|\$IDS_BASE/bin/|\"\$IDS_BASE/bin/)(\w+\.sh)\"?((?:\s+(?:-\w+|\"[^\"]*\"|\S+/\S+))*)", text):
        script, args = m.group(1), m.group(2)
        line = text[text.rfind("\n", 0, m.start()) + 1:m.start()]
        if re.search(r"(sh -n|test -[xrf]|\[ -[xrf])\s", line):
            continue  # a syntax or existence check, not a run
        if script not in getopts:
            continue
        flags = set("".join(re.findall(r"(?:^|\s)-(\w+)", args)))
        bad = flags - getopts[script]
        report(not bad, f"{where}: {script}{args} uses only options {script} accepts", str(sorted(bad)))
        if script in ("monitor.sh", "baseline.sh"):
            report("-c" in args.split(), f"{where}: {script}{args} passes the Ansible configuration with -c")


def check_tasks(tasks, where, role_dir=None, play_dir=None):
    for task in walk_tasks(tasks):
        label = f"{where} [{task.get('name', '?')}]"
        loop = task.get("loop") or task.get("with_items")
        items = loop if isinstance(loop, list) else [None]

        inc = module_args(task, "include_tasks", "import_tasks")
        if inc is not None:
            inc = inc.get("file") if isinstance(inc, dict) else inc
            base = os.path.join(role_dir, "tasks") if role_dir else play_dir
            for f in expand(inc):
                report(os.path.isfile(os.path.join(base, f)), f"{label}: task file {f} exists")

        inc = module_args(task, "include_role", "import_role")
        if inc is not None:
            check_role(inc.get("name"), label, inc.get("tasks_from"))

        tpl = module_args(task, "template")
        if tpl is not None:
            base = os.path.join(role_dir, "templates") if role_dir else os.path.join(play_dir, "templates")
            for item in items:
                for f in expand(tpl["src"], item):
                    report(os.path.isfile(os.path.join(base, f)), f"{label}: template {f} exists")

        cp = module_args(task, "copy")
        if isinstance(cp, dict) and "src" in cp and not cp.get("remote_src"):
            for item in items:
                for f in expand(cp["src"], item):
                    report(os.path.isfile(os.path.join(REPO, f)), f"{label}: copied file {f} exists")

        notify = task.get("notify")
        for n in [notify] if isinstance(notify, str) else notify or []:
            report(n in handler_names, f"{label}: handler \"{n}\" exists")

        for mod in ("command", "shell", "cron"):
            args = module_args(task, mod)
            text = args.get("job", args.get("cmd", "")) if isinstance(args, dict) else args
            if isinstance(text, str):
                check_script_calls(text, label)


# --- Playbooks -----------------------------------------------------------

playbooks = sorted(glob.glob(os.path.join(REPO, "playbooks/*.yml")))
for path in playbooks:
    where = rel(path)
    for play in load(path):
        for h in play.get("handlers") or []:
            handler_names.add(h.get("name"))
        for r in play.get("roles") or []:
            check_role(r["role"] if isinstance(r, dict) else r, where)
        for key in ("pre_tasks", "tasks", "post_tasks", "handlers"):
            check_tasks(play.get(key), where, play_dir=os.path.dirname(path))

# --- Roles ---------------------------------------------------------------

for role in sorted(role_names):
    role_dir = os.path.join(REPO, "roles", role)
    for path in sorted(glob.glob(os.path.join(role_dir, "tasks/*.yml")) +
                       glob.glob(os.path.join(role_dir, "handlers/*.yml"))):
        check_tasks(load(path), rel(path), role_dir=role_dir)
    for path in sorted(glob.glob(os.path.join(role_dir, "templates/*.j2"))):
        with open(path, encoding="utf-8") as f:
            check_script_calls(f.read(), rel(path))

report(os.path.isfile(os.path.join(REPO, "roles/ids_base/handlers/main.yml")),
       "handlers live in a role (ids_base) that every deploy play runs")
report(not os.path.exists(os.path.join(REPO, "handlers")),
       "no top-level handlers/ directory that no play loads")

# --- ansible.cfg and variables ------------------------------------------

cfg = configparser.RawConfigParser(strict=False, interpolation=None)
cfg.read(os.path.join(REPO, "ansible.cfg"))
roles_path = cfg.get("defaults", "roles_path", fallback="")
report(any(os.path.normpath(os.path.join(REPO, p)) == os.path.join(REPO, "roles") for p in roles_path.split(":") if p),
       "ansible.cfg: roles_path points at roles/", roles_path or "unset")
report(not cfg.has_option("defaults", "vault_password_file"),
       "ansible.cfg: no vault_password_file that must exist on every controller")
for opt, value in cfg.items("defaults"):
    if opt in ("stdout_callback", "callback_whitelist") and value == "yaml":
        report(False, f"ansible.cfg: {opt} = {value} names a callback that ansible-core 2.13+ removed")
report(not os.path.exists(os.path.join(REPO, "group_vars")),
       "no group_vars/ at the repository root, where no playbook or inventory loads it")
report(os.path.isdir(os.path.join(REPO, "playbooks/group_vars/all")),
       "playbooks/group_vars/all exists next to the playbooks")

# --- ids.conf template ---------------------------------------------------

with open(os.path.join(REPO, "config/ids.conf"), encoding="utf-8") as f:
    keys = set(re.findall(r"^([A-Z_][A-Z0-9_]*)=", f.read(), re.M))
with open(os.path.join(REPO, "roles/ids_config/templates/ids.conf.j2"), encoding="utf-8") as f:
    tpl = f.read()
defined = set(re.findall(r"^([A-Z_][A-Z0-9_]*)=", tpl, re.M))
missing = sorted(keys - defined)
report(not missing, "ids.conf.j2 defines every setting in config/ids.conf", ", ".join(missing))

with open(os.path.join(REPO, "roles/ids_monitor/templates/ids.service.j2"), encoding="utf-8") as f:
    unit = f.read()
reload_hup = re.search(r"^ExecReload=.*(HUP|kill\s+-1)", unit, re.M)
report(not reload_hup, "ids.service.j2 does not send SIGHUP on reload (monitor.sh exits on HUP)")

sys.exit(1 if failed else 0)
