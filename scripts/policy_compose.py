"""Reference composer for layered policies; the conformance oracle for the mvm client.

Covers the rules in docs/adr/004 that the vectors exercise: allows union, denies
union, deny beats allow, tools deny > ask > allow, resources take the smallest
bound, shares are writable only if every layer says so.
shortcut: no network canonicalisation, block or secret-host narrowing yet; add vectors and rules together.
"""
import re

_UNITS = {"": 1, "K": 1 << 10, "M": 1 << 20, "G": 1 << 30}


def _size(value):
    m = re.fullmatch(r"(\d+)([KMG]?)", value)
    if not m:
        raise ValueError(f"bad size {value!r}")
    return int(m[1]) * _UNITS[m[2]]


def _union(layers, section, key):
    seen = []
    for layer in layers:
        for item in layer.get(section, {}).get(key, []):
            if item not in seen:
                seen.append(item)
    return seen


def compose(layers):
    """Return the resolved policy for ordered layers (plain dicts)."""
    out = {}
    names = lambda items: [i["name"] if isinstance(i, dict) else i for i in items]

    deny = {s: _union(layers, s, "deny") for s in ("secrets", "env", "tools", "shares")}
    out["secrets"] = {"bind": [
        n for n in names(_union(layers, "secrets", "bind")) if n not in deny["secrets"]]}
    out["env"] = {"allow": [e for e in _union(layers, "env", "allow") if e not in deny["env"]]}

    ask = [t for t in _union(layers, "tools", "ask") if t not in deny["tools"]]
    out["tools"] = {
        "allow": [t for t in _union(layers, "tools", "allow")
                  if t not in deny["tools"] and t not in ask],
        "ask": ask,
    }

    mounts, guests = [], {}
    for layer in layers:
        for m in layer.get("shares", {}).get("mount", []):
            if any(m["host"] == d or m["host"].startswith(d.rstrip("/") + "/")
                   for d in deny["shares"]):
                continue
            if m["guest"] in guests and guests[m["guest"]]["host"] != m["host"]:
                raise ValueError(f"shares.mount.guest: {m['guest']} has two sources")
            if m["guest"] in guests:
                guests[m["guest"]]["writable"] &= m.get("writable", False)
            else:
                guests[m["guest"]] = {"host": m["host"], "guest": m["guest"],
                                      "writable": m.get("writable", False)}
                mounts.append(guests[m["guest"]])
    out["shares"] = {"mount": mounts}

    res = {}
    for layer in layers:
        for k, v in layer.get("resources", {}).items():
            cur = res.get(k)
            key = _size if k.startswith("max_memory") else int
            res[k] = v if cur is None or key(v) < key(cur) else cur
    out["resources"] = res
    return out


def _argv(argv, what):
    if (not isinstance(argv, list) or not argv
            or not all(isinstance(a, str) for a in argv)):
        raise ValueError(f"{what}: argv must be a non-empty list of strings")
    if not argv[0].startswith("/"):
        raise ValueError(f"{what}: argv[0] must be an absolute path, got {argv[0]!r}")
    return argv


def select_entrypoint(applications, runtime_override=None, workload=None):
    """Runtime override, else workload, else the last application's `default` entrypoint.

    Only entries named `default` are implicit; any other name is explicit-only.
    """
    chosen = None
    for i, app in enumerate(applications):
        names = set()
        for e in app.get("entrypoints", []):
            name = e.get("name")
            if not isinstance(name, str) or not name:
                raise ValueError(f"application {i}: entrypoint name must be a non-empty string")
            if name in names:
                raise ValueError(f"application {i}: duplicate entrypoint name {name!r}")
            names.add(name)
            _argv(e.get("argv"), f"application {i} entrypoint {name!r}")
            if name == "default":
                chosen = e["argv"]
    if runtime_override is not None:
        return _argv(runtime_override, "runtime_override")
    if workload is not None:
        return _argv(workload, "workload")
    if chosen is None:
        raise ValueError("no entrypoint")
    return chosen
