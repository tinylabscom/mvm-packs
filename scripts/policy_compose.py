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
