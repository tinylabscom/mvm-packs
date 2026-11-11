"""Verified archive details recorded by the publisher when it signs an application version.

The publisher gate has already opened the archive, so it writes what it saw to
pack-details/<namespace>/<name>/<version>.json. Pages show it so a reader sees the
architecture, runtime, signed environment and pinned binaries without downloading the archive.
It is **not signed registry metadata**: a pull re-verifies the archive itself (ADR 004, R1).
Every value is treated as untrusted text and is escaped before it reaches a page.
"""

import re

from rootfs_requirements import _plain_json

HEX64 = re.compile(r"[0-9a-f]{64}\Z")
HEX32 = re.compile(r"[0-9a-f]{32}\Z")
REFERENCE = re.compile(r"[a-z0-9][a-z0-9_-]*/[a-z0-9][a-z0-9_-]*@[0-9A-Za-z.+-]+\Z")
ENV_KEYS = {"descriptor_version", "pack", "target", "entrypoint", "resources", "policy",
            "secret_slots", "capabilities"}
TOP_KEYS = {"schema_version", "reference", "archive", "created_at", "artifacts", "runtime",
            "environment", "binaries"}
MAX_BYTES = 64 << 10


def validate(details):
    """Raise ValueError unless `details` has exactly the recorded shape."""
    if not isinstance(details, dict) or set(details) != TOP_KEYS or details["schema_version"] != 1:
        raise ValueError("details must have exactly the recorded top-level fields at schema_version 1")
    if not isinstance(details["reference"], str) or not REFERENCE.fullmatch(details["reference"]):
        raise ValueError("reference must be namespace/name@version")
    archive = details["archive"]
    if (not isinstance(archive, dict) or set(archive) != {"sha256", "size", "key_id", "arch"}
            or not isinstance(archive["sha256"], str) or not HEX64.fullmatch(archive["sha256"])
            or not isinstance(archive["key_id"], str) or not HEX32.fullmatch(archive["key_id"])
            or type(archive["size"]) is not int or archive["size"] <= 0
            or archive["arch"] not in ("x86_64", "aarch64")):
        raise ValueError("archive must name sha256, size, key_id and arch")
    created = details["created_at"]
    if created is not None and (not isinstance(created, str) or len(created) > 64):
        raise ValueError("created_at must be short text or null")
    artifacts = details["artifacts"]
    if not isinstance(artifacts, list) or not artifacts or len(artifacts) > 64:
        raise ValueError("artifacts must be a list of 1 to 64 entries")
    for item in artifacts:
        if (not isinstance(item, dict) or set(item) != {"name", "role", "size_bytes", "sha256"}
                or not all(isinstance(item[k], str) and len(item[k]) <= 200 for k in ("name", "role"))
                or not isinstance(item["sha256"], str) or not HEX64.fullmatch(item["sha256"])
                or type(item["size_bytes"]) is not int or item["size_bytes"] < 0):
            raise ValueError("each artifact needs name, role, size_bytes and sha256")
    runtime = details["runtime"]
    if (not isinstance(runtime, list) or len(runtime) > 16
            or not all(isinstance(r, dict) and set(r) == {"class", "version"}
                       and all(isinstance(r[k], str) and len(r[k]) <= 64 for k in r) for r in runtime)):
        raise ValueError("runtime must be a short list of class and version")
    environment = details["environment"]
    if environment is not None and (not isinstance(environment, dict) or set(environment) - ENV_KEYS
                                    or not _plain_json(environment, depth=4)):
        raise ValueError("environment must be a small table of the known environment fields")
    binaries = details["binaries"]
    if not isinstance(binaries, list) or len(binaries) > 16 or not all(
            isinstance(b, dict) and set(b) == {"package", "path", "sha256", "size"}
            and isinstance(b["sha256"], str) and HEX64.fullmatch(b["sha256"])
            and all(isinstance(b[k], str) and len(b[k]) <= 200 for k in ("package", "path"))
            and type(b["size"]) is int and b["size"] > 0 for b in binaries):
        raise ValueError("binaries must be a short list of package, path, sha256 and size")
    return details


def code(value, limit=200):
    """A markdown code span from untrusted text: printable characters only, no backticks, bounded."""
    text = "".join(ch if ch.isprintable() else " " for ch in str(value)).replace("`", "'")
    return "`" + text[:limit] + "`"


def _mib(count):
    return f"{count / (1 << 20):.1f} MiB"


def render(details):
    """Markdown lines for the 'Recorded at signing' section of a pack page."""
    a, env = details["archive"], details["environment"] or {}
    out = ["## Recorded at signing\n\n",
           "Recorded by the publisher from the archive when it signed this version. This is "
           "**not signed registry metadata**: `mvmctl pull` re-verifies the archive itself.\n\n",
           "| Field | Value |\n|---|---|\n"
           f"| Architecture | {code(a['arch'])} |\n"
           f"| Created | {code(details['created_at'] or 'not recorded')} |\n"
           f"| Archive | {code(a['sha256'])}, {_mib(a['size'])} |\n"
           f"| Bundle key ID | {code(a['key_id'])} |\n"]
    for item in details["runtime"]:
        out.append(f"| Runtime asset | {code(item['class'])} {code(item['version'])} |\n")
    if env.get("entrypoint"):
        out.append(f"| Entrypoint | {code(' '.join(map(str, env['entrypoint'].get('argv', []))))} |\n")
    if isinstance(env.get("resources"), dict):
        out.append("| Resources | " + code(", ".join(f"{k}={v}" for k, v in sorted(env["resources"].items()))) + " |\n")
    policy = env.get("policy")
    if isinstance(policy, dict):
        for k, v in sorted(policy.items()):
            out.append(f"| Policy `{k}` | {code(v if not isinstance(v, (dict, list)) else _flat(v))} |\n")
    if isinstance(env.get("secret_slots"), list):
        out.append("| Secret slots | " + code(", ".join(
            f"{s.get('name')} ({'required' if s.get('required') else 'optional'})"
            for s in env["secret_slots"] if isinstance(s, dict)) or "none") + " |\n")
    if isinstance(env.get("capabilities"), list):
        out.append("| Capabilities | " + code(", ".join(map(str, env["capabilities"])) or "none") + " |\n")
    out.append("\n### Artifacts in the archive\n\n| Name | Role | Size | SHA-256 |\n|---|---|---|---|\n")
    for item in details["artifacts"]:
        out.append(f"| {code(item['name'])} | {code(item['role'])} | {_mib(item['size_bytes'])} | {code(item['sha256'])} |\n")
    if details["binaries"]:
        out.append("\n### Pinned executables\n\n| Package | Path | Size | SHA-256 |\n|---|---|---|---|\n")
        for b in details["binaries"]:
            out.append(f"| {code(b['package'])} | {code(b['path'])} | {_mib(b['size'])} | {code(b['sha256'])} |\n")
    out.append("\n")
    return out


def _flat(value):
    import json
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def render_component(manifest):
    """Markdown lines for a component manifest dict the caller already validated; every string goes through code()."""
    kind = manifest["kind"]
    body = manifest[kind]
    req = body["requirements"]
    out = [f"## Component\n\n- Kind: {code(kind)}\n- Architecture: {code(body['guest_arch'])}\n\n",
           "### Requirements\n\n",
           "These are descriptor-declared requirements to compare against a selected signed base, "
           "not evidence that it provides them.\n\n",
           f"- Filesystem ABI: {code(req['filesystem_abi'])}\n- libc: {code(req['libc'])}\n"]
    if "loader" in req:
        out.append(f"- Loader: {code(req['loader'])}\n")
    out.append(f"- Minimum kernel: {code(req['minimum_kernel'])}\n"
               "- Required capabilities: " + (", ".join(code(c) for c in req["required_capabilities"]) or "none") + "\n")
    if kind == "application_component":
        out.append("\n### Entrypoints\n\n")
        out += [f"- {code(e['name'])}: {code(' '.join(map(str, e['argv'])))}\n" for e in body["entrypoints"]] or ["none\n"]
    else:
        out.append("\n### Dependencies (in order)\n\n")
        out += [f"{i}. {code(d['reference'])} {code(d['manifest_sha256'])}\n"
                for i, d in enumerate(body["dependencies"], 1)] or ["none\n"]
    out.append("\n### Policy documents\n\n")
    out += [f"- {code(f['path'])}, {code(f['size'])} bytes\n" for f in manifest["files"]] or ["none\n"]
    out.append("\n")
    return out
