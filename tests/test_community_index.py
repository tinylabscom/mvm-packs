import copy
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from community_index import validate_index  # noqa: E402


def index():
    return {"schema_version": 3, "kind": "community", "packs": [{
        "namespace": "acme", "name": "tool", "description": "d",
        "publisher": {"repository": "acme/packs", "workflow": ".github/workflows/p.yml",
                      "ref": "refs/heads/main", "environment": ""},
        "versions": [
            {"version": "1.1.0", "manifest_sha256": "a" * 64, "tags": ["latest"],
             "guest_arch": "aarch64", "size_bytes": 5},
            {"version": "1.0.0", "manifest_sha256": "b" * 64},
        ]}]}


class CommunityIndexTests(unittest.TestCase):
    def test_valid_index_and_empty_index_pass(self):
        validate_index(index())
        validate_index({"schema_version": 3, "kind": "community", "packs": []})

    def test_invalid_indexes_are_refused(self):
        def change(fn):
            value = copy.deepcopy(index())
            fn(value)
            return value
        pack = lambda v: v["packs"][0]  # noqa: E731
        cases = {
            "official schema": change(lambda v: v.update(schema_version=2)),
            "wrong kind": change(lambda v: v.update(kind="official")),
            "extra top field": change(lambda v: v.update(x=1)),
            "reserved namespace": change(lambda v: pack(v).update(namespace="agent")),
            "owner mismatch": change(lambda v: pack(v)["publisher"].update(repository="other/packs")),
            "bad ref": change(lambda v: pack(v)["publisher"].update(ref="refs/tags/*")),
            "bad digest": change(lambda v: pack(v)["versions"][0].update(manifest_sha256="A" * 64)),
            "bad arch": change(lambda v: pack(v)["versions"][0].update(guest_arch="arm")),
            "bad size": change(lambda v: pack(v)["versions"][0].update(size_bytes=0)),
            "repeated tag": change(lambda v: pack(v)["versions"][1].update(tags=["latest"])),
            "unknown version field": change(lambda v: pack(v)["versions"][0].update(url="x")),
            "duplicate version": change(lambda v: pack(v)["versions"][1].update(version="1.1.0")),
            "oldest first": change(lambda v: pack(v)["versions"].reverse()),
            "unsorted packs": change(lambda v: v["packs"].insert(0, dict(copy.deepcopy(pack(v)), name="zz"))),
        }
        for label, value in cases.items():
            with self.subTest(label), self.assertRaises(ValueError):
                validate_index(value)
