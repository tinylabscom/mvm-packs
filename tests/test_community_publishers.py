import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from community_publishers import validate_directory, validate_reference  # noqa: E402


def good(**changes):
    data = {"repository": "acme/packs", "workflow": ".github/workflows/publish-pack.yml",
            "ref": "refs/heads/main", "environment": "", "packs": ["tool"]}
    return data | changes


class CommunityPublisherTests(unittest.TestCase):
    def test_valid_reference_passes(self):
        validate_reference("acme", good())
        validate_reference("acme", {k: v for k, v in good().items() if k != "environment"})

    def test_bad_references_are_refused(self):
        cases = [
            ("agent", good(repository="agent/x")),            # reserved namespace
            ("acme", good(repository="other/packs")),          # owner != namespace
            ("acme", good(workflow="scripts/x.yml")),          # outside .github/workflows
            ("acme", good(ref="refs/tags/*")),               # wildcard
            ("acme", good(ref="refs/*")),                    # not tags/heads
            ("acme", good(ref="refs/tags/v*")),                # pattern, not exact
            ("acme", good(ref="refs/heads/")),                 # no name
            ("acme", good(ref="refs/heads/a/../x")),   # traversal
            ("acme", good(packs=[])),
            ("acme", good(packs=["a", "a"])),
            ("acme", good(packs=["Bad Name"])),
            ("acme", good(environment="a b")),
            ("acme", good(extra="x")),
            ("Acme", good()),                                  # namespaces are lowercase
        ]
        for owner, data in cases:
            with self.subTest(owner=owner, data=data), self.assertRaises(ValueError):
                validate_reference(owner, data)

    def test_directory_checks_every_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "acme.toml").write_text(
                'repository = "acme/packs"\nworkflow = ".github/workflows/p.yml"\n'
                'ref = "refs/heads/main"\npacks = ["tool"]\n')
            self.assertEqual(validate_directory(root), [])
            (root / "other.toml").write_text('repository = "acme/packs"\n')
            (root / "notes.md").write_text("x")
            self.assertEqual(len(validate_directory(root)), 2)
        self.assertEqual(validate_directory(Path(tmp) / "missing"), [])
