import json
import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import policy_compose  # noqa: E402

VECTORS = json.loads((ROOT / "tests/policy-vectors/vectors.json").read_text())


class PolicyVectors(unittest.TestCase):
    def test_vectors(self):
        for v in VECTORS:
            with self.subTest(v["name"]):
                if "error" in v:
                    with self.assertRaisesRegex(ValueError, v["error"]):
                        policy_compose.compose(v["layers"])
                else:
                    self.assertEqual(policy_compose.compose(v["layers"]), v["expect"])


if __name__ == "__main__":
    unittest.main()
