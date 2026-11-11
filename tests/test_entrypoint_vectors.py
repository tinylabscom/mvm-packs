import json
import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import policy_compose  # noqa: E402

VECTORS = json.loads((ROOT / "tests/entrypoint-vectors.json").read_text())


class EntrypointVectors(unittest.TestCase):
    def test_vectors(self):
        for v in VECTORS:
            with self.subTest(v["name"]):
                args = (v["applications"], v.get("runtime_override"), v.get("workload"))
                if "error" in v:
                    with self.assertRaisesRegex(ValueError, v["error"]):
                        policy_compose.select_entrypoint(*args)
                else:
                    self.assertEqual(policy_compose.select_entrypoint(*args), v["expect"])

    def test_null_entrypoints_is_a_value_error_and_no_default_says_why(self):
        with self.assertRaisesRegex(ValueError, "entrypoints must be a list"):
            policy_compose.select_entrypoint([{"entrypoints": None}])
        with self.assertRaisesRegex(ValueError, "no application declares a default"):
            policy_compose.select_entrypoint([{"entrypoints": []}])


if __name__ == "__main__":
    unittest.main()
