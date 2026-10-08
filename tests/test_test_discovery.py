"""Repository test helpers must not resolve to an installed tests package."""

import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]


class TestPackageDiscoveryTests(unittest.TestCase):
    def test_local_helpers_win_over_an_unrelated_tests_package(self):
        with tempfile.TemporaryDirectory() as temporary:
            foreign_package = Path(temporary) / "tests"
            foreign_package.mkdir()
            (foreign_package / "__init__.py").write_text(
                "raise RuntimeError('unrelated tests package imported')\n",
                encoding="utf-8",
            )
            result = subprocess.run(
                [
                    sys.executable,
                    "-S",
                    "-c",
                    "import tests.test_bind_image_candidate as helper; "
                    "print(helper.__file__)",
                ],
                cwd=ROOT,
                env={**os.environ, "PYTHONPATH": temporary},
                capture_output=True,
                text=True,
                timeout=30,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(
                Path(result.stdout.strip()).resolve(),
                ROOT / "tests" / "test_bind_image_candidate.py",
            )
