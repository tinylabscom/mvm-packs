#!/usr/bin/env python3
"""Rebuild registry content as the local site server serves it."""

import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def snapshot(root):
    inputs = [root / "index.json", root / "revocations.toml",
              root / "docs/publishing-a-pack.md", *(root / "packs").rglob("*")]
    return {
        path: (path.stat().st_mtime_ns, path.stat().st_size)
        for path in inputs if path.is_file()
    }


def main():
    command = [sys.executable, str(ROOT / "scripts/build-pack-pages.py")]
    subprocess.run(command, cwd=ROOT, check=True)
    subprocess.run(["node", "scripts/stage-starlight-pages.mjs"], cwd=ROOT, check=True)
    previous = snapshot(ROOT)
    server = subprocess.Popen(
        ["node", "node_modules/astro/bin/astro.mjs", "dev",
         "--host", "127.0.0.1", "--port", "8000"], cwd=ROOT
    )
    print("Preview: http://127.0.0.1:8000/mvm-packs/ — watching registry inputs (Ctrl+C to stop)", flush=True)
    try:
        while True:
            if server.poll() is not None:
                raise SystemExit(server.returncode)
            time.sleep(1)
            current = snapshot(ROOT)
            if current != previous:
                previous = current
                if subprocess.run(command, cwd=ROOT, check=False).returncode == 0:
                    subprocess.run(["node", "scripts/stage-starlight-pages.mjs"], cwd=ROOT, check=False)
    except KeyboardInterrupt:
        pass
    finally:
        server.terminate()
        server.wait()


if __name__ == "__main__":
    main()
