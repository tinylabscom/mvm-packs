#!/usr/bin/env python3
"""Rebuild registry pages when their inputs change; stop with Ctrl+C."""

import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def snapshot(root):
    inputs = [root / "index.json", root / "revocations.toml", *(root / "packs").rglob("*")]
    return {
        path: (path.stat().st_mtime_ns, path.stat().st_size)
        for path in inputs if path.is_file()
    }


def main():
    command = [sys.executable, str(ROOT / "scripts/build-pack-pages.py")]
    subprocess.run(command, cwd=ROOT, check=False)
    previous = snapshot(ROOT)
    print("Watching index.json, revocations.toml and packs/ (Ctrl+C to stop)", flush=True)
    try:
        while True:
            time.sleep(1)
            current = snapshot(ROOT)
            if current != previous:
                previous = current
                subprocess.run(command, cwd=ROOT, check=False)
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
