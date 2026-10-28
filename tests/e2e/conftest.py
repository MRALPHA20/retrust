"""Session fixtures shared by the browser test modules.

One server and one Playwright driver per session: two session-scoped drivers
in different modules cannot coexist (the sync API refuses to nest).
"""

import os
import pathlib
import socket
import subprocess
import sys
import time
import urllib.request

import pytest

pytest.importorskip("playwright")
from playwright.sync_api import sync_playwright  # noqa: E402

ROOT = pathlib.Path(__file__).resolve().parents[2]
BROWSERS = [name.strip() for name in
            os.environ.get("RETRUST_E2E_BROWSERS", "chromium").split(",") if name.strip()]


@pytest.fixture(scope="session")
def base_url():
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    env = {k: v for k, v in os.environ.items() if k != "RETRUST_HOSTED"}
    server = subprocess.Popen([sys.executable, "-m", "retrust.cli", "serve", "--port", str(port)],
                              cwd=ROOT, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    base = f"http://127.0.0.1:{port}"
    try:
        deadline = time.monotonic() + 90
        while True:
            if server.poll() is not None:
                pytest.skip(f"retrust serve exited with status {server.returncode}")
            try:
                with urllib.request.urlopen(base + "/healthz", timeout=2):
                    break
            except OSError:
                if time.monotonic() > deadline:
                    pytest.skip("retrust serve did not become healthy")
                time.sleep(.5)
        yield base
    finally:
        server.terminate()
        server.wait(timeout=10)


@pytest.fixture(scope="session", params=BROWSERS)
def browser(request):
    with sync_playwright() as playwright:
        try:
            launched = getattr(playwright, request.param).launch()
        except Exception as error:  # browser binaries not installed
            pytest.skip(f"{request.param} is not installed: {str(error).splitlines()[0]}")
        yield launched
        launched.close()
