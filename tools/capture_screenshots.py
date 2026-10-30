"""Capture the documentation screenshots from the running web app.

Starts `retrust serve` on a free loopback port, drives Playwright's own
Chromium against it, and stops the server again, so a screenshot always shows
the code and index it was taken from. Headless by default; --headed opens the
browser window to watch the capture.

    python -m pip install -e '.[docs]' && python -m playwright install chromium
    python tools/capture_screenshots.py [--headed] [--out docs/assets]

Playwright is a documentation dependency only. The tool itself never imports
it: an air-gapped install needs no browser automation to assess hardware.
"""

import argparse
import pathlib
import socket
import subprocess
import sys
import time
import urllib.request

from playwright.sync_api import sync_playwright

ROOT = pathlib.Path(__file__).resolve().parent.parent

# Published name -> page. The comparison view is the one the guide embeds.
SHOTS = {
    "workspace-comparison": "/compare?vendor_1=Siemens&product_1=SIMATIC+IPC477E+Pro"
                            "&vendor_2=Moxa&product_2=EDS-405A",
}
VIEWPORT = {"width": 1440, "height": 1000}


def _free_port():
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def _wait_until_healthy(base, server, timeout=60):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if server.poll() is not None:
            raise SystemExit(f"retrust serve exited with status {server.returncode}")
        try:
            with urllib.request.urlopen(base + "/healthz", timeout=2):
                return
        except OSError:
            time.sleep(.5)
    raise SystemExit(f"retrust serve did not answer at {base} within {timeout}s")


def capture(out_dir, headed=False):
    port = _free_port()
    base = f"http://127.0.0.1:{port}"
    server = subprocess.Popen([sys.executable, "-m", "retrust.cli", "serve", "--port", str(port)],
                              cwd=ROOT, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    written = []
    try:
        _wait_until_healthy(base, server)
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=not headed)
            page = browser.new_page(viewport=VIEWPORT, device_scale_factor=1)
            for name, path in SHOTS.items():
                page.goto(base + path, wait_until="networkidle")
                target = pathlib.Path(out_dir) / f"{name}.png"
                page.screenshot(path=str(target))
                written.append(target)
            browser.close()
    finally:
        server.terminate()
        server.wait(timeout=10)
    return written


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--headed", action="store_true", help="show the browser window")
    parser.add_argument("--out", default=str(ROOT / "docs" / "assets"),
                        help="directory to write the PNGs into")
    args = parser.parse_args()
    pathlib.Path(args.out).mkdir(parents=True, exist_ok=True)
    for path in capture(args.out, headed=args.headed):
        print(path)


if __name__ == "__main__":
    main()
