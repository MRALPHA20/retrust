"""Capture the documentation screenshots from the running web app.

Starts `retrust serve` on a free loopback port, drives Playwright's own
Chromium against it, and stops the server again, so a screenshot always shows
the code and index it was taken from. Headless by default; --headed opens the
browser window to watch the capture.

    python -m pip install -e '.[docs]' && python -m playwright install chromium
    python tools/capture_screenshots.py [--headed] [--out docs/assets]
    python tools/capture_screenshots.py --set review [--out DIR] [--hosted]

--set docs (the default) writes the one published screenshot. --set review
writes the review matrix (pages x widths x modes) plus manifest.json to a
scratch directory and exits non-zero on a 5xx response or a CSP violation.

Playwright is a documentation dependency only. The tool itself never imports
it: an air-gapped install needs no browser automation to assess hardware.
"""

import argparse
import json
import os
import pathlib
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parent.parent

# Published name -> page. The comparison view is the one the guide embeds.
SHOTS = {
    "workspace-comparison": "/compare?vendor_1=Siemens&product_1=SIMATIC+IPC477E+Pro"
                            "&vendor_2=Moxa&product_2=EDS-405A",
}
VIEWPORT = {"width": 1440, "height": 1000}

ALL_WIDTHS = "375,640,1024,1100,1440"
ALL_MODES = "default,reduced-motion,grayscale,print,coarse"

# (slug, path) for the review set. Parameter examples come from the manual and
# Redesign-plan section 5. "cleared-firmware" is a firmware version above every
# fixed-in version, so no advisory still applies to it.
REVIEW_PAGES = [
    ("home", "/"),
    ("home-search", "/?q=S7-1500"),
    ("score-empty", "/score"),
    ("verify-abb-ac800m", "/score?vendor=ABB&product=AC+800M"),
    ("avoid-kev-s7-1500", "/score?vendor=Siemens&product=SIMATIC+S7-1500&version=3.1.6"),
    ("avoid-restriction-hikvision", "/score?vendor=Hikvision&product=IP+Camera"),
    ("answered-ipc477e", "/score?vendor=Siemens&product=SIMATIC+IPC477E+Pro&network_exposure=ot_only"
                         "&interface=blocked&prerequisites=satisfiable&consequence=control&remediation=affected"),
    ("not-identified", "/score?vendor=Nobody&product=Nothing+123"),
    ("cleared-firmware", "/score?vendor=Moxa&product=EDS-405A&version=99.0"),
    ("compare", "/compare?c=ABB%7CAC%20800M&c=Moxa%7CEDS-405A"),
    ("about", "/about"),
    ("annex", "/annex?vendor=Moxa&product=EDS-405A"),
    ("vendor", "/vendor?name=Siemens"),
    ("timeline", "/timeline?vendor=Siemens&product=SIMATIC+S7-1500"),
    ("lev", "/lev?vendor=Siemens&product=SIMATIC+S7-1500"),
    ("ssvc", "/ssvc?vendor=Siemens&product=SIMATIC+S7-1500&version=3.1.6"),
    ("alternatives", "/alternatives?vendor=Siemens&product=SIMATIC+S7-1500"),
    ("not-found", "/no-such-page"),
]

CSP_MARKERS = ("content security policy", "content-security-policy", "violates the following")


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
    from playwright.sync_api import sync_playwright
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


def _start_server(port, hosted):
    env = dict(os.environ)
    if hosted:
        env["RETRUST_HOSTED"] = "1"
    else:
        env.pop("RETRUST_HOSTED", None)
    # cwd=ROOT so the server finds data/retrust.db.
    return subprocess.Popen([sys.executable, "-m", "retrust.cli", "serve", "--port", str(port)],
                            cwd=ROOT, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def capture_review(out_dir, widths, modes, pages, hosted=False, headed=False):
    """Return (shots, problems). Problems are 5xx responses and CSP violations."""
    from playwright.sync_api import sync_playwright
    out = pathlib.Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    port = _free_port()
    base = f"http://127.0.0.1:{port}"
    server = _start_server(port, hosted)
    shots, problems, seen = [], [], set()
    try:
        _wait_until_healthy(base, server)
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=not headed)
            for mode in modes:
                for width in widths:
                    options = {"viewport": {"width": width, "height": 900}, "device_scale_factor": 1}
                    if mode == "reduced-motion":
                        options["reduced_motion"] = "reduce"
                    elif mode == "coarse":
                        options.update(has_touch=True, is_mobile=True)
                    context = browser.new_context(**options)
                    for slug, path in pages:
                        page = context.new_page()
                        messages = []
                        page.on("console", lambda m, sink=messages: sink.append((m.type, m.text)))
                        page.on("pageerror", lambda e, sink=messages: sink.append(("pageerror", str(e))))
                        if mode == "print":
                            page.emulate_media(media="print")
                        response = page.goto(base + path, wait_until="networkidle")
                        status = response.status if response else 0
                        if mode == "grayscale":
                            page.add_style_tag(content="html{filter:grayscale(1)}")
                        name = f"{slug}__{width}__{mode}.png"
                        page.screenshot(path=str(out / name), full_page=True)
                        shots.append({"file": name, "page": slug, "path": path, "width": width,
                                      "mode": mode, "status": status,
                                      "console": [f"{kind}: {text}" for kind, text in messages]})
                        label = f"{slug} {width} {mode}"
                        if status >= 500:
                            problems.append(f"{label}: HTTP {status}")
                        for kind, text in messages:
                            if any(marker in text.lower() for marker in CSP_MARKERS):
                                problems.append(f"{label}: CSP violation: {text}")
                            # Most pages log the same thing at every width and
                            # mode; print each distinct message once.
                            if (slug, text) not in seen:
                                seen.add((slug, text))
                                print(f"[console {kind}] {slug}: {text}")
                        page.close()
                    context.close()
            browser.close()
    finally:
        server.terminate()
        server.wait(timeout=10)
    manifest = {"hosted": hosted, "shots": shots}
    (out / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return shots, problems


def _csv(value, allowed, label):
    items = [part.strip() for part in value.split(",") if part.strip()]
    bad = [item for item in items if item not in allowed]
    if bad:
        raise SystemExit(f"unknown {label}: {', '.join(bad)} (choose from {', '.join(allowed)})")
    return items


def review_main(args):
    out = pathlib.Path(args.out or tempfile.mkdtemp(prefix="retrust-review-")).resolve()
    docs = (ROOT / "docs").resolve()
    if out == docs or docs in out.parents:
        raise SystemExit("refusing to write review screenshots into docs/")
    widths = [int(w) for w in _csv(args.widths, ALL_WIDTHS.split(","), "width")]
    modes = _csv(args.modes, ALL_MODES.split(","), "mode")
    wanted = [part.strip() for part in args.pages.split(",") if part.strip()]
    pages = [(slug, path) for slug, path in REVIEW_PAGES if not wanted or slug in wanted or path in wanted]
    if not pages:
        raise SystemExit("no page matches --pages; slugs: " + ", ".join(slug for slug, _ in REVIEW_PAGES))
    shots, problems = capture_review(out, widths, modes, pages, hosted=args.hosted, headed=args.headed)
    print(f"{len(shots)} screenshots and manifest.json in {out}")
    for problem in problems:
        print("PROBLEM " + problem, file=sys.stderr)
    if problems:
        raise SystemExit(1)


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--headed", action="store_true", help="show the browser window")
    parser.add_argument("--set", dest="shot_set", choices=("docs", "review"), default="docs",
                        help="docs: the published shot (default); review: the review matrix")
    parser.add_argument("--out", default=None,
                        help="directory for the PNGs (docs: docs/assets; review: a new scratch "
                             "directory, and docs/ is refused)")
    parser.add_argument("--hosted", action="store_true", help="review set: serve with RETRUST_HOSTED=1")
    parser.add_argument("--widths", default=ALL_WIDTHS, help="review set: comma-separated widths")
    parser.add_argument("--modes", default=ALL_MODES, help="review set: comma-separated modes")
    parser.add_argument("--pages", default="",
                        help="review set: comma-separated slugs or exact paths, e.g. '/,about'")
    args = parser.parse_args()
    if args.shot_set == "review":
        review_main(args)
        return
    out = args.out or str(ROOT / "docs" / "assets")
    pathlib.Path(out).mkdir(parents=True, exist_ok=True)
    for path in capture(out, headed=args.headed):
        print(path)


if __name__ == "__main__":
    main()
