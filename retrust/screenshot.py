"""Render a report to PNG with headless Chrome.

Two jobs. Documentation -- Arsenal asks for three pages of docs and a demo
video, and a tool that can shoot its own screenshots keeps those current
instead of letting them drift from the code. And review -- a report you can
look at is a report whose layout bugs you notice.

Chrome is found on the system rather than pulled in as a dependency; nothing
here is required for scoring, so a machine without a browser loses screenshots
and nothing else. The blank tail a tall full-page canvas leaves behind is
handled without Pillow and without cropping: the content height is measured
straight off the PNG's compressed scanlines (stdlib only), and the page is
shot a second time at that height. The workspace pages paint a fixed sidebar
down the whole canvas and pin a chip to its bottom, so "crop the uniform
background" stopped working the day the sidebar arrived -- and an optional
dependency that silently does nothing when absent is the kind of quiet
failure this tool exists to refuse.
"""

import os
import re
import shutil
import struct
import subprocess
import tempfile
import zlib
from pathlib import Path

# Tried in order. The "new" headless mode is the one that renders correctly.
BROWSERS = ["chromium", "chromium-browser", "google-chrome", "google-chrome-stable",
            "chrome", "/usr/lib/chromium/chromium"]

DEFAULT_WIDTH = 1280
DEFAULT_HEIGHT = 900
# Tall canvas for a full-page shot; the blank tail is cropped afterwards.
FULL_PAGE_HEIGHT = 12000


def find_browser():
    """Path to a usable Chrome/Chromium, or None."""
    for name in BROWSERS:
        if path := (shutil.which(name) or (name if Path(name).exists() else None)):
            return path
    return None


def _sandbox_flags():
    """Keep Chrome's renderer sandbox on unless the environment forbids it.

    The sandbox is the main containment between a malicious page and the host,
    and these shots load a report from a privileged file:// origin -- so it
    stays on for a normal user. Chrome refuses to start the sandbox as root
    (the usual case on Kali and in containers); there --no-sandbox is the only
    way to run at all, and the page being rendered is the tool's own escaped
    HTML. RETRUST_CHROME_NO_SANDBOX=1 forces it off for any other locked-down
    environment that needs it.
    """
    forced = os.environ.get("RETRUST_CHROME_NO_SANDBOX") == "1"
    is_root = hasattr(os, "geteuid") and os.geteuid() == 0
    return ["--no-sandbox"] if (forced or is_root) else []


def _theme_variant(html_path, theme):
    """Copy the page with a theme stamped on <html>, returning the new path.

    The reports style themselves from :root[data-theme=...], so stamping the
    attribute is all it takes to shoot either theme deterministically rather
    than depending on the machine's OS setting.
    """
    source = Path(html_path).read_text(encoding="utf-8")

    # Target the <html> tag specifically. Splitting on the first ">" instead
    # lands on <!doctype html>, which silently produces an unthemed page --
    # both themes then render identically and the bug is invisible.
    match = re.search(r"<html\b[^>]*>", source, re.I)
    if match:
        tag = match.group(0)
        stamped = re.sub(r'\s+data-theme="[^"]*"', "", tag[:-1])
        stamped = source[:match.start()] + f'{stamped} data-theme="{theme}">' \
            + source[match.end():]
    else:
        stamped = f'<html data-theme="{theme}">{source}</html>'

    handle = tempfile.NamedTemporaryFile(
        "w", suffix=".html", delete=False, encoding="utf-8")
    handle.write(stamped)
    handle.close()
    return Path(handle.name)


# The tail is not one colour: a fixed sidebar paints its rail down the whole
# canvas and pins a chip to its bottom, so "crop the uniform background"
# stopped working the day the sidebar arrived. What the dead canvas IS, on
# every layout, is a long run of pixel-identical rows -- content varies line
# to line, dead canvas does not. Identical rows are detectable on the PNG's
# compressed scanlines without decoding a single pixel: an Up-filtered row of
# zeros is byte-for-byte its predecessor, and two rows carrying the same
# filter and payload repeat whenever that filter looks only sideways -- or,
# for the two filters that look upward, whenever the rows above them repeated
# too. The pinned chip sits inside BOTTOM_SLACK, so the run need not reach
# the exact bottom edge.
BOTTOM_SLACK = 700
MIN_TAIL_ROWS = 200
# CSS pixels added under the content on the second shot, so the page's own
# footer keeps its breathing room.
RESHOOT_PAD = 24


def _content_height(png_path):
    """Device-pixel height of the content in a tall capture, or None.

    None means "no dead tail worth acting on": content filled the canvas, or
    the file is not the plain 8-bit PNG Chromium writes.
    """
    try:
        height, stride, lines = _scanlines(png_path)
    except (ValueError, zlib.error, struct.error):
        return None

    # A row counts as repeating its predecessor when its scanline is
    # byte-identical to the previous one (same filter, same payload) or is
    # Up over all zeros. For the upward-looking filters identical scanlines
    # strictly prove identical rows only inductively, and Chromium anchors
    # dead canvas with Paeth lines that never get an anchor -- so the strict
    # rule finds nothing. The loose rule can in theory misread a long
    # constant-step vertical gradient as canvas, but it would have to run
    # 200+ rows AND cross into the last 700, where every page this tool
    # renders is flat; the guards below carry that assumption.
    zeros = bytes(stride)
    repeats = [False] * height
    previous = None
    for y, (kind, payload) in enumerate(lines):
        if y and ((kind == 2 and payload == zeros)
                  or (kind, payload) == previous):
            repeats[y] = True
        previous = (kind, payload)

    # The tail is the first run, walking up from the bottom, that is long
    # enough AND crosses the slack boundary: a flat band inside the pinned
    # chip sits wholly within the slack and must not read as canvas.
    boundary = height - BOTTOM_SLACK
    run = 0
    bottom = None
    for y in range(height - 1, 0, -1):
        if repeats[y]:
            bottom = y if run == 0 else bottom
            run += 1
            if run >= MIN_TAIL_ROWS and bottom >= boundary and y <= boundary:
                # Keep climbing to the run's top before cutting.
                continue
        else:
            if run >= MIN_TAIL_ROWS and bottom >= boundary and y + 1 <= boundary:
                return y + 1                  # content ends where the run began
            run = 0
    if run >= MIN_TAIL_ROWS and bottom >= boundary:
        return 1                              # the whole canvas repeats row 0
    return None


def _scanlines(path):
    """(height, stride, [(filter, payload), ...]) of a plain 8-bit PNG."""
    data = Path(path).read_bytes()
    if data[:8] != b"\x89PNG\r\n\x1a\n":
        raise ValueError("not a PNG")

    width = height = channels = None
    idat = []
    offset = 8
    while offset < len(data):
        (length,) = struct.unpack(">I", data[offset:offset + 4])
        kind = data[offset + 4:offset + 8]
        body = data[offset + 8:offset + 8 + length]
        if kind == b"IHDR":
            width, height, depth, colour = struct.unpack(">IIBB", body[:10])
            if depth != 8 or colour not in (2, 6) or body[10:13] != b"\x00\x00\x00":
                raise ValueError("not a plain 8-bit RGB/RGBA PNG")
            channels = 3 if colour == 2 else 4
        elif kind == b"IDAT":
            idat.append(body)
        elif kind == b"IEND":
            break
        offset += 12 + length

    stride = width * channels
    raw = zlib.decompress(b"".join(idat))
    lines = [(raw[y * (stride + 1)],
              raw[y * (stride + 1) + 1:(y + 1) * (stride + 1)])
             for y in range(height)]
    return height, stride, lines


def capture(html_path, out_path, width=DEFAULT_WIDTH, height=DEFAULT_HEIGHT,
            theme=None, full_page=False, timeout=60):
    """Shoot one PNG of `html_path`. Returns a dict describing what happened."""
    browser = find_browser()
    if not browser:
        raise SystemExit(
            "No Chrome or Chromium found. Install one, or open the HTML report "
            "directly -- screenshots are optional and scoring does not need them.")

    source = Path(html_path).resolve()
    if not source.exists():
        raise SystemExit(f"{source} does not exist. Generate it with --html first.")

    temporary = _theme_variant(source, theme) if theme else None
    target = Path(out_path)
    target.parent.mkdir(parents=True, exist_ok=True)
    shot_height = FULL_PAGE_HEIGHT if full_page else height

    command = [
        browser, "--headless=new", "--disable-gpu", "--hide-scrollbars",
        *_sandbox_flags(), "--force-device-scale-factor=2",
        f"--window-size={width},{shot_height}",
        f"--screenshot={target}",
        (temporary or source).as_uri(),
    ]

    try:
        result = subprocess.run(command, capture_output=True, timeout=timeout, text=True)
    except subprocess.TimeoutExpired:
        if temporary:
            temporary.unlink(missing_ok=True)
        raise SystemExit(f"{browser} timed out rendering {source}")

    if not target.exists():
        if temporary:
            temporary.unlink(missing_ok=True)
        detail = (result.stderr or result.stdout or "").strip().splitlines()
        raise SystemExit("Screenshot failed: " + (detail[-1] if detail else "no output"))

    # A tall canvas with a dead tail is re-shot at the content's own height
    # rather than cropped: one more render costs a second, and the second
    # frame is a real viewport -- the sidebar's pinned chip sits at an actual
    # bottom instead of being amputated with the tail.
    trimmed = False
    if full_page and (content := _content_height(target)):
        css_height = max(400, -(-content // 2) + RESHOOT_PAD)   # scale factor 2
        if css_height < shot_height - 40:
            command[command.index(f"--window-size={width},{shot_height}")] = \
                f"--window-size={width},{css_height}"
            retaken = subprocess.run(command, capture_output=True,
                                     timeout=timeout, text=True)
            trimmed = retaken.returncode == 0 and target.exists()
    if temporary:
        temporary.unlink(missing_ok=True)
    return {"path": str(target), "browser": Path(browser).name,
            "theme": theme or "system", "trimmed": trimmed,
            "bytes": target.stat().st_size}


def capture_both_themes(html_path, out_dir, stem=None, width=DEFAULT_WIDTH,
                        full_page=True):
    """Shoot the same page in light and dark. Useful for documentation."""
    stem = stem or Path(html_path).stem
    directory = Path(out_dir)
    return [capture(html_path, directory / f"{stem}-{theme}.png",
                    width=width, theme=theme, full_page=full_page)
            for theme in ("light", "dark")]
