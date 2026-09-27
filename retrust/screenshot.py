"""Render a report to PNG with headless Chrome.

Two jobs. Documentation -- Arsenal asks for three pages of docs and a demo
video, and a tool that can shoot its own screenshots keeps those current
instead of letting them drift from the code. And review -- a report you can
look at is a report whose layout bugs you notice.

Chrome is found on the system rather than pulled in as a dependency; nothing
here is required for scoring, so a machine without a browser loses screenshots
and nothing else. Pillow, if installed, trims the blank tail off a full-page
capture; without it the capture still works, just padded.
"""

import re
import shutil
import subprocess
import tempfile
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


def _trim(png_path):
    """Crop the uniform tail a tall full-page capture leaves behind."""
    try:
        from PIL import Image
    except ImportError:
        return False

    with Image.open(png_path) as image:
        rgb = image.convert("RGB")
        width, height = rgb.size
        background = rgb.getpixel((width - 2, height - 2))

        # Walk up from the bottom until a row differs from the background.
        last = height
        for y in range(height - 1, 0, -8):
            row = [rgb.getpixel((x, y)) for x in range(0, width, max(1, width // 40))]
            if any(pixel != background for pixel in row):
                last = min(height, y + 40)
                break
        if last < height:
            rgb.crop((0, 0, width, last)).save(png_path)
            return True
    return False


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
        "--no-sandbox", "--force-device-scale-factor=2",
        f"--window-size={width},{shot_height}",
        f"--screenshot={target}",
        (temporary or source).as_uri(),
    ]

    try:
        result = subprocess.run(command, capture_output=True, timeout=timeout, text=True)
    except subprocess.TimeoutExpired:
        raise SystemExit(f"{browser} timed out rendering {source}")
    finally:
        if temporary:
            temporary.unlink(missing_ok=True)

    if not target.exists():
        detail = (result.stderr or result.stdout or "").strip().splitlines()
        raise SystemExit("Screenshot failed: " + (detail[-1] if detail else "no output"))

    trimmed = _trim(target) if full_page else False
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
