"""Bundled static assets: the response type, the font CSS and the file loader.

Pages are self-contained and uncached; the only things the server hands out
with a long cache lifetime are files shipped inside the package. Everything
here is an exact-name lookup into a fixed table, so a request path is never
used as a filename. New asset kinds (for example a script) belong in `_FILES`
and reuse `Asset` unchanged.
"""

import hashlib
from dataclasses import dataclass
from functools import lru_cache
from importlib import resources

IMMUTABLE = "public, max-age=31536000, immutable"


@dataclass(frozen=True)
class Asset:
    """A response whose body is bytes, sent verbatim by the server."""
    body: bytes
    content_type: str
    cache_control: str = IMMUTABLE


# (family, css weight, file name). The file name is the whole public name.
FONT_FACES = (
    ("IBM Plex Sans", 400, "IBMPlexSans-Regular.woff2"),
    ("IBM Plex Sans", 500, "IBMPlexSans-Medium.woff2"),
    ("IBM Plex Sans", 600, "IBMPlexSans-SemiBold.woff2"),
    ("IBM Plex Sans", 700, "IBMPlexSans-Bold.woff2"),
    ("IBM Plex Mono", 400, "IBMPlexMono-Regular.woff2"),
    ("IBM Plex Mono", 500, "IBMPlexMono-Medium.woff2"),
    ("IBM Plex Mono", 600, "IBMPlexMono-SemiBold.woff2"),
)

FONT_PREFIX = "/static/fonts/"
FONT_FILES = tuple(name for _, _, name in FONT_FACES)

# route path -> (package-relative directory parts, file name, content type)
_FILES = {FONT_PREFIX + name: (("static", "fonts"), name, "font/woff2")
          for name in FONT_FILES}


def _read(parts, name):
    """The bytes of a bundled file, or None if it is not there."""
    try:
        node = resources.files("retrust")
        for part in parts:
            node = node.joinpath(part)
        return node.joinpath(name).read_bytes()
    except (OSError, ValueError, TypeError, ModuleNotFoundError):
        return None


@lru_cache(maxsize=None)
def _cached(path):
    parts, name, kind = _FILES[path]
    body = _read(parts, name)
    return None if body is None else Asset(body, kind)


def static_asset(path):
    """The Asset for an exact route path, else None (the caller sends 404).

    Anything not in the fixed table is rejected before any file is touched,
    including paths with dot segments, separators or backslashes.
    """
    if not isinstance(path, str) or ".." in path or "\\" in path:
        return None
    if path not in _FILES:
        return None
    asset = _cached(path)
    if asset is None:
        _cached.cache_clear()             # do not remember a miss forever
    return asset


def is_static_path(path):
    return isinstance(path, str) and path in _FILES


@lru_cache(maxsize=None)
def _version(name):
    body = _read(("static", "fonts"), name)
    return hashlib.sha256(body).hexdigest()[:8] if body else "0"


def font_face_css(served):
    """@font-face rules. served=False is for the self-contained export: it may
    only name fonts already installed, never a URL."""
    rules = []
    for family, weight, name in FONT_FACES:
        if served:
            source = 'url(%s%s?v=%s) format("woff2")' % (FONT_PREFIX, name, _version(name))
        else:
            source = 'local("%s")' % _local_name(family, weight)
        rules.append('@font-face{font-family:"%s";font-style:normal;font-weight:%d;'
                     'font-display:swap;src:%s}' % (family, weight, source))
    return "".join(rules)


_WEIGHT_NAMES = {400: "", 500: " Medium", 600: " SemiBold", 700: " Bold"}


def _local_name(family, weight):
    return family + _WEIGHT_NAMES[weight]
