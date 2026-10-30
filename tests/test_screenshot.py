"""The screenshot trimmer's measuring half, without a browser.

The capture itself needs Chromium and is exercised by `make docs`; what these
tests pin is the stdlib scanline measurer -- the part that decides where a
tall canvas's content ends, and that silently doing nothing would turn every
documentation shot into a mile of dead canvas again.
"""

import struct
import zlib

from retrust import screenshot


def _png(path, rows, channels=3):
    """A minimal 8-bit PNG: filter-0 scanlines, one IDAT, stdlib only."""
    width = len(rows[0]) // channels
    raw = b"".join(b"\x00" + row for row in rows)

    def chunk(kind, body):
        return (struct.pack(">I", len(body)) + kind + body
                + struct.pack(">I", zlib.crc32(kind + body) & 0xFFFFFFFF))

    colour = 2 if channels == 3 else 6
    path.write_bytes(
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", struct.pack(">IIBBBBB", width, len(rows), 8, colour,
                                     0, 0, 0))
        + chunk(b"IDAT", zlib.compress(raw))
        + chunk(b"IEND", b""))
    return path


def _row(seed, width=32, channels=3):
    return bytes((seed * 31 + i * 7) % 256 for i in range(width * channels))


def test_a_dead_tail_is_measured_to_the_content_edge(tmp_path):
    content = [_row(y) for y in range(300)]
    tail = [_row(999)] * 2000
    png = _png(tmp_path / "shot.png", content + tail)
    measured = screenshot._content_height(png)
    assert measured is not None
    # The edge sits at the content boundary, within a row either side.
    assert 299 <= measured <= 301


def test_a_pinned_chip_inside_the_slack_does_not_hide_the_tail(tmp_path):
    """The sidebar's bottom chip breaks the tail's uniformity; the run that
    crosses the slack boundary is still the one that decides."""
    content = [_row(y) for y in range(300)]
    tail = [_row(999)] * 2000
    chip = [_row(50 + y) for y in range(120)]      # varying rows at the bottom
    png = _png(tmp_path / "shot.png", content + tail + chip)
    measured = screenshot._content_height(png)
    assert measured is not None and 299 <= measured <= 301


def test_a_flat_band_inside_the_chip_zone_is_not_a_tail(tmp_path):
    """A flat run living wholly inside the bottom slack must not trim the
    page: content that genuinely fills the canvas stays untouched."""
    filler = [_row(y) for y in range(2400)]        # varying to the end...
    flat = [_row(7)] * (screenshot.MIN_TAIL_ROWS + 60)   # ...but a flat band
    png = _png(tmp_path / "shot.png", filler + flat)
    assert screenshot._content_height(png) is None


def test_a_full_canvas_has_no_tail_to_measure(tmp_path):
    png = _png(tmp_path / "shot.png", [_row(y) for y in range(1200)])
    assert screenshot._content_height(png) is None


def test_short_repeat_runs_between_sections_are_content(tmp_path):
    """Gaps between page sections repeat for tens of rows; only a run long
    enough AND reaching the bottom region reads as canvas."""
    page = []
    for section in range(6):
        page += [_row(section * 100 + y) for y in range(150)]
        page += [_row(1000 + section)] * 80        # a section gap, sub-MIN
    page += [_row(999)] * 1500                     # then the true tail
    png = _png(tmp_path / "shot.png", page)
    measured = screenshot._content_height(png)
    expected = 6 * (150 + 80)
    assert measured is not None
    assert expected - 1 <= measured <= expected + 1


def test_rgba_and_up_filtered_tails_measure_too(tmp_path):
    """Chromium sometimes writes RGBA and encodes dead rows as Up-zero."""
    width, channels = 32, 4
    content = [bytes((y + i) % 256 for i in range(width * channels))
               for y in range(300)]
    raw = b"".join(b"\x00" + row for row in content)
    raw += b"\x02" + bytes(width * channels)       # one Up row copying the last
    raw += (b"\x02" + bytes(width * channels)) * 1500

    def chunk(kind, body):
        return (struct.pack(">I", len(body)) + kind + body
                + struct.pack(">I", zlib.crc32(kind + body) & 0xFFFFFFFF))

    png = tmp_path / "shot.png"
    png.write_bytes(
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", struct.pack(">IIBBBBB", width, 300 + 1501, 8, 6, 0, 0, 0))
        + chunk(b"IDAT", zlib.compress(raw))
        + chunk(b"IEND", b""))
    measured = screenshot._content_height(png)
    assert measured is not None and 299 <= measured <= 302


def test_a_file_this_codec_cannot_read_is_left_alone(tmp_path):
    odd = tmp_path / "not.png"
    odd.write_bytes(b"GIF89a not a png at all")
    assert screenshot._content_height(odd) is None
