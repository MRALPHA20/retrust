# Bundled fonts

IBM Plex Sans (400, 500, 600, 700) and IBM Plex Mono (400, 500, 600), served by
`retrust/assets.py` from `/static/fonts/`. Licensed under the SIL Open Font
License 1.1 (see `OFL.txt`); copyright IBM Corp., Reserved Font Name "Plex".

These are the unmodified `*-Latin1.woff2` files from the `fonts/split/woff2/`
directory of the official npm packages, renamed to drop the `-Latin1` suffix:

- `@ibm/plex-sans` 1.1.0, https://registry.npmjs.org/@ibm/plex-sans/-/plex-sans-1.1.0.tgz
- `@ibm/plex-mono` 2.5.0, https://registry.npmjs.org/@ibm/plex-mono/-/plex-mono-2.5.0.tgz

The Latin-1 subset has no U+25CF, U+25C6, U+25A0, U+2713, U+25B2, U+25BC,
U+2191 or U+2265; the browser falls back to a system font for those.
U+2013, U+00B7 and U+00D7 are present.

sha256 (also pinned in `tests/test_assets.py`; change both together):

| File | sha256 |
| --- | --- |
| IBMPlexSans-Regular.woff2 | b5ad7bd39f996144915f0ad9849a90183b27d8c28ad97ed98af5b1bebc51f6b1 |
| IBMPlexSans-Medium.woff2 | b5610af04d0d4b5a14a621d96d974b993e945a065db1a8861918f69ef9321934 |
| IBMPlexSans-SemiBold.woff2 | fff0ab3a88b0b4aa0b693e4f0201359a15183b08e3fa5696d1918d8f0ade8ad5 |
| IBMPlexSans-Bold.woff2 | 914f1400f363e636b6f9cc7965aa807ff01e93586e1437617525cba0a62aa78d |
| IBMPlexMono-Regular.woff2 | e8993d946649b9d01abb1ed06d574b19d8ea3e66b5c3948602db335c44c18e56 |
| IBMPlexMono-Medium.woff2 | 41201b658a328b9d00368215c2f1102770f80b15952ab82631e4006255e6365d |
| IBMPlexMono-SemiBold.woff2 | b7acd05041ab65f3b7039e218ddd893065e11a07e85ea85019473152a51b6b7d |
