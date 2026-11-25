"""Copy the UI's third-party files into pandora/web/vendor/ so the UI works with no internet.

The result is committed: a fresh clone works offline. Run again only to upgrade a version:
    python scripts/vendor_web.py
xterm.js + addon-fit: MIT. Atkinson Hyperlegible Next/Mono, Noto Sans Thai: SIL Open Font License 1.1.
"""
import re
import urllib.request
from pathlib import Path

OUT = Path(__file__).resolve().parents[1] / "pandora" / "web" / "vendor"
FONTS_CSS = ("https://fonts.googleapis.com/css2?family=Atkinson+Hyperlegible+Next:wght@400;500;600;700"
             "&family=Atkinson+Hyperlegible+Mono:wght@400;500&family=Noto+Sans+Thai:wght@400;500;600;700&display=swap")
FILES = {
    "xterm.css": "https://cdn.jsdelivr.net/npm/@xterm/xterm@5.5.0/css/xterm.css",
    "xterm.js": "https://cdn.jsdelivr.net/npm/@xterm/xterm@5.5.0/lib/xterm.js",
    "addon-fit.js": "https://cdn.jsdelivr.net/npm/@xterm/addon-fit@0.10.0/lib/addon-fit.js",
}
# Google Fonts picks the format by User-Agent: ask as a current browser to get woff2.
UA = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/130.0 Safari/537.36"}


def fetch(url: str) -> bytes:
    with urllib.request.urlopen(urllib.request.Request(url, headers=UA), timeout=60) as r:
        return r.read()


def main():
    (OUT / "fonts").mkdir(parents=True, exist_ok=True)
    for name, url in FILES.items():
        (OUT / name).write_bytes(fetch(url))
        print(f"{name:<14} {url}")
    css = fetch(FONTS_CSS).decode()
    for i, url in enumerate(dict.fromkeys(re.findall(r"url\((https://fonts\.gstatic\.com/[^)]+)\)", css))):
        family = re.search(r"/s/([^/]+)/", url).group(1)
        local = f"fonts/{family}-{i:02d}.woff2"
        (OUT / local).write_bytes(fetch(url))
        css = css.replace(url, local)
    (OUT / "fonts.css").write_text(css, encoding="utf-8")
    print(f"fonts.css      {len(list((OUT / 'fonts').iterdir()))} woff2 files")
    (OUT / "LICENSES.txt").write_text(
        "xterm.js, @xterm/addon-fit: MIT License, Copyright (c) The xterm.js authors. https://github.com/xtermjs/xterm.js\n"
        "Atkinson Hyperlegible Next, Atkinson Hyperlegible Mono: SIL Open Font License 1.1, Braille Institute.\n"
        "Noto Sans Thai: SIL Open Font License 1.1, The Noto Project Authors.\n"
        "Fonts downloaded from Google Fonts; https://openfontlicense.org\n", encoding="utf-8")


if __name__ == "__main__":
    main()
