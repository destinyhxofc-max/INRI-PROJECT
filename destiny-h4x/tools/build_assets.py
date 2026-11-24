"""One-off asset builder: extracts the avatar from the supplied HTML and
writes the country/subdivision list used by the geo-lock UI."""
import base64
import json
import re
from pathlib import Path

import pycountry

ROOT = Path(__file__).resolve().parent.parent
SRC = Path(r"C:\Users\User\Desktop\destiny-h4x-access.html")
AVATAR = ROOT / "app" / "static" / "img" / "avatar.jpg"
GEO = ROOT / "app" / "data" / "geo.json"


def build_avatar():
    html = SRC.read_text(encoding="utf-8")
    match = re.search(r'data:image/jpeg;base64,([A-Za-z0-9+/=\s]+?)"', html)
    if not match:
        raise SystemExit("avatar data URI not found")
    raw = base64.b64decode(re.sub(r"\s+", "", match.group(1)))
    AVATAR.parent.mkdir(parents=True, exist_ok=True)
    AVATAR.write_bytes(raw)
    print("avatar", AVATAR, len(raw), "bytes")


def build_geo():
    countries = sorted(
        ({"code": c.alpha_2, "name": c.name} for c in pycountry.countries),
        key=lambda c: c["name"],
    )
    states = {}
    for country in countries:
        try:
            subs = list(pycountry.subdivisions.get(country_code=country["code"]) or [])
        except Exception:
            subs = []
        names = sorted({s.name for s in subs})
        if names:
            states[country["code"]] = names
    GEO.parent.mkdir(parents=True, exist_ok=True)
    GEO.write_text(
        json.dumps({"countries": countries, "states": states}, ensure_ascii=False),
        encoding="utf-8",
    )
    print("geo", GEO, len(countries), "countries,", len(states), "with regions")


if __name__ == "__main__":
    build_avatar()
    build_geo()
