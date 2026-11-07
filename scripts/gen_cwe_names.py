"""Regenerate frontend/src/data/cwe-names.json from the MITRE CWE catalogue.

Stdlib only. Run from anywhere: python scripts/gen_cwe_names.py
The download is held in memory and only the CSV member of the archive is read; nothing is extracted to disk.
"""

import csv
import io
import json
import re
import urllib.request
import zipfile
from pathlib import Path

URL = "https://cwe.mitre.org/data/csv/1000.csv.zip"
OUT = Path(__file__).resolve().parent.parent / "frontend" / "src" / "data" / "cwe-names.json"
ID_RE = re.compile(r"^[0-9]{1,6}$")


def fetch(url: str) -> bytes:
    with urllib.request.urlopen(url, timeout=60) as resp:
        return resp.read()


def read_names(archive: bytes) -> dict[str, str]:
    with zipfile.ZipFile(io.BytesIO(archive)) as zf:
        members = [m for m in zf.infolist() if m.filename.lower().endswith(".csv")]
        if len(members) != 1:
            raise SystemExit(f"expected exactly one CSV in the archive, found {len(members)}")
        print(f"csv member: {members[0].filename}")
        text = zf.read(members[0]).decode("utf-8-sig")
    names: dict[str, str] = {}
    for row in csv.DictReader(io.StringIO(text)):
        cwe_id = (row.get("CWE-ID") or "").strip()
        name = " ".join((row.get("Name") or "").split())
        if ID_RE.match(cwe_id) and name:
            names[str(int(cwe_id))] = name
    return names


def main() -> None:
    names = read_names(fetch(URL))
    ordered = {k: names[k] for k in sorted(names, key=int)}
    OUT.parent.mkdir(parents=True, exist_ok=True)
    with open(OUT, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(json.dumps(ordered, indent=0, ensure_ascii=False) + "\n")
    print(f"wrote {len(ordered)} entries to {OUT}")


if __name__ == "__main__":
    main()
