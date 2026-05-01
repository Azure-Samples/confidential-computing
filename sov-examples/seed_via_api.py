"""Seed citizen records via the app's /citizen/new form POST endpoint."""
import re
import sys
import urllib.request
import urllib.parse

APP_URL = sys.argv[1] if len(sys.argv) > 1 else "http://20.214.205.239"
SEED_FILE = sys.argv[2] if len(sys.argv) > 2 else "citizen-registry-app/seed-data.sql"

COLUMNS = [
    "national_id", "first_name", "last_name", "date_of_birth", "sex",
    "region", "municipality", "address_line", "postal_code", "household_size",
    "marital_status", "employment_status", "tax_bracket", "registered_voter",
]

def parse_values(line):
    m = re.search(r"VALUES\s*\((.+)\)\s*;", line)
    if not m:
        return None
    raw = m.group(1)
    vals = []
    buf = ""
    in_q = False
    for ch in raw:
        if ch == "'" and not in_q:
            in_q = True; continue
        elif ch == "'" and in_q:
            in_q = False; continue
        elif ch == "," and not in_q:
            vals.append(buf.strip()); buf = ""; continue
        buf += ch
    vals.append(buf.strip())
    # Strip N prefix artifacts
    vals = [v.lstrip("N").strip("'") for v in vals]
    return vals

ok = 0
fail = 0
with open(SEED_FILE, encoding="utf-8") as f:
    for line in f:
        line = line.strip()
        if not line.startswith("INSERT"):
            continue
        vals = parse_values(line)
        if not vals or len(vals) != len(COLUMNS):
            print(f"SKIP bad parse: {line[:60]}...")
            fail += 1
            continue
        form = dict(zip(COLUMNS, vals))
        # registered_voter: SQL has 1/0, form expects 'on' or absent
        if form["registered_voter"] == "1":
            form["registered_voter"] = "on"
        else:
            del form["registered_voter"]
        data = urllib.parse.urlencode(form).encode()
        req = urllib.request.Request(f"{APP_URL}/citizen/new", data=data, method="POST")
        try:
            resp = urllib.request.urlopen(req)
            # Follow redirect means success (302 -> index)
            ok += 1
            if ok % 10 == 0:
                print(f"  inserted {ok}...")
        except urllib.error.HTTPError as e:
            # 302 redirect is actually success for form POST
            if e.code == 302:
                ok += 1
                if ok % 10 == 0:
                    print(f"  inserted {ok}...")
            else:
                print(f"FAIL [{e.code}]: {line[:60]}...")
                fail += 1

print(f"\nDone: {ok} inserted, {fail} failed")
