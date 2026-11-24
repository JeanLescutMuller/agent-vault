"""Settings, paths and small helpers shared by every part of agent-vault (DESIGN.md §1, §12).

Every path and setting comes from the environment, so the tests run everything in a sandbox folder as Jean's user;
the installed copy (user av-vault) sets none of them and gets the defaults below.
Reads and writes nothing itself, except log_event: <AV_HOME>/events.jsonl (what happened, never a value).
"""
import datetime
import html
import json
import os
import re
import unicodedata
import urllib.parse

HOME = os.environ.get("AV_HOME", "/var/agent-vault")            # av-vault's own state, 700: bw logins, key, fingerprints, grants
OUT = os.environ.get("AV_OUT", "/var/agent-vault-out")           # what Jean's user may read (750, group staff): alerts
BW = os.environ.get("AV_BW", "/opt/homebrew/bin/bw")
BW_DIR = os.path.join(HOME, "bw", "main")                        # agent-vault's own Bitwarden CLI login (BITWARDENCLI_APPDATA_DIR)
BW_FOLDER = os.environ.get("AV_FOLDER", "Agent auto-login")      # Jean's name (2026-11-05): the only folder agent-vault writes to
# sandbox only (Jean, 2026-11-21, a test on his real vault): read, fingerprint and write this one folder, nothing else
ONLY_FOLDER = os.environ.get("AV_ONLY_FOLDER") == "1"
KEY_FIELD = "pwl key"  # the password layer's old site key, read only as another name of an item (DESIGN.md §11)


def now():
    """(ts, dt): Unix seconds and ISO 8601 UTC."""
    t = datetime.datetime.now(datetime.timezone.utc)
    return int(t.timestamp()), t.strftime("%Y-%m-%dT%H:%M:%SZ")


def log_event(**d_ev):
    ts, dt = now()
    with open(os.path.join(HOME, "events.jsonl"), "a") as f:
        f.write(json.dumps({"ts": ts, "dt": dt, **d_ev}, ensure_ascii=False) + "\n")


def reg(origin):
    """The registrable domain of an origin: https://www.shop.example.co.uk → example.co.uk."""
    l = re.sub(r"^https?://|:\d+$", "", origin).lower().split(".")
    return ".".join(l[-3:] if len(l) >= 3 and l[-2] in ("co", "com", "ac", "org", "gov", "net") and len(l[-1]) == 2 else l[-2:])


def domain(url):
    """The registrable domain of a URL or a bare host ("" for a page that is not on the web: a test's file://)."""
    try:
        host = urllib.parse.urlsplit(url if "://" in url else "https://" + url).hostname or ""
    except ValueError:  # an item named "Amazon Europe (.de, .fr)": no domain
        return ""
    return reg(host) if "." in host and not re.fullmatch(r"[\d.]+", host) else host  # an IP address stays whole


def fold(t):
    """Lower case, accents off: "CentraleSupélec" → "centralesupelec"."""
    return "".join(c for c in unicodedata.normalize("NFKD", str(t).lower()) if not unicodedata.combining(c))


def unescape(s):
    """HTML entities that end with ";" only: html.unescape also reads "&region_code=" in a link as "®ion_code=" (TP-Link, 2026-10-22)."""
    return re.sub(r"&(?:#\d+|#[xX][0-9a-fA-F]+|[A-Za-z][A-Za-z0-9]*);", lambda m: html.unescape(m.group(0)), s)


def key_of(it):
    """An item's other name: the password layer's site key in its field "pwl key", else its name."""
    return next((f.get("value") for f in it.get("fields") or [] if f.get("name") == KEY_FIELD and f.get("value")), it.get("name", ""))


def item_domains(it):
    """The websites (registrable domains) an item's password belongs to: its URIs, else its name."""
    l_uri = [u.get("uri") for u in (it.get("login") or {}).get("uris") or [] if u.get("uri")]
    s = {domain(u) for u in l_uri}
    if not any(u.startswith("file:") for u in l_uri):  # a local page (a test's file://) has the domain ""
        s.discard("")
    return s or ({domain(key_of(it))} - {""})
