"""Fingerprints and masking (DESIGN.md §7, §8): every long-lived secret of the vault known only by keyed fingerprints, and
`vault internal mask [--out]`, which replaces each one in a text by a token.

  sync:  every secret → its folded, compacted form (seq_of) → the whole value if 8–11 characters, else every 12-character
         piece → fingerprint (BLAKE2b keyed with agent-vault's own random key) → its item's id and category
  mask:  the text's folded, compacted form (and reversed, and every Base64 / hex / URL-encoded run decoded) → every window of
         12 characters and of each short length → a known fingerprint → <vault-secret <item id>>; then what only looks like a
         password → stored encrypted → <suspected-secret <random id>>; login codes, links, addresses untouched
  --out: vault secrets only; a hit = a leak: one alert line in <AV_OUT>/alerts.jsonl (`vault-admin file-alerts` files it)

Reads and writes (AV_HOME, av-vault only): key (32 random bytes, 600), fingerprints.json ({"short": [lengths], "fp": {hex:
[item id, category]}}), suspected/<id>.json (the value, AES-GCM), suspected_index.json (fingerprint → id: one id per value),
pending_saves.json (save-token requests). AV_OUT: alerts.jsonl (item, category, caller; never a value).
"""
import base64
import hashlib
import json
import os
import re
import secrets as _secrets
import unicodedata
import urllib.parse

from .common import HOME, OUT, now

PIECE = 12   # a value of 12+ characters is known by every 12-character piece of it
MIN_LEN = 8  # shorter values (PINs) are skipped: they would match ordinary text
# look-alike letters folded to Latin, invisible characters dropped, separators dropped: agent-firewall's text.py (_fold, compact)
D_FOLD = str.maketrans("аеорсухіјѕԁԛԝАВЕКМНОРСТХІЈЅαονρτυχΑΒΕΗΙΚΜΝΟΡΤΥΧ", "aeopcyxijsdqwABEKMHOPCTXIJSaovptuxABEHIKMNOPTYX")
INVISIBLE = re.compile("[­͏؜ᅟᅠ឴឵᠎​-‏‪-‮⁠-⁯ㅤ︀-️﻿ﾠ\U000e0000-\U000e007f]")
SEP = re.compile(r"[\s.\-_/·•|,;:'\"()\[\]+]")
D_DIGIT = {w: str(i) for i, l_w in enumerate([
    "zero null zéro", "one eins un uno", "two zwei deux due", "three drei trois tre", "four vier quatre quattro",
    "five fünf cinq cinque", "six sechs sei", "seven sieben sept sette", "eight acht huit otto", "nine neun neuf nove"])
    for w in l_w.split()}
DIGIT_WORDS = re.compile(r"\b(" + "|".join(sorted(D_DIGIT, key=len, reverse=True)) + r")\b", re.I)
TOKEN = re.compile(r"<(?:vault|suspected)-secret [0-9a-f]{8}>")
# what only looks like a password: after a label, or 8–64 characters without spaces mixing lower, upper and digits, or letters,
# digits and a symbol (a false positive only hides a harmless word, Jean 2026-11-21)
LABEL = re.compile(r"(?i)\b(?:password|passwort|kennwort|mot de passe|contrase[ñn]a|wachtwoord|senha|pwd|mdp|pin|passcode)\b"
                   r"(?:\s*(?:temporaire|temporary|provisoire|tempor[äa]r|initial))?\s*(?:is|est|ist|:|=)\s*(\S{4,64})")
WORD = re.compile(r"(?<![^\s<>\"'()\[\]{}])[^\s<>\"'()\[\]{}]{8,64}(?![^\s<>\"'()\[\]{}])")  # a whole word only, never
# a 64-character slice of a longer one (2026-11-22, robotics-radar: a 382-character Facebook share link, cut into slices, one
# slice "…ive+Coatings+by+Robot+Cleaning" taken for a password)
# words after a label that are no value (`vault show`: "password:  yes, last changed…"; a form: "Password: required")
NOT_A_VALUE = {"yes", "none", "required", "optional", "missing", "changed", "hidden", "redacted", "unknown", "empty", "invalid",
               "incorrect", "wrong", "expired", "reset", "forgotten", "forgot", "please", "field"}


def fold_char(c):
    return unicodedata.normalize("NFKC", c).translate(D_FOLD).lower()


def seq_of(text):
    """The form secrets are compared in, with where each character came from: [(char, start, end)]. Look-alikes and case
    folded, invisible characters and separators dropped, digit words as digits ("seven five six" → 756)."""
    d_word = {m.start(): (m.end(), D_DIGIT[m.group(1).lower()]) for m in DIGIT_WORDS.finditer(text)}
    out, i, n = [], 0, len(text)
    while i < n:
        if i in d_word:
            end, dig = d_word[i]
            out.append((dig, i, end))
            i = end
            continue
        c = text[i]
        if not (SEP.match(c) or INVISIBLE.match(c)):
            out.extend((x, i, i + 1) for x in fold_char(c) if not SEP.match(x))
        i += 1
    return out


def decoded_runs(text):
    """Every Base64, hex and URL-encoded run of the text that decodes to printable text: [(start, end, decoded)]."""
    out = []
    for m in re.finditer(r"[A-Za-z0-9+/_-]{12,}={0,2}", text):
        run = m.group(0)
        for d_how in ({"validate": True}, {"altchars": b"-_"}):
            try:
                s = base64.b64decode(run + "=" * (-len(run) % 4), **d_how).decode("utf-8")
            except ValueError:
                continue
            if len(s) >= 6 and all(c.isprintable() or c in "\n\r\t" for c in s):
                out.append((m.start(), m.end(), s))
                break
    for m in re.finditer(r"\b(?:[0-9a-fA-F]{2}){6,}\b", text):
        try:
            s = bytes.fromhex(m.group(0)).decode("utf-8")
        except ValueError:
            continue
        if all(c.isprintable() for c in s):
            out.append((m.start(), m.end(), s))
    for m in re.finditer(r"[^\s%]*(?:%[0-9A-Fa-f]{2}[^\s%]*)+", text):
        s = urllib.parse.unquote(m.group(0))
        if s != m.group(0):
            out.append((m.start(), m.end(), s))
    return out


SYM = "!#$%&*+=?^~@"
EDGE = "*`'\"()<>[]{}.,;:!?_#|"


def looks_secret(w):
    """A word with no label that looks like a password: only password characters, lower and upper case, a digit, and a
    symbol inside it (Ph8#nQ2vLx5w). Never a name or an id (H-Frank-1, GPT-4o, a Todoist id: no symbol), a number, a date,
    a time, an assignment's name, a query string, URL-encoded text. 2026-11-21, measured on 72,356 real tool outputs of a
    week: the old rule (any word with lower, upper and digit) masked something in 27.1 % of them, this one in < 1 %. A
    password with a label ("password: …") is caught by LABEL; any of Jean's own secrets by its fingerprint."""
    if "://" in w or w.lower().startswith("www.") or "/" in w or re.search(r"@[\w-]+\.", w) or TOKEN.search(w):
        return False
    w = w.strip(EDGE)
    if "=" in w and ("&" in w or "?" in w):  # a query string: data
        return False
    m = re.fullmatch(r"-{0,2}[A-Za-z_][\w.\-]*[:=]=?(.*)", w)  # name=value, --flag=value, key:value: the value alone
    if m:
        w = m.group(1).strip(EDGE)
    if not 8 <= len(w) <= 64 or re.search(r"%[0-9A-Fa-f]{2}", w) or not re.fullmatch(r"[A-Za-z0-9" + re.escape(SYM) + r"\-]+", w):
        return False
    return bool(re.search(r"[a-z]", w) and re.search(r"[A-Z]", w) and re.search(r"\d", w) and re.search("[" + re.escape(SYM) + "]", w[1:-1]))


class Masker:
    def __init__(self):
        self.key = None
        self.fp, self.short, self.names = {}, [], {}
        self.loaded = False

    # ------------------------------------------------------------ state
    def load(self):
        if self.loaded:
            return
        os.makedirs(HOME, exist_ok=True)
        p = os.path.join(HOME, "key")
        if not os.path.exists(p):
            fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            os.write(fd, _secrets.token_bytes(32))
            os.close(fd)
        self.key = open(p, "rb").read()
        d = load_json(os.path.join(HOME, "fingerprints.json"), {})
        self.fp, self.short, self.names = d.get("fp", {}), d.get("short", []), d.get("names", {})
        self.loaded = True

    def h(self, s):
        return hashlib.blake2b(s.encode(), key=self.key, digest_size=16).hexdigest()

    # ------------------------------------------------------------ sync
    def sync(self, l_secret, d_name=None):
        """l_secret: [(item id, category, value)] → the new fingerprints; d_name: item id → its name (no secret: for the alert
        task). Returns the counts, never a value."""
        self.load()
        d_fp, s_short, d_item, n_skip = {}, set(), {}, 0
        for iid, cat, v in l_secret:
            s = "".join(c for c, _, _ in seq_of(v))
            if len(s) < MIN_LEN:
                n_skip += 1
                continue
            l_w = [s] if len(s) < PIECE else [s[i:i + PIECE] for i in range(len(s) - PIECE + 1)]
            if len(s) < PIECE:
                s_short.add(len(s))
            for w in l_w:
                d_fp[self.h(w)] = [iid[:8], cat]
            d_item.setdefault(iid[:8], set()).update(self.h(w) for w in l_w)
        old = {}
        for f, (iid, _) in self.fp.items():
            old.setdefault(iid, set()).add(f)
        n_add = len(set(d_item) - set(old))
        n_del = len(set(old) - set(d_item))
        n_chg = sum(1 for k in set(d_item) & set(old) if d_item[k] != old[k])
        self.fp, self.short = d_fp, sorted(s_short)
        self.names = {k[:8]: v for k, v in (d_name or {}).items() if k[:8] in d_item}
        save_json(os.path.join(HOME, "fingerprints.json"), {"short": self.short, "fp": self.fp, "names": self.names})
        return {"secrets": len(l_secret) - n_skip, "items": len(d_item), "added": n_add, "changed": n_chg, "removed": n_del,
                "skipped (under 8 characters)": n_skip}

    def add(self, iid, cat, v, name=""):
        """One new secret (a new password just saved, a token just typed): its fingerprints added at once, so an echo of it
        on the next page is masked before the next full sync."""
        self.load()
        s = "".join(c for c, _, _ in seq_of(v))
        if len(s) < MIN_LEN:
            return
        for w in ([s] if len(s) < PIECE else [s[i:i + PIECE] for i in range(len(s) - PIECE + 1)]):
            self.fp[self.h(w)] = [iid[:8], cat]
        if len(s) < PIECE and len(s) not in self.short:
            self.short = sorted(self.short + [len(s)])
        if name:
            self.names[iid[:8]] = name
        save_json(os.path.join(HOME, "fingerprints.json"), {"short": self.short, "fp": self.fp, "names": self.names})

    # ------------------------------------------------------------ finding
    def spans(self, text):
        """[(start, end, item id, category)] of every vault secret found in the text."""
        self.load()
        if not self.fp:
            return []
        out = self._spans_seq(seq_of(text))
        for a, b, s in decoded_runs(text):  # a secret inside an encoded run: the whole run
            hit = self._spans_seq(seq_of(s))
            if hit:
                out.append((a, b, hit[0][2], hit[0][3]))
        return out

    def _spans_seq(self, sq):
        out = []
        for seq in (sq, sq[::-1]):
            s = "".join(c for c, _, _ in seq)
            for n in [PIECE] + self.short:
                for i in range(len(s) - n + 1):
                    hit = self.fp.get(self.h(s[i:i + n]))
                    if hit:
                        l = seq[i:i + n]
                        out.append((min(x[1] for x in l), max(x[2] for x in l), hit[0], hit[1]))
        return out

    def mask(self, text, out=False, caller=None, suspects=True):
        """(masked text, [categories]). out: vault secrets only, and each item found gets one alert line. suspects=False:
        vault secrets only, no alert (the daemon's own words: an agent's name like agentA1 is no password)."""
        l_sp = sorted(self.spans(text))
        l_cat = sorted({c for _, _, _, c in l_sp})
        repl = [(a, b, f"<vault-secret {iid}>") for a, b, iid in merge(l_sp)]
        if out and l_sp:
            ts, dt = now()
            os.makedirs(OUT, exist_ok=True)
            with open(os.path.join(OUT, "alerts.jsonl"), "a") as f:
                for iid, cat in sorted({(i, c) for _, _, i, c in l_sp}):
                    f.write(json.dumps({"ts": ts, "dt": dt, "item": iid, "name": self.names.get(iid, ""), "category": cat, "caller": caller or {}}) + "\n")
        l_rev = self._revealed_values() if os.path.exists(os.path.join(HOME, "revealed.json")) else []
        if out:  # a revealed temporary secret leaving: reported (the hook sends it back to its source only), never masked
            for sid, v in l_rev:
                if v and (v in text or v in urllib.parse.unquote(text)):
                    l_cat.append(f"revealed:{sid}")
        rev_values = {v for _, v in l_rev}
        if suspects and not out:
            taken = [(a, b) for a, b, _ in repl]
            free = lambda a, b: not any(a < y and x < b for x, y in taken) and not any(a < m.end() and m.start() < b for m in TOKEN.finditer(text))
            for m in LABEL.finditer(text):
                v = m.group(1).rstrip(".,;:!?)")
                a = m.start(1)
                if free(a, a + len(v)) and not re.fullmatch(r"\d{4,8}", v) and "://" not in v and v.lower() not in NOT_A_VALUE and v not in rev_values:
                    repl.append((a, a + len(v), f"<suspected-secret {self.suspect(v)}>"))
                    taken.append((a, a + len(v)))
            for m in WORD.finditer(text):
                v = m.group(0).rstrip(".,;:!?")
                a = m.start()
                if looks_secret(v) and free(a, a + len(v)) and v not in rev_values:
                    repl.append((a, a + len(v), f"<suspected-secret {self.suspect(v)}>"))
                    taken.append((a, a + len(v)))
            if len(repl) > len(merge(l_sp)):
                l_cat.append("suspected")
        for a, b, t in sorted(repl, reverse=True):
            text = text[:a] + t + text[b:]
        return text, l_cat

    # ------------------------------------------------------------ suspected secrets (stored for good, Jean 2026-11-21)
    def _aead(self):
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        return AESGCM(hashlib.blake2b(b"suspected", key=self.key, digest_size=32).digest())

    def suspect(self, v):
        """The random id of a value that looks like a password: the same value always gets the same id."""
        self.load()
        p_idx = os.path.join(HOME, "suspected_index.json")
        idx, f = load_json(p_idx, {}), self.h("suspected:" + v)
        if f in idx:
            return idx[f]
        sid = _secrets.token_hex(4)
        nonce = _secrets.token_bytes(12)
        os.makedirs(os.path.join(HOME, "suspected"), exist_ok=True)
        ts, dt = now()
        save_json(os.path.join(HOME, "suspected", sid + ".json"),
                  {"ts": ts, "dt": dt, "nonce": nonce.hex(), "value": self._aead().encrypt(nonce, v.encode(), sid.encode()).hex()})
        idx[f] = sid
        save_json(p_idx, idx)
        return sid

    def revealed(self):
        """{token id: {ts, why, session}}: the suspected secrets an agent revealed as temporary."""
        return load_json(os.path.join(HOME, "revealed.json"), {})

    def reveal(self, sid, why, session):
        d = self.revealed()
        ts, dt = now()
        d[sid] = {"ts": ts, "dt": dt, "why": why[:200], "session": session}
        save_json(os.path.join(HOME, "revealed.json"), d)

    def _revealed_values(self):
        return [(sid, self.suspected_value(sid)) for sid in self.revealed()]

    def suspected_value(self, sid):
        self.load()
        if not re.fullmatch(r"[0-9a-f]{8}", sid or ""):
            raise RuntimeError("a token id is 8 hex characters: the XXXX of <suspected-secret XXXX>")
        d = load_json(os.path.join(HOME, "suspected", sid + ".json"), None)
        if not d:
            raise RuntimeError(f"no suspected secret {sid}")
        return self._aead().decrypt(bytes.fromhex(d["nonce"]), bytes.fromhex(d["value"]), sid.encode()).decode()


def merge(l_sp):
    """Overlapping spans as one (the first's item)."""
    out = []
    for a, b, iid, cat in sorted(l_sp):
        if out and a < out[-1][1]:
            out[-1] = (out[-1][0], max(b, out[-1][1]), out[-1][2], out[-1][3])
        else:
            out.append((a, b, iid, cat))
    return [(a, b, iid) for a, b, iid, _ in out]


def load_json(p, default):
    try:
        return json.load(open(p, encoding="utf-8"))
    except (OSError, ValueError):
        return default


def save_json(p, d):
    tmp = p + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(d, f)
    os.replace(tmp, p)


MASK = Masker()
