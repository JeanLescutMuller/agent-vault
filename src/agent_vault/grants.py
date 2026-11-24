"""Grants (DESIGN.md §4): Jean's permission for one Claude session to use some items, a whole folder or a website, for a
time, with abilities. Made only by `sudo vault-admin grant` (the daemon checks the caller is root); the session is the UUID
the client sends (§2: trusted, rogue agents are out of scope).

Reads and writes <AV_HOME>/grants.json: [{"ts", "dt", "session", "targets", "can", "until_ts"}].
A target: "folder:<name>", "site:<domain>", or an item (the start of its id, its exact name, or its old site key).
"""
import os
import re
import time

from .common import BW_FOLDER, HOME, domain, now
from .masking import load_json, save_json

ABILITIES = ("login", "new-password")


def seconds(s):
    """"2h", "30m", "90s", "1d" → seconds."""
    m = re.fullmatch(r"(\d+)([smhd])", s or "")
    if not m:
        raise RuntimeError("--for takes a duration: 30m, 2h, 1d")
    return int(m.group(1)) * {"s": 1, "m": 60, "h": 3600, "d": 86400}[m.group(2)]


class Grants:
    def __init__(self):
        self.p = os.path.join(HOME, "grants.json")

    def all(self):
        return [g for g in load_json(self.p, []) if g["until_ts"] > time.time()]

    def add(self, session, targets, dur, can):
        if not re.fullmatch(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", session or ""):
            raise RuntimeError("a Claude session UUID, please (its $CLAUDE_CODE_SESSION_ID)")
        if not targets:
            raise RuntimeError("what may it use? items, folder:\"<name>\" or site:<domain>")
        l_bad = [c for c in can if c not in ABILITIES]
        if l_bad:
            raise RuntimeError(f"--can takes {', '.join(ABILITIES)} (not {', '.join(l_bad)})")
        ts, dt = now()
        g = {"ts": ts, "dt": dt, "session": session, "targets": targets, "can": can, "until_ts": ts + seconds(dur)}
        save_json(self.p, self.all() + [g])
        return g

    def revoke(self, session=None):
        l = self.all()
        keep = [g for g in l if session and g["session"] != session]
        save_json(self.p, keep)
        return len(l) - len(keep)

    def live(self, session):
        return [g for g in self.all() if session and g["session"] == session]

    def covers_item(self, session, info, ability=None):
        """Does a live grant of this session cover this item (an info dict from Vault.info), with this ability?"""
        for g in self.live(session):
            if ability and ability not in g["can"]:
                continue
            for t in g["targets"]:
                if t.startswith("folder:") and t[7:] == info["folder"]:
                    return True
                if t.startswith("site:") and domain(t[5:]) in info["domains"]:
                    return True
                if not t.startswith(("folder:", "site:")) and (t in (info["name"], info["key"]) or (len(t) >= 6 and info["id"].startswith(t))):
                    return True
        return False

    def covers_site(self, session, name, ability=None):
        """A tab with no item yet (a new account): a grant naming its website, or folder "Agent auto-login" (where a new
        item goes)."""
        for g in self.live(session):
            if ability and ability not in g["can"]:
                continue
            for t in g["targets"]:
                if t == f"folder:{BW_FOLDER}" or (t.startswith("site:") and domain(t[5:]) in (domain(name), name)):
                    return True
        return False

    def summary(self, session=None):
        l = [g for g in self.all() if not session or g["session"] == session]
        return [f"{g['session']}  {', '.join(g['targets'])}  can {','.join(g['can']) or '(browse only)'}  until "
                f"{time.strftime('%Y-%m-%d %H:%M', time.localtime(g['until_ts']))}" for g in l]


GRANTS = Grants()
