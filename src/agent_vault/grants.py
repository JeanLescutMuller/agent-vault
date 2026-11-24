"""Grants (DESIGN.md §4): Jean's permission for one Claude session to use some items, a whole folder or a website, for a
time, with abilities. Made only by `sudo vault-admin grant` (the daemon checks the caller is root); the session is the UUID
the client sends (§2: trusted, rogue agents are out of scope).

Reads and writes <AV_HOME>/grants.json: [{"ts", "dt", "session", "targets", "can", "until_ts"}].
A target: "folder:<name>", "site:<domain>", or an item (the start of its id, its exact name, or its old site key).
A standing grant (Jean, 2026-11-24: "any Claude session can log in to my Oxylabs dashboard on its own, with no expiry"):
session "*" (every session), until_ts null with --forever; one site: target, ability login only; ended only by revoke.
"""
import os
import re
import time

from .common import BW_FOLDER, HOME, domain, now
from .masking import load_json, save_json

ABILITIES = ("login", "new-password")
ANY = "*"  # the session of a standing grant: every session


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
        return [g for g in load_json(self.p, []) if g["until_ts"] is None or g["until_ts"] > time.time()]

    def add(self, session, targets, dur, can, forever=False):
        if session == ANY:  # a standing grant: one website, login only (Jean, 2026-11-24)
            if len(targets) != 1 or not targets[0].startswith("site:") or not domain(targets[0][5:]):
                raise RuntimeError("--any-session takes one site:<domain> (no item, no folder: a standing grant stays one website)")
            if can != ["login"]:
                raise RuntimeError("--any-session takes --can login only (no new-password)")
        elif not re.fullmatch(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", session or ""):
            raise RuntimeError("a Claude session UUID, please (its $CLAUDE_CODE_SESSION_ID), or --any-session")
        if forever and session != ANY:
            raise RuntimeError("--forever only with --any-session (a session's own grant takes --for)")
        if forever and dur:
            raise RuntimeError("--forever or --for, not both")
        if not targets:
            raise RuntimeError("what may it use? items, folder:\"<name>\" or site:<domain>")
        l_bad = [c for c in can if c not in ABILITIES]
        if l_bad:
            raise RuntimeError(f"--can takes {', '.join(ABILITIES)} (not {', '.join(l_bad)})")
        ts, dt = now()
        g = {"ts": ts, "dt": dt, "session": session, "targets": targets, "can": can, "until_ts": None if forever else ts + seconds(dur)}
        save_json(self.p, self.all() + [g])
        return g

    def revoke(self, session=None, site=None):
        """revoke(<uuid>): that session's own grants (never a standing one); revoke(ANY): every standing grant, or only the
        one of site:<domain>; revoke(None): all."""
        l = self.all()
        keep = [g for g in l if session and not (g["session"] == session and (not site or site in g["targets"]))]
        save_json(self.p, keep)
        return len(l) - len(keep)

    def live(self, session, own=False):
        """The grants that apply to this session: its own, and the standing ones unless own."""
        return [g for g in self.all() if session and (g["session"] == session or (not own and g["session"] == ANY))]

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

    @staticmethod
    def line(g):
        until = "forever" if g["until_ts"] is None else f"until {time.strftime('%Y-%m-%d %H:%M', time.localtime(g['until_ts']))}"
        if g["session"] == ANY:
            return f"any session, {until}  {', '.join(g['targets'])}  can {','.join(g['can'])}"
        return f"{g['session']}  {', '.join(g['targets'])}  can {','.join(g['can']) or '(browse only)'}  {until}"

    def summary(self, session=None):
        """Every live grant, or those that apply to this session (its own and the standing ones)."""
        return [self.line(g) for g in (self.live(session) if session else self.all())]


GRANTS = Grants()
