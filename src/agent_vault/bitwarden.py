"""The vault through the bw CLI (DESIGN.md §3): the daemon's own login (BW_DIR), the session key in memory only.

Items go in and out through bw's stdin and stdout, never its arguments (any program sees those with `ps`). Writes go only to
folder "Agent auto-login"; a delete goes to Bitwarden's trash, no further. Reads: every folder (details for agents; values only
inside the daemon, for typing, comparing and fingerprinting).
"""
import asyncio
import base64
import json
import os
import shutil
import subprocess
import tempfile
import threading
import time

from .common import BW, BW_DIR, BW_FOLDER, HOME, KEY_FIELD, ONLY_FOLDER, item_domains, key_of
from .scrub import SEC

# Bitwarden item types
LOGIN, NOTE, CARD, IDENTITY, SSH_KEY = 1, 2, 3, 4, 5


def enc(d):  # what `bw encode` does
    return base64.b64encode(json.dumps(d).encode()).decode()


class Vault:
    SYNC_S = 60  # an item changed on another device is seen within a minute

    def __init__(self):
        self.session, self.folder, self.t_sync, self.lock = None, None, 0, asyncio.Lock()

    def bw(self, *a, data=None):
        env = dict(os.environ, BITWARDENCLI_APPDATA_DIR=BW_DIR, BW_SESSION=self.session or "")
        p = subprocess.run([BW, *a, "--nointeraction"], input=data, capture_output=True, text=True, env=env, timeout=90)
        if p.returncode:
            raise RuntimeError(f"Bitwarden: `bw {' '.join(a[:2])}` failed: {SEC.scrub((p.stderr or p.stdout).strip()[:150])}")
        return p.stdout

    def ready(self):
        if not os.path.isdir(BW_DIR):
            raise RuntimeError("agent-vault has no Bitwarden login yet (Jean: install_system.sh, step bw login)")
        if not self.session:
            raise RuntimeError("the vault is locked: Jean runs `vault-admin unlock`")
        if time.time() - self.t_sync > self.SYNC_S:
            self.bw("sync")
            self.t_sync = time.time()

    # ------------------------------------------------------------ unlock and lock (the master password: never stored)
    def unlock(self, password):
        """Jean's master password → a session key, kept in this process only. The password goes to bw through a named pipe in
        a folder only av-vault can open: never an argument nor the environment. Returns (items in the folder, passwords)."""
        if not os.path.isdir(BW_DIR):
            raise RuntimeError("agent-vault has no Bitwarden login yet (Jean: install_system.sh, step bw login)")
        d = tempfile.mkdtemp(prefix="unlock_", dir=HOME)
        fifo = os.path.join(d, "p")
        os.mkfifo(fifo, 0o600)
        threading.Thread(target=lambda: open(fifo, "w").write(password), daemon=True).start()
        try:
            p = subprocess.run([BW, "unlock", "--raw", "--passwordfile", fifo, "--nointeraction"], capture_output=True, text=True,
                               env=dict(os.environ, BITWARDENCLI_APPDATA_DIR=BW_DIR), timeout=120)
        finally:
            try:  # a wrong password may leave the writer blocked: open the pipe once to free it
                fd = os.open(fifo, os.O_RDONLY | os.O_NONBLOCK)
                os.close(fd)
            except OSError:
                pass
            shutil.rmtree(d, ignore_errors=True)
        if p.returncode or not p.stdout.strip():
            raise RuntimeError("wrong master password, or no Bitwarden login (`bw status` as av-vault)")
        self.session, self.folder, self.t_sync = p.stdout.strip(), None, 0
        l = self.passwords()
        for _, pw in l:
            SEC.add_pw(pw)
        return len({k for k, _ in l}), len(l)

    def forget(self):
        """Lock: the session key forgotten (and locked in bw, so the key is worthless even if it was seen)."""
        if self.session:
            try:
                self.bw("lock")
            except RuntimeError:
                pass
        self.session, self.folder = None, None

    # ------------------------------------------------------------ reading
    def folder_id(self):
        if not self.folder:
            l = [f for f in json.loads(self.bw("list", "folders", "--search", BW_FOLDER)) if f["name"] == BW_FOLDER]
            if not l:  # never made here: a typo would make an empty folder that agents then fill
                raise RuntimeError(f"no folder \"{BW_FOLDER}\" in the vault: Jean creates it in Bitwarden")
            self.folder = l[0]["id"]
        return self.folder

    def everything(self):
        """Every item of the vault (every type, every folder) and the folders' names."""
        self.ready()
        d_f = {f.get("id"): f.get("name") for f in json.loads(self.bw("list", "folders"))}
        if ONLY_FOLDER:  # the sandbox on Jean's real vault: one folder, nothing else is ever read
            return json.loads(self.bw("list", "items", "--folderid", self.folder_id())), d_f
        return json.loads(self.bw("list", "items")), d_f

    def passwords(self):
        """(item name, password) for every password of the folder: the current ones, their history, and the extra fields
        where the first import (2026-10-22/24) kept earlier tries: what the scrub knows from the start."""
        self.ready()
        l = json.loads(self.bw("list", "items", "--folderid", self.folder_id()))
        return [(key_of(it), x) for it in l for x in [(it.get("login") or {}).get("password")]
                + [h.get("password") for h in it.get("passwordHistory") or []]
                + [f.get("value") for f in it.get("fields") or [] if f.get("name") != KEY_FIELD] if x]

    def resolve(self, ref, logins_only=True):
        """An item by the start of its id (6+ characters, any folder), else by its exact name or old site key: folder "Agent
        auto-login" first (the newest), then any folder. Returns (item, folder names)."""
        l, d_f = self.everything()
        if logins_only:
            l = [it for it in l if it.get("type") == LOGIN]
        fid = self.folder_id()
        by_rev = lambda x: sorted(x, key=lambda it: it.get("revisionDate", ""), reverse=True)
        l_id = [it for it in l if len(ref) >= 6 and (it.get("id") or "").startswith(ref)]
        if len(l_id) == 1:
            return l_id[0], d_f
        for l_hit in ([it for it in l if it.get("folderId") == fid and ref in (it.get("name"), key_of(it))],
                      [it for it in l if ref in (it.get("name"), key_of(it))]):
            if l_hit:
                return by_rev(l_hit)[0], d_f
        raise RuntimeError(f"no item {ref!r}: give its exact name or the id `vault find` shows")

    @staticmethod
    def info(it, d_f):
        """What the grants and tabs need of an item: no value."""
        return {"id": it["id"], "name": it.get("name") or "", "key": key_of(it), "folder": d_f.get(it.get("folderId")) or "",
                "domains": sorted(item_domains(it))}

    def same(self, ref_a, ref_b):
        """Which passwords two items share (current and older ones), compared inside the daemon: only yes/no leaves it."""
        a, _ = self.resolve(ref_a)
        b, _ = self.resolve(ref_b)

        def pws(it):
            lg = it.get("login") or {}
            return [("current", lg.get("password"))] + [(f"older #{i} (replaced {(h.get('lastUsedDate') or '?')[:10]})", h.get("password"))
                                                        for i, h in enumerate(it.get("passwordHistory") or [], 1)]
        return [f"{a.get('name')} {x}  =  {b.get('name')} {y}" for x, pa in pws(a) for y, pb in pws(b)
                if pa and pa == pb and (a["id"] != b["id"] or x < y)]

    def clash(self, dom, login, also_id=None):
        """The items, in any folder, that already hold a password for this account: this username on this website (or the
        item also_id). Not empty: no new password (Jean, 2026-11-11: a password in Bitwarden is never changed)."""
        l, d_f = self.everything()
        lo, hit = (login or "").strip().lower(), []
        for it in l:
            lg = it.get("login") or {}
            if it.get("type") != LOGIN or not lg.get("password"):
                continue
            if it["id"] == also_id or (lo and dom and (lg.get("username") or "").strip().lower() == lo and dom in item_domains(it)):
                hit.append(f"{it.get('name')} (id {it['id'][:8]}, folder {d_f.get(it.get('folderId')) or 'none'}, username {lg.get('username') or 'none'})")
        return hit

    def secrets(self):
        """Every long-lived secret of the vault, for the fingerprints (DESIGN.md §7): (item id, category, value). Never leaves
        the daemon."""
        l, _ = self.everything()
        out = []
        for it in l:
            t, iid = it.get("type"), it["id"]
            lg = it.get("login") or {}
            if t == LOGIN:
                out += [(iid, "password", v) for v in [lg.get("password")] + [h.get("password") for h in it.get("passwordHistory") or []] if v]
                if lg.get("totp"):
                    out.append((iid, "other", lg["totp"]))
            elif t == CARD and (it.get("card") or {}).get("number"):
                out.append((iid, "card", it["card"]["number"]))
            elif t == IDENTITY:
                idt = it.get("identity") or {}
                out += [(iid, "ahv" if k == "ssn" else "other", idt[k]) for k in ("ssn", "passportNumber", "licenseNumber") if idt.get(k)]
            elif t == SSH_KEY and (it.get("sshKey") or {}).get("privateKey"):
                out.append((iid, "other", it["sshKey"]["privateKey"]))
            for f in it.get("fields") or []:  # hidden custom fields (type 1) of any item; an IBAN in any field
                v = f.get("value") or ""
                if f.get("name") == KEY_FIELD or not v:
                    continue
                if iban_like(v):
                    out.append((iid, "iban", v))
                elif f.get("type") == 1:
                    out.append((iid, "other", v))
        return out

    def listing(self, l_ok):
        """The login items whose id is in l_ok: (id, name, username, websites), never a password."""
        l, _ = self.everything()
        return sorted(((it["id"], it.get("name") or "", (it.get("login") or {}).get("username") or "",
                        [u.get("uri", "") for u in (it.get("login") or {}).get("uris") or []]) for it in l
                       if it.get("type") == LOGIN and it["id"] in l_ok), key=lambda r: r[1].lower())

    # ------------------------------------------------------------ writing (folder "Agent auto-login" only)
    def get(self, iid):
        return json.loads(self.bw("get", "item", iid))

    def in_folder(self, it):
        if it.get("folderId") != self.folder_id():
            raise RuntimeError(f"{it.get('name')} is not in folder {BW_FOLDER}: agent-vault never writes elsewhere (Jean changes it in Bitwarden)")

    def save_new(self, name, url, login, pw, note, iid=None):
        """A new password: a new item of the folder; iid = this visit's own new item (the site refused its first try): that
        item gets it, and Bitwarden keeps the first in its history. Returns the item id."""
        self.ready()
        if iid:
            it = self.get(iid)
            it["login"].update(username=login, password=pw)
            it["notes"] = ((it.get("notes") or "") + "\n" + note).strip()
            return json.loads(self.bw("edit", "item", iid, data=enc(it)))["id"]
        it = {"organizationId": None, "folderId": self.folder_id(), "type": LOGIN, "name": name, "notes": note, "favorite": False,
              "fields": [], "reprompt": 0, "login": {"uris": [{"match": None, "uri": url}], "username": login, "password": pw, "totp": None}}
        return json.loads(self.bw("create", "item", data=enc(it)))["id"]

    def edit(self, iid, change):
        """change(item) edits the item in place; the item must be in the folder. Returns what change returned."""
        self.ready()
        it = self.get(iid)
        self.in_folder(it)
        out = change(it)
        self.bw("edit", "item", iid, data=enc(it))
        return out

    def delete(self, iid, dry=False):
        self.ready()
        it = self.get(iid)
        self.in_folder(it)
        if not dry:
            self.bw("delete", "item", iid)  # to the trash: never --permanent
        return (it.get("login") or {}).get("username") or ""


def iban_like(v):
    """A value that is an IBAN (2 letters, 2 digits, 10–30 letters or digits, spaces allowed): kept as category iban."""
    import re
    c = re.sub(r"\s", "", v).upper()
    return bool(re.fullmatch(r"[A-Z]{2}\d{2}[A-Z0-9]{10,30}", c))


def describe(it, d_f, fid, l_events=()):
    """An item's details, never a value nor Jean's notes: name, folder, username, websites, dates, how many older passwords
    and when each was replaced, and agent-vault's own lines of the notes (items of its folder)."""
    lg, d = it.get("login") or {}, lambda x: (x or "")[:16].replace("T", " ") or "?"
    hist = it.get("passwordHistory") or []
    l = [f"{it.get('name', '')}  ·  folder: {d_f.get(it.get('folderId')) or '(no folder)'}  ·  id {(it.get('id') or '')[:8]}",
         f"  username:  {lg.get('username') or '(none)'}",
         f"  websites:  {', '.join(u.get('uri', '') for u in lg.get('uris') or []) or '(none)'}",
         f"  has a password: {'yes' if lg.get('password') else 'NO'}, last changed "
         + (d(lg.get("passwordRevisionDate")) if lg.get("passwordRevisionDate") else "never since the item was made")
         + f"  ·  item made {d(it.get('creationDate'))}, last edited {d(it.get('revisionDate'))}",
         f"  older passwords: {len(hist)}" + (" (" + "; ".join(f"#{i} replaced {d(h.get('lastUsedDate'))}" for i, h in enumerate(hist, 1)) + ")" if hist else "")]
    if it.get("folderId") == fid:
        l += [f"  note: {x.strip()}" for x in (it.get("notes") or "").splitlines() if "by the password layer" in x or "by agent-vault" in x or "by layer-vault" in x]
    return l + list(l_events)


def item_events(iid):
    """What agent-vault did with this item (events.jsonl): every new password and username change, the last logins."""
    p, l = os.path.join(HOME, "events.jsonl"), []
    for x in open(p, encoding="utf-8") if iid and os.path.exists(p) else []:
        try:
            e = json.loads(x)
        except ValueError:
            continue
        if e.get("item") == iid and e.get("event") in ("password_new", "password_typed"):
            l.append(f"  {e.get('dt', '')[:16].replace('T', ' ')}  {'NEW password' if e['event'] == 'password_new' else 'typed'} "
                     f"on tab {e.get('tab')} for login {e.get('login') or '?'}" + (f" (why: {e['why']})" if e.get("why") else ""))
    l_new = [x for x in l if "NEW password" in x]
    return ["  agent-vault's record:"] + (sorted(l_new + [x for x in l if "NEW password" not in x][-3:]) or ["  (nothing)"])


VAULT = Vault()
