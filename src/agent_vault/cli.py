"""`vault` (agents) and `vault-admin` (Jean): agent-vault version 2, a command, no daemon (DESIGN.md §3–§8).

Reads and writes <AV_HOME> (700): session (the Bitwarden session key, 600), had_grant, grants.json, key, fingerprints.json,
suspected/, suspected_index.json, pending_saves.json, events.jsonl; <AV_OUT>/alerts.jsonl. Every reply is checked by mask
(the vault's secrets only) before it is printed: it holds no value by construction, this is the second net.
Exit codes: 0 done · 1 refused or failed (one line on stderr) · 3 `mask`: something was masked.
"""
import getpass
import json
import os
import re
import secrets
import string
import subprocess
import sys
import time

from . import chrome
from .bitwarden import Vault, describe, item_events
from .common import BW_FOLDER, HOME, OUT, domain, log_event, now
from .grants import ANY, GRANTS
from .masking import MASK, load_json, save_json

VAULT = Vault()
# A mask-only machine (the NAS, task D5): `vault mask` for the hooks, `reveal` of its own suspected secrets, and the import of
# the Mac's fingerprints; no Bitwarden, no grant, no typing. Set by the root-owned file MASK_ONLY beside src/ (install_system.sh
# on Linux), or AV_MASK_ONLY=1 in the sandbox (AV_HOME set).
MASK_ONLY = (os.path.exists(os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "MASK_ONLY"))
             or bool(os.environ.get("AV_HOME")) and os.environ.get("AV_MASK_ONLY") == "1")
MASK_ONLY_VAULT = ("help", "--help", "-h", "mask", "status", "reveal")
MASK_ONLY_ADMIN = ("status", "mask-key", "import-mask", "file-alerts")
P_IMPORT_KEY = os.path.join(HOME, "import_x25519.key")
P_SESSION = os.path.join(HOME, "session")
P_HAD = os.path.join(HOME, "had_grant")
HELP = """vault: agent-vault for agents (DESIGN.md §3). <tab> = the Claude in Chrome tab id; <item> = an id prefix or exact name.
  vault type-username <tab> [--item <item>]                 the item's username into the page (grant: login)
  vault type-password <tab> [--item <item>] [--nth N]       the item's password into password field N (grant: login)
  vault type-new-password <tab> --username <login> [--length 20] [--no-symbols]
                                                            a new password: saved in the vault, then typed (grant: new-password)
  vault type-token <tab> <token> [--nth N]                  a <suspected-secret …> into a password field (grant: login)
  vault save-token <token> --site <domain> [--username <login>]   a suspected secret → a vault item (a password)
  vault reveal <token> --temporary --why "<why it expires>"  a suspected secret you are SURE is temporary → shown in clear
  vault mask [--out]                                        JSON list of texts on stdin → masked; exit 3 if anything was
  vault list | find <text> | show <item>                    the granted items, never a secret
  vault rename <item> <name> | set-username <item> <login> | add-website <item> <https url> | delete <item> [--dry]
  vault status
vault-admin unlock | lock | sync | status | file-alerts · sudo vault-admin grant <session> <targets…> --for 2h --can login,new-password
            · sudo vault-admin grant --any-session site:<domain> --forever --can login      (a standing grant: every session)
            · sudo vault-admin revoke <session> | --any-session [site:<domain>] | --all"""


SYMBOLS = "-_.!@#%+="


def make_password(length=20, symbols=SYMBOLS):
    alphabet = string.ascii_letters + string.digits + (symbols or "")
    while True:
        pw = "".join(secrets.choice(alphabet) for _ in range(length))
        if (any(c.islower() for c in pw) and any(c.isupper() for c in pw) and any(c.isdigit() for c in pw)
                and (not symbols or any(c in symbols for c in pw)) and pw[0].isalnum()):
            return pw


# ------------------------------------------------------------ state
def session():
    return os.environ.get("CLAUDE_CODE_SESSION_ID", "")


def load_session():
    try:
        VAULT.session = open(P_SESSION).read().strip() or None
    except OSError:
        VAULT.session = None


def save_session():
    fd = os.open(P_SESSION, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(VAULT.session or "")


def lock(why):
    VAULT.forget()
    for p in (P_SESSION, P_HAD):
        if os.path.exists(p):
            os.remove(p)
    log_event(event="lock", why=why)


def tick():
    """Nothing: the vault stays unlocked until Jean locks it (version 3, Jean 2026-11-21: "Why can't we have the vault being
    completely continuously unlocked?"); grants alone decide who may use an item (agent-firewall doc/agent-interfaces/DESIGN.md §12.1, the project design before the split)."""


def no_grant(what):
    return RuntimeError(f"no grant for {what}: ask Jean for `sudo vault-admin grant {session() or '<your session UUID>'} <item or "
                        f"site:<domain> or folder:\"{BW_FOLDER}\"> --for 2h --can login[,new-password]`")


def options(a, d_default, flags=()):
    d, rest, it = dict(d_default), [], iter(a)
    for o in it:
        if o in flags:
            d[o[2:]] = True
        elif o.startswith("--"):
            d[o[2:]] = next(it, "")
        else:
            rest.append(o)
    return d, rest


# ------------------------------------------------------------ typing (§8)
def page(tab):
    """(the tab: its address and AppleScript id, the page's website), after the tab check (§8 step 2)."""
    where = chrome.locate(tab, session())
    return where, domain(where[0])


def login_item(ref, here, ability="login"):
    """The item to type on this page: the one named, else the only granted login item of this website."""
    l, d_f = VAULT.everything()
    if ref:
        it, d_f = VAULT.resolve(ref)
        l_it = [it]
    else:
        l_it = [it for it in l if it.get("type") == 1 and here in Vault.info(it, d_f)["domains"]
                and GRANTS.covers_item(session(), Vault.info(it, d_f), ability)]
        if len(l_it) > 1:
            raise RuntimeError(f"{len(l_it)} granted items for {here}: name one with --item: " + "; ".join(
                f"{x['id'][:8]} ({(x.get('login') or {}).get('username') or 'no username'})" for x in l_it))
        if not l_it:
            near = lookalike(here, sorted({x for it in l if it.get("type") == 1 for x in Vault.info(it, d_f)["domains"]}))
            if near:
                alert("look-alike website", site=here, imitates=near)
                raise RuntimeError(f"this page is on {here}, which looks like {near} but is another website: a look-alike (phishing), "
                                   "nothing typed (an alert for Jean)")
            raise no_grant(f"logging in on {here} (ability {ability})")
    it = l_it[0]
    info = Vault.info(it, d_f)
    if not GRANTS.covers_item(session(), info, ability):
        raise no_grant(f"item {info['name']} (ability {ability})")
    if here not in info["domains"] and lookalike(here, info["domains"]):
        alert("look-alike website", site=here, imitates=lookalike(here, info["domains"]), item=it["id"][:8])
        raise RuntimeError(f"this page is on {here}, which looks like {lookalike(here, info['domains'])} but is another website: a "
                           "look-alike (phishing), nothing typed (an alert for Jean)")
    if here not in info["domains"]:
        raise RuntimeError(f"this page is on {here or 'no website'}, the item belongs to {', '.join(info['domains']) or 'no website'}: "
                           "nothing typed. The same account on another domain: Jean adds the website to the item")
    return it, info


def alert(kind, **d):
    """A suspicious page (a look-alike website, a password asked in clear text, a field turned into clear text): one line in
    AV_OUT/alerts.jsonl, the job turns it into a Todoist task for Jean (file-alerts)."""
    ts, dt = now()
    os.makedirs(OUT, exist_ok=True)
    with open(os.path.join(OUT, "alerts.jsonl"), "a") as f:
        f.write(json.dumps({"ts": ts, "dt": dt, "kind": kind, "session": session(), **d}) + "\n")
    log_event(event="alert", kind=kind, **d)


def lookalike(here, l_dom):
    """The item's website this page imitates (1 or 2 letters differ, or the same name under another ending), or None."""
    def dist(a, b):
        row = list(range(len(b) + 1))
        for i, ca in enumerate(a, 1):
            prev, row[0] = row[0], i
            for j, cb in enumerate(b, 1):
                prev, row[j] = row[j], min(row[j] + 1, row[j - 1] + 1, prev + (ca != cb))
        return row[-1]
    for d in l_dom:
        name, mine = d.split(".")[0], here.split(".")[0]
        if here and d and here != d and (dist(here, d) <= 2 or mine == name
                                         or (len(name) >= 4 and re.search(rf"(?:^|[-_.]){re.escape(name)}(?:[-_.]|$)", mine))):
            return d
    return None


def typed(out, what, n_chars, where=None, here=""):
    if out == "wrong site":
        raise RuntimeError("the page changed website before typing: nothing typed")
    if out == "clear field":
        alert("password asked in clear text", site=here, url=(where or ("",))[0][:200])
        raise RuntimeError(f"this page on {here} asks for the password in a field that shows it in clear: suspicious, nothing typed "
                           "(an alert for Jean)")
    if out.startswith("frame "):
        src = out[6:]
        raise RuntimeError(f"the {what} field is in a frame from {domain(src) or src[:60]}, which the page cannot reach: navigate the tab "
                           f"to {src[:200]} and run this again (agent-vault then checks that site against the item)")
    if out == "no field":
        raise RuntimeError(f"no {what} field on this page: nothing typed")
    n = out.split()[-1]
    if what == "password" and where:
        time.sleep(0.6)  # a page that turns the field into clear text after typing (to show it, or to read it)
        v = chrome.fill(where, here, "", "verify")
        if v.startswith("swapped"):
            alert("password field turned into clear text", site=here, url=where[0][:200])
            raise RuntimeError(f"the page turned the password field into clear text right after typing: suspicious; the field was "
                               "emptied (an alert for Jean)")
    if out.startswith("mismatch"):
        return f"typed into {n} {what} field(s) ({n_chars} chars), but the page changed the value (it cuts or refuses characters): tell Jean"
    return f"typed into {n} {what} field(s) ({n_chars} chars)"


def type_username(tab, *a):
    d, _ = options(a, {"item": ""})
    where, here = page(tab)
    it, info = login_item(d["item"], here)
    user = (it.get("login") or {}).get("username") or ""
    if not user:
        raise RuntimeError(f"the item {info['name']} has no username: Jean adds it")
    out = chrome.fill(where, here, user, "username")
    log_event(event="username_typed", item=it["id"], tab=tab, session=session())
    return typed(out, "username", len(user), where, here) + f": {user}"


def type_password(tab, *a):
    d, _ = options(a, {"item": "", "nth": "1"})
    where, here = page(tab)
    it, info = login_item(d["item"], here)
    pw = (it.get("login") or {}).get("password")
    if not pw:
        raise RuntimeError(f"the item {info['name']} has no password")
    out = chrome.fill(where, here, pw, "password", int(d["nth"] or 1))
    log_event(event="password_typed", item=it["id"], tab=tab, session=session())
    return typed(out, "password", len(pw), where, here)


def type_new_password(tab, *a):
    d, _ = options(a, {"length": "20", "username": ""}, flags=("--no-symbols",))
    if not d["username"]:
        raise RuntimeError("`type-new-password` needs --username <the login> (for the vault item)")
    where, here = page(tab)
    if not GRANTS.covers_site(session(), here, "new-password"):
        raise no_grant(f"a new password on {here} (ability new-password)")
    l_hit = VAULT.clash(here, d["username"])
    if l_hit:
        raise RuntimeError(f"already in Bitwarden: {'; '.join(l_hit[:3])}. A password in Bitwarden is never changed (Jean, "
                           "2026-11-11): log in with `type-password`; the site refuses it: tell Jean")
    pw = make_password(max(8, min(64, int(d["length"]))), "" if d.get("no-symbols") else SYMBOLS)
    iid = VAULT.save_new(here, "https://" + here, d["username"], pw, f"Set by agent-vault {now()[1]}")  # in the vault first
    MASK.add(iid, "password", pw, here)
    out = chrome.fill(where, here, pw, "new")
    log_event(event="password_new", item=iid, tab=tab, session=session(), login=d["username"])
    return typed(out, "password", len(pw), where, here) + f", saved in the vault (item {iid[:8]})"


def type_token(tab, token, *a):
    d, _ = options(a, {"nth": "1"})
    where, here = page(tab)
    if not GRANTS.covers_site(session(), here, "login") and not GRANTS.live(session(), own=True):  # a standing grant: its site only
        raise no_grant(f"typing a token on {here} (ability login)")
    sid = token.strip("<>").split()[-1]
    v = MASK.suspected_value(sid)
    MASK.add("s" + sid[:7], "password", v)
    out = chrome.fill(where, here, v, "password", int(d["nth"] or 1))
    log_event(event="token_typed", token=sid, tab=tab, session=session())
    return typed(out, "password", len(v), where, here)


# ------------------------------------------------------------ reveal (a suspected secret the agent says is temporary)
def reveal(token, *a):
    """The value of a <suspected-secret …> the agent is sure is temporary (a one-time password, a code, a link's token):
    printed once, then shown in clear by every mask; never saved to the vault; it may go back to its source only (the
    outgoing hook: mask --out reports it as revealed:<id>). Jean, 2026-11-21 (agent-firewall doc/agent-interfaces/DESIGN.md §12.5, the project design before the split)."""
    d, _ = options(a, {"why": ""}, flags=("--temporary",))
    sid = token.strip("<>").split()[-1]
    if not d.get("temporary") or len(d["why"].strip()) < 10:
        raise RuntimeError("`vault reveal <token> --temporary --why \"<why it expires within hours>\"`: only a secret you are sure is "
                           "temporary (a one-time password, a code, a link's token); a password for an account: `vault save-token`")
    l_save = [r for r in load_json(os.path.join(HOME, "pending_saves.json"), []) if r.get("token") == sid]
    if l_save:
        raise RuntimeError(f"{sid} was saved to the vault as a password ({l_save[-1].get('status')}): never revealed")
    v = MASK.suspected_value(sid)
    MASK.reveal(sid, d["why"], session())
    log_event(event="reveal", token=sid, session=session(), why=d["why"][:200])
    return f"{sid} (temporary, shown in clear from now on; it may go back to where it came from, nowhere else): {v}"


# ------------------------------------------------------------ save-token (a token → a vault item)
def save_token(token, *a):
    d, _ = options(a, {"site": "", "username": ""})
    sid = token.strip("<>").split()[-1]
    MASK.suspected_value(sid)  # it exists (the value stays inside)
    if sid in MASK.revealed():
        raise RuntimeError(f"{sid} was revealed as temporary: never saved to the vault (Jean, 2026-11-21)")
    if "." not in d["site"]:
        raise RuntimeError("--site <the website's domain>, please (shop.ch)")
    p = os.path.join(HOME, "pending_saves.json")
    ts, dt = now()
    save_json(p, load_json(p, []) + [{"ts": ts, "dt": dt, "token": sid, "site": d["site"], "username": d["username"],
                                      "session": session(), "status": "pending"}])
    return apply_saves() or f"{sid}: will be saved for {d['site']} at Jean's next unlock"


def apply_saves():
    if not VAULT.session:
        return ""
    p = os.path.join(HOME, "pending_saves.json")
    l, l_out = load_json(p, []), []
    for r in l:
        if r.get("status") != "pending":
            continue
        l_hit = VAULT.clash(domain(r["site"]), r["username"])
        if l_hit and r["username"]:
            r["status"] = "refused: already in Bitwarden: " + "; ".join(l_hit[:2])
        else:
            v = MASK.suspected_value(r["token"])
            r["item"] = VAULT.save_new(r["site"], "https://" + r["site"], r["username"], v,
                                       f"Saved by agent-vault from a token ({r['token']}) {now()[1]}")
            MASK.add(r["item"], "password", v, r["site"])
            r["status"] = "saved"
        log_event(event="save_token", token=r["token"], site=r["site"], status=r["status"], item=r.get("item"))
        l_out.append(f"{r['token']} → {r['site']}: {r['status']}" + (f" (item {r['item'][:8]})" if r.get("item") else ""))
    save_json(p, l)
    return "\n".join(l_out)


# ------------------------------------------------------------ mask
def mask(a):
    out = "--out" in a
    raw = sys.stdin.read()
    try:
        l = json.loads(raw)
        if not (isinstance(l, list) and all(isinstance(x, str) for x in l)):
            raise ValueError
    except ValueError:
        l = None
    caller = {"session": session()} if session() else {}
    l_res = [MASK.mask(t, out=out, caller=caller) for t in (l if l is not None else [raw])]
    l_cat = sorted({c for _, cats in l_res for c in cats})
    sys.stdout.write((json.dumps([m for m, _ in l_res], ensure_ascii=False) if l is not None else l_res[0][0]) + "\n")
    if l_cat:
        print(" ".join(l_cat), file=sys.stderr)
    return 3 if l_cat else 0


# ------------------------------------------------------------ the items (R4, R5)
def granted(l, d_f):
    return [it for it in l if it.get("type") == 1 and GRANTS.covers_item(session(), Vault.info(it, d_f))]


def items(verb, *a):
    if not GRANTS.live(session()):
        raise no_grant("the vault's items")
    l, d_f = VAULT.everything()
    fid = VAULT.folder_id()
    if verb == "list":
        l_ok = granted(l, d_f)
        return "your grants:\n" + "\n".join("  " + x for x in GRANTS.summary(session())) + f"\n{len(l_ok)} granted item(s)\n" + "\n".join(
            f"{it['id'][:8]}\t{it.get('name')}\t{(it.get('login') or {}).get('username') or '(no username)'}\t"
            + " ".join(u.get("uri", "") for u in (it.get("login") or {}).get("uris") or []) for it in sorted(l_ok, key=lambda it: (it.get("name") or "").lower()))
    if verb == "find":
        text = " ".join(a).strip().lower()
        if len(text) < 3:
            raise RuntimeError("at least 3 characters to find")
        l_hit = [it for it in granted(l, d_f) if text in " ".join([it.get("name") or "", (it.get("login") or {}).get("username") or ""]
                                                                   + [u.get("uri") or "" for u in (it.get("login") or {}).get("uris") or []]).lower()]
        return f"{len(l_hit)} granted item(s) holding {text!r}" + "".join("\n" + x for it in l_hit[:30] for x in describe(it, d_f, fid))
    if not a:
        raise RuntimeError(f"`vault {verb} <item> …`")
    it, _ = VAULT.resolve(a[0])
    info = Vault.info(it, d_f)
    if not GRANTS.covers_item(session(), info):
        raise no_grant(f"item {info['name']}")
    if verb == "show":
        return "\n".join(describe(it, d_f, fid, item_events(it["id"])))
    if verb == "rename":
        name = " ".join(a[1:]).strip()
        if not name or len(name) > 120 or "\n" in name or MASK.spans(name):
            raise RuntimeError("a name of 1 to 120 characters on one line, not a secret, please")
        old = VAULT.edit(it["id"], lambda x: (x.get("name"), x.update(name=name))[0])
        log_event(event="item_rename", item=it["id"], old=old, new=name)
        return f"{old!r} → {name!r}"
    if verb == "set-username":
        login = a[1] if len(a) > 1 else ""
        if not login or MASK.spans(login):
            raise RuntimeError("a username, not a secret, please")
        old = VAULT.edit(it["id"], lambda x: (x["login"].get("username") or "", x["login"].update(username=login))[0])
        log_event(event="item_username", item=it["id"], old=old, new=login)
        return f"{info['name']}: username {old or '(none)'} → {login}"
    if verb == "add-website":
        url = a[1] if len(a) > 1 else ""
        if not re.match(r"https://[\w.-]+\.[a-z]{2,}(/|$)", url):
            raise RuntimeError("an https:// address of a website, please")
        if domain(url) not in info["domains"]:  # only another address of a website the item has: a new website is Jean's
            raise RuntimeError(f"{domain(url)} is not a website of {info['name']} ({', '.join(info['domains']) or 'none'}): not added; "
                               "Jean adds it in Bitwarden if it is right")

        def ch(x):
            l_u = x["login"].get("uris") or []
            if url in [u.get("uri") for u in l_u]:
                return False
            x["login"]["uris"] = l_u + [{"match": None, "uri": url}]
            return True
        added = VAULT.edit(it["id"], ch)
        log_event(event="item_website", item=it["id"], url=url, added=added)
        return f"{info['name']}: {url} {'added' if added else 'was already there'}"
    if verb == "delete":
        dry = "--dry" in a
        user = VAULT.delete(it["id"], dry)
        if not dry:
            log_event(event="item_delete", item=it["id"])
        return f"{info['name']} ({user or 'no login'}): {'would go' if dry else 'sent'} to Bitwarden's trash (30 days to restore)"
    raise RuntimeError(f"unknown command {verb!r}")


# ------------------------------------------------------------ vault-admin (Jean)
def admin_ok():
    """Jean's admin commands: root (`sudo vault-admin …`: vault-run runs it as av-vault and sudo sets SUDO_UID=0, which no
    caller can set: sudo resets the environment); the sandbox only (AV_HOME set): AV_ADMIN_OK=1."""
    if os.geteuid() == 0 or os.environ.get("SUDO_UID") == "0":
        return True
    return bool(os.environ.get("AV_HOME")) and os.environ.get("AV_ADMIN_OK") == "1"


def admin(argv):
    verb, a = (argv[0] if argv else "status"), argv[1:]
    if verb in ("unlock", "sync"):
        pw = getpass.getpass("Bitwarden master password: ") if sys.stdin.isatty() else sys.stdin.readline().rstrip("\n")
        VAULT.unlock(pw)
        del pw
        save_session()
        l_all, _ = VAULT.everything()
        counts = MASK.sync(VAULT.secrets(), {it["id"]: it.get("name") or "" for it in l_all})
        saved = apply_saves()
        log_event(event=verb, **{k.split(" ")[0]: v for k, v in counts.items()})
        out = "vault unlocked · fingerprints: " + " · ".join(f"{k} {v}" for k, v in counts.items()) + (f"\n{saved}" if saved else "")
        if verb == "sync":
            lock("vault-admin sync")
            return out.replace("vault unlocked", "synced, then locked")
        return out + ("" if GRANTS.all() else "\nno grant yet: `sudo vault-admin grant …`; the vault stays unlocked until `vault-admin lock`")
    if verb == "lock":
        lock("vault-admin lock")
        return "vault locked"
    if verb == "status":
        MASK.load()
        return (f"vault: {'unlocked' if VAULT.session else 'locked'} · fingerprints: {len(MASK.fp)} pieces of "
                f"{len(set(i for i, _ in MASK.fp.values()))} items\ngrants:\n" + ("\n".join("  " + x for x in GRANTS.summary()) or "  none"))
    if verb in ("grant", "revoke"):
        if not admin_ok():
            raise RuntimeError(f"`vault-admin {verb}` only through sudo (Jean's): refused")
        d, rest = options(a, {"for": "", "can": ""}, flags=("--any-session", "--forever", "--all"))
        if verb == "revoke":
            if d.get("any-session"):
                n = GRANTS.revoke(ANY, rest[0] if rest else None)
            else:
                n = GRANTS.revoke(None if d.get("all") else (rest[0] if rest else ""))
            log_event(event="revoke", n=n)
            return f"{n} grant(s) ended"
        sid = ANY if d.get("any-session") else (rest.pop(0) if rest else "")
        g = GRANTS.add(sid, rest, d["for"], [c for c in d["can"].split(",") if c], forever=bool(d.get("forever")))
        log_event(event="grant", **{k: v for k, v in g.items() if k not in ("ts", "dt")})
        return "granted: " + GRANTS.line(g) + ("" if VAULT.session else "\nthe vault is locked: `vault-admin unlock`")
    if verb == "file-alerts":
        return file_alerts()
    if verb == "mask-key":  # the mask-only machine (the NAS): the public half of av-vault's import key, for tools/mask_to_nas.sh
        from .bundle import key_pair
        return key_pair(P_IMPORT_KEY)
    if verb == "import-mask":  # the mask-only machine: the Mac's key + fingerprints, sealed for this machine (bundle.py)
        if not admin_ok():
            raise RuntimeError("`vault-admin import-mask` only through sudo (Jean's): refused")
        from .bundle import open_bundle
        key, d_fp = open_bundle(sys.stdin.read(), P_IMPORT_KEY)
        p_key = os.path.join(HOME, "key")
        n_gone = 0
        if os.path.exists(p_key) and open(p_key, "rb").read() != key:  # the first import (or a new Mac key): the suspected
            d_sus = os.path.join(HOME, "suspected")  # secrets kept so far are sealed with the old key: dropped, never left unreadable
            for f in os.listdir(d_sus) if os.path.isdir(d_sus) else []:  # (an unreadable revealed one would break every mask)
                os.remove(os.path.join(d_sus, f))
                n_gone += 1
            for f in ("suspected_index.json", "revealed.json"):
                if os.path.exists(os.path.join(HOME, f)):
                    os.remove(os.path.join(HOME, f))
        save_json(os.path.join(HOME, "fingerprints.json"), d_fp)
        fd = os.open(os.path.join(HOME, "key.new"), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        os.write(fd, key)
        os.close(fd)
        os.replace(os.path.join(HOME, "key.new"), os.path.join(HOME, "key"))
        n_items = len({v[0] for v in d_fp["fp"].values()})
        log_event(event="import-mask", pieces=len(d_fp["fp"]), items=n_items, suspected_dropped=n_gone)
        return (f"imported: fingerprints {len(d_fp['fp'])} pieces of {n_items} items (the Mac's key)"
                + (f"; {n_gone} suspected secret(s) kept before it dropped (sealed with the old key)" if n_gone else ""))
    raise RuntimeError(f"unknown vault-admin command {verb!r}")


def file_alerts():
    """Each alert → one Todoist task, once per subject and day (the job agent-vault.alerts). A leak (mask --out): change the
    item's secret. A suspicious page (look-alike, clear text field, field turned into clear text): look at it. Run by Jean's
    user, which holds the Todoist login (av-vault does not)."""
    p_state = os.environ.get("AV_ALERTS_STATE") or os.path.expanduser("~/.local/state/agent-vault/alerts_filed.json")
    os.makedirs(os.path.dirname(p_state), exist_ok=True)
    s_done = set(load_json(p_state, []))
    n = 0
    p = os.path.join(OUT, "alerts.jsonl")
    for line in open(p) if os.path.exists(p) else []:
        a = json.loads(line)
        kind = a.get("kind", "leak")
        key = f"{kind}:{a.get('item') or a.get('site')}:{a['dt'][:10]}"
        if key in s_done:
            continue
        if kind == "leak":
            name = re.sub(r"[^\w .()+&-]", "", a.get("name") or "") or f"id {a['item']}"
            title, done, need = (f"Change the password of vault item {name}", "the item's secret is changed in Bitwarden and on its website "
                                 "(or Jean judged the alert harmless)", "a long-lived secret reached an agent's transcript: whoever reads it can use it until it is changed")
            desc = (f"agent-vault's late alarm (vault mask --out) found item {name} ({a.get('category')}, id {a['item']}) in a text leaving on "
                    f"{a['dt']} (session {(a.get('caller') or {}).get('session') or '?'}). The value is never written anywhere.")
        else:
            site = re.sub(r"[^\w.-]", "", a.get("site") or "?")
            title, done, need = (f"Look at a suspicious login page: {site} ({kind})", "Jean looked at it: a real attack (report it) or a false alarm",
                                 "an agent was about to type a password into a page that looks like an attack")
            desc = (f"agent-vault refused to type on {site} on {a['dt']}: {kind}" + (f", imitating {a['imitates']}" if a.get("imitates") else "")
                    + f". Session {a.get('session') or '?'}. Nothing was typed.")
        cmd = [os.environ.get("AV_TASK") or next((t for t in (os.path.expanduser("~/.local/bin/task"),) if os.path.exists(t)), "task"), "add", title, "--done_when", done, "--need_level", "major", "--because", need,
               "--deadline", "within_a_day", "--why_deadline", "too late: a leaked secret stays usable · set by: agent-vault",
               "--project", os.environ.get("AV_ALERT_PROJECT", "Personal"), "--section", os.environ.get("AV_ALERT_SECTION", "Projects - IT"),
               "--subsection", "agent-vault", "--description", desc]
        r = subprocess.run(cmd, capture_output=True, text=True)
        if r.returncode:
            print(f"task add failed for {key}: {(r.stderr or r.stdout).strip()[:300]}", file=sys.stderr)
            continue
        s_done.add(key)
        n += 1
    save_json(p_state, sorted(s_done))
    return f"{n} alert task(s) filed"


# ------------------------------------------------------------ main
AGENT = {"type-username": type_username, "type-password": type_password, "type-new-password": type_new_password,
         "type-token": type_token, "save-token": save_token, "reveal": reveal}


def run(prog, argv):
    verb, a = (argv[0] if argv else ("status" if prog == "vault-admin" else "help")), argv[1:]
    if MASK_ONLY and verb not in (MASK_ONLY_ADMIN if prog == "vault-admin" else MASK_ONLY_VAULT):
        raise RuntimeError(f"this machine's vault only masks (no Bitwarden here: the NAS, task D5): `{prog} {verb}` runs on the Mac")
    if MASK_ONLY and verb == "status":
        MASK.load()
        return (f"vault: mask only (no Bitwarden on this machine) · fingerprints: {len(MASK.fp)} pieces of "
                f"{len(set(i for i, _ in MASK.fp.values()))} items" + ("" if MASK.fp else " (none yet: tools/mask_to_nas.sh on the Mac)")), 0
    if prog == "vault-admin":
        return admin(argv), 0
    if verb in ("help", "--help", "-h"):
        return HELP, 0
    if verb == "mask":
        return None, mask(a)
    if verb == "status":
        l_g = GRANTS.summary(session())
        return f"vault: {'unlocked' if VAULT.session else 'locked'}\nyour grants: " + ("\n  " + "\n  ".join(l_g) if l_g else "none"), 0
    if verb in AGENT:
        if not a:
            raise RuntimeError(f"`vault {verb}` needs its arguments: `vault help`")
        return AGENT[verb](*a), 0
    if verb in ("list", "find", "show", "rename", "set-username", "add-website", "delete"):
        return items(verb, *a), 0
    raise RuntimeError(f"unknown command {verb!r}: `vault help`")


def main():
    prog = sys.argv[1] if len(sys.argv) > 1 else "vault"
    argv = sys.argv[2:]
    os.makedirs(HOME, mode=0o700, exist_ok=True)
    os.umask(0o077)
    load_session()
    tick()
    # `vault-admin file-alerts` runs in Jean's user (bin/vault-admin), which cannot read av-vault's key, so it cannot mask:
    # its replies are a count and Todoist errors, never a value (the alerts hold item names and ids only). Masking them
    # failed every run with "Permission denied: /var/agent-vault/key" (job agent-vault.alerts, 2026-11-21 → 11-23).
    no_key = prog == "vault-admin" and argv[:1] == ["file-alerts"]
    try:
        out, code = run(prog, argv)
    except Exception as e:  # one line, checked like every reply
        msg = (str(e).splitlines() or [type(e).__name__])[0][:300]
        print("error: " + (msg if no_key else MASK.mask(msg, suspects=False)[0]), file=sys.stderr)
        sys.exit(1)
    if out is not None:
        print(out if argv[:1] == ["reveal"] or no_key else MASK.mask(out, suspects=False)[0])
    sys.exit(code)
