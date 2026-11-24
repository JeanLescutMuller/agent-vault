"""agent-vault's command, cases V01–V26: unlock, mask, grants (V23–V26: the standing grant), the item commands, the tab checks before
typing, save-token, reveal, look-alikes, alerts, the lock, the one-folder mode. A fake vault; no Chrome, no Claude.

  bash test/run_all.sh vault     (or: .venv/bin/python test/test_vault.py)
"""
import base64
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from harness import AHV, CARD, IBAN, OLD, PW, S1, S2, TEMP, Box  # noqa: E402

b = Box("vault")
admin = {"AV_ADMIN_OK": "1"}

c, o = b.run("vault-admin", "unlock", stdin="wrongmaster\n")
b.case("V01", "unlock: a wrong master password is refused", c == 1 and "wrong master password" in o, o)
c, o = b.run("vault-admin", "unlock", stdin="testmaster\n")
b.case("V02", "unlock: fingerprints made, counts only", c == 0 and "fingerprints" in o and "items 4" in o, o)

c, o = b.run("vault", "mask", stdin=json.dumps([f"password {PW}", f"card {CARD}", f"IBAN {IBAN}", "b64 " + base64.b64encode(PW.encode()).decode()]))
l = json.loads(o.split("\n")[0]) if c == 3 else ["", "", "", ""]
b.case("V03", "mask: a password, a card, an IBAN, a password in Base64 → their tokens",
       "<vault-secret a1b2c3d4>" in l[0] and "<vault-secret c0ffee00>" in l[1] and "<vault-secret 1ba11ba1>" in l[2] and "<vault-secret" in l[3], o)
c, o = b.run("vault", "mask", stdin=json.dumps([f"password: {TEMP}", "hello, nothing here"]))
l = json.loads(o.split("\n")[0]) if c == 3 else ["", ""]
b.case("V04", "mask: a password-like value → <suspected-secret …>; plain text untouched", "<suspected-secret " in l[0] and l[1] == "hello, nothing here", o)
token = l[0].split("<suspected-secret ")[1][:8] if "<suspected-secret " in l[0] else "00000000"
c0, _ = b.run("vault", "mask", stdin=json.dumps(["nothing secret"]))
c, o = b.run("vault", "mask", stdin=json.dumps(["  has a password: yes, last changed 2026-11-01", "Password: required"]))
b.case("V05", "mask: 'password: yes' and 'Password: required' are no value (and nothing to mask → exit 0)", c == 0 and c0 == 0, o)
c, o = b.run("vault", "mask", "--out", stdin=json.dumps([f"sending {PW}"]))
alerts = open(os.path.join(b.out, "alerts.jsonl")).read() if os.path.exists(os.path.join(b.out, "alerts.jsonl")) else ""
b.case("V06", "mask --out: a vault secret → exit 3, an alert naming the item, no value", c == 3 and '"item": "a1b2c3d4"' in alerts and PW not in alerts, o)

r = [b.run("vault-admin", "grant", S1, "site:galaxus.localhost", "--for", "1h", "--can", "login")[0],
     b.run("vault-admin", "grant", S1, "site:galaxus.localhost", "--for", "2x", "--can", "login", env=admin)[0],
     b.run("vault-admin", "grant", S1, "site:galaxus.localhost", "--for", "1h", "--can", "pay", env=admin)[0],
     b.run("vault-admin", "grant", "not-a-uuid", "site:galaxus.localhost", "--for", "1h", "--can", "login", env=admin)[0]]
b.case("V07", "grant: only through sudo; a wrong duration, an unknown ability, a non-UUID refused", r == [1, 1, 1, 1], r)
c1, _ = b.run("vault-admin", "grant", S1, "site:galaxus.localhost", "--for", "1h", "--can", "login,new-password", env=admin)
c2, _ = b.run("vault-admin", "grant", S2, "folder:Agent auto-login", "--for", "3s", "--can", "login", env=admin)
c3, o3 = b.run("vault", "list", env={"CLAUDE_CODE_SESSION_ID": S2})
time.sleep(3.5)
c4, o4 = b.run("vault", "list", env={"CLAUDE_CODE_SESSION_ID": S2})
b.case("V08", "grant on a website, on a folder; the folder grant lists its items, then expires", (c1, c2, c3, c4) == (0, 0, 0, 1) and "galaxus" in o3 and "no grant" in o4, [o3, o4])

r = {k: b.run("vault", *a) for k, a in {"list": ("list",), "find": ("find", "gala"), "short": ("find", "ga"), "show": ("show", "galaxus"),
                                         "other": ("show", "Bank")}.items()}
b.case("V09", "list, find, show: granted items, no value; find < 3 chars refused; another folder's item refused",
       r["list"][0] == 0 and "me@example.com" in r["list"][1] and r["find"][0] == 0 and r["short"][0] == 1 and r["show"][0] == 0
       and "older passwords: 1" in r["show"][1] and r["other"][0] == 1, r)
r = [b.run("vault", "rename", "galaxus", "Galaxus (test)")[0], b.run("vault", "rename", "a1b2c3d4", "galaxus")[0],
     b.run("vault", "set-username", "galaxus", "me2@example.com")[0], b.run("vault", "set-username", "galaxus", "me@example.com")[0],
     b.run("vault", "add-website", "galaxus", "https://www.galaxus.localhost/account")[0], b.run("vault", "add-website", "galaxus", "https://evil.example/")[0],
     b.run("vault", "rename", "galaxus", PW)[0], b.run("vault", "delete", "galaxus", "--dry")[0],
     b.run("vault", "delete", "galaxus", env={"CLAUDE_CODE_SESSION_ID": "00000000-0000-0000-0000-000000000000"})[0]]
b.case("V10", "rename, set-username, add-website (same website only), delete --dry; a secret as a name and no grant refused",
       r == [0, 0, 0, 0, 0, 1, 1, 0, 1], r)
r = [b.run("vault", "type-password", "999")[1], b.run("vault", "type-password", "888")[1],
     b.run("vault", "type-password", "801", env={"CLAUDE_CODE_SESSION_ID": S2})[1]]
b.case("V11", "type-*: an unknown tab, another session's tab, no grant: refused",
       "not an agent tab" in r[0] and "another session" in r[1] and "another session" in r[2], r)
c1, o1 = b.run("vault", "type-new-password", "801")
b.case("V12", "type-new-password: --username required", c1 == 1 and "--username" in o1, o1)

# V13, V20: a second home with two items for one website and a second folder
from harness import ITEMS  # noqa: E402
home2 = os.path.join(b.dir, "home2")
b.fake_vault(home2, ITEMS + [{"id": "b2b2b2b2b2", "folderId": "F1", "type": 1, "name": "galaxus second", "notes": "", "fields": [],
                              "login": {"username": "other@example.com", "password": "Zz9-Second-Pw-77", "uris": [{"uri": "http://galaxus.localhost/"}]}}])
env2 = {"AV_HOME": home2, "AV_BW": b.bw}
b.run("vault-admin", "unlock", stdin="testmaster\n", env=env2)
b.run("vault-admin", "grant", S1, "site:galaxus.localhost", "--for", "1h", "--can", "login,new-password", env={**env2, **admin})
from paths import AV  # noqa: E402
sys.path.insert(0, os.path.join(AV, "src"))  # the code under test (2026-11-22: was ~/dev/…, broken in a container)
os.environ.update(AV_HOME=home2, AV_BW=b.bw, CLAUDE_CODE_SESSION_ID=S1)
from agent_vault import cli  # noqa: E402
cli.load_session()
try:
    cli.login_item("", "galaxus.localhost")
    msg = ""
except RuntimeError as e:
    msg = str(e)
b.case("V13", "two items for one website: refused, naming both", "a1b2c3d4" in msg and "b2b2b2b2" in msg and "other@example.com" in msg, msg)
clash = cli.VAULT.clash("galaxus.localhost", "me@example.com")
b.case("V12", "type-new-password: refused when the account is already in the vault (the clash)", bool(clash), clash)
c, o = b.run("vault-admin", "unlock", stdin="testmaster\n", env={**env2, "AV_ONLY_FOLDER": "1", "AV_FOLDER": "Agent auto-login"})
c2, o2 = b.run("vault", "mask", stdin=json.dumps([f"IBAN {IBAN}", f"pw {PW}"]), env={**env2, "AV_ONLY_FOLDER": "1", "AV_FOLDER": "Agent auto-login"})
b.case("V20", "one-folder mode: only that folder's secrets are known (the IBAN of another folder is not)",
       c == 0 and "items 2" in o and "<vault-secret a1b2c3d4>" in o2 and "1ba11ba1" not in o2, [o, o2])

c, o = b.run("vault", "type-token", "801", "<suspected-secret ffffffff>")
b.case("V14", "type-token: an unknown token refused", c == 1, o)
c, o = b.run("vault", "save-token", token, "--site", "newsite.example", "--username", "me@example.com")
c2, o2 = b.run("vault", "mask", stdin=json.dumps([f"it is {TEMP}"]))
b.case("V15", "save-token: a suspected secret → a vault item, then masked as a vault secret", c == 0 and "saved" in o and "<vault-secret" in o2, [o, o2])
c, o = b.run("vault", "mask", stdin=json.dumps(["Your temporary password: Ab3#xY9pQw2z"]))
tok2 = o.split("<suspected-secret ")[1][:8] if "<suspected-secret " in o else "00000000"
r = [b.run("vault", "reveal", tok2, "--temporary")[0], b.run("vault", "reveal", tok2, "--temporary", "--why", "a one-time password, valid 15 minutes")[0],
     b.run("vault", "save-token", tok2, "--site", "x.example")[0], b.run("vault", "reveal", token, "--temporary", "--why", "it is in the vault since V15")[0]]
b.case("V16", "reveal: refused without a reason; a revealed token never saved; a saved token never revealed", r == [1, 0, 1, 1], r)

from agent_vault.cli import lookalike  # noqa: E402
ok_l = all(lookalike(h, [n]) == n for h, n in [("sh0p.localhost", "shop.localhost"), ("galaxus.co", "galaxus.ch"), ("galaxus-secure.co", "galaxus.ch"),
                                                ("secure-galaxus.ch", "galaxus.ch")])
ok_n = all(lookalike(h, [n]) is None for h, n in [("galaxus.ch", "galaxus.ch"), ("digitec.ch", "galaxus.ch"), ("auth.localhost", "shop.localhost")])
b.case("V17", "look-alikes: one letter, another ending, the name inside a name; never the site itself or an unrelated one", ok_l and ok_n)

with open(os.path.join(b.out, "alerts.jsonl"), "a") as f:
    f.write(json.dumps({"ts": 1, "dt": "2026-11-21T10:00:00Z", "kind": "look-alike website", "site": "sh0p.localhost", "imitates": "shop.localhost"}) + "\n")
env_t = {"AV_TASK": b.task, "AV_ALERTS_STATE": os.path.join(b.dir, "alerts_filed.json")}
c1, o1 = b.run("vault-admin", "file-alerts", env=env_t)
c2, o2 = b.run("vault-admin", "file-alerts", env=env_t)
tasks = open(os.path.join(b.dir, "tasks.log")).read() if os.path.exists(os.path.join(b.dir, "tasks.log")) else ""
b.case("V18", "file-alerts: a leak and a look-alike → 2 tasks, no value; each once", "2 alert task" in o1 and "0 alert task" in o2
       and "Change the password" in tasks and "sh0p.localhost" in tasks and PW not in tasks, [o1, o2])

# V23–V26: a standing grant (any session, forever, one website, login only; Jean, 2026-11-24). S3: a session with no grant of its
# own. The website checks run in-process (as V13): a type-* that passes the tab check reads the tab's address from the real Chrome.
S3 = "33333333-4444-5555-6666-777777777777"
e3 = {"CLAUDE_CODE_SESSION_ID": S3}
r = [b.run("vault-admin", "grant", "--any-session", "site:galaxus.localhost", "--forever", "--can", "login")[0],
     b.run("vault-admin", "grant", "--any-session", "folder:Agent auto-login", "--forever", "--can", "login", env=admin)[0],
     b.run("vault-admin", "grant", "--any-session", "site:galaxus.localhost", "--forever", "--can", "login,new-password", env=admin)[0],
     b.run("vault-admin", "grant", "--any-session", "site:galaxus.localhost", "site:other.localhost", "--forever", "--can", "login", env=admin)[0],
     b.run("vault-admin", "grant", "--any-session", "a1b2c3d4", "--forever", "--can", "login", env=admin)[0],
     b.run("vault-admin", "grant", "--any-session", "site:galaxus.localhost", "--forever", env=admin)[0],
     b.run("vault-admin", "grant", S3, "site:galaxus.localhost", "--forever", "--can", "login", env=admin)[0],
     b.run("vault-admin", "grant", "--any-session", "site:galaxus.localhost", "--forever", "--for", "1h", "--can", "login", env=admin)[0]]
c0, o0 = b.run("vault", "list", env=e3)
b.case("V23", "standing grant: only through sudo; a folder, new-password, two websites, an item, no ability, --forever for one "
       "session, --forever with --for: refused", r == [1] * 8 and c0 == 1 and "no grant" in o0, [r, o0])
c1, o1 = b.run("vault-admin", "grant", "--any-session", "site:galaxus.localhost", "--forever", "--can", "login", env=admin)
c2, o2 = b.run("vault-admin", "status")
c3, o3 = b.run("vault", "list", env=e3)
c4, o4 = b.run("vault", "status", env=e3)
b.case("V24", "standing grant: made; status and every session's list show it as \"any session, forever\"; list shows the website's item",
       c1 == 0 and "any session, forever  site:galaxus.localhost  can login" in o2 and c3 == 0
       and "any session, forever" in o3 and "me@example.com" in o3 and "Bank" not in o3 and "any session, forever" in o4, [o1, o2, o3, o4])
b.run("vault-admin", "grant", "--any-session", "site:galaxus.localhost", "--forever", "--can", "login", env={**env2, **admin})
os.environ["CLAUDE_CODE_SESSION_ID"] = S3


def refused(f, *a):
    try:
        f(*a)
        return ""
    except RuntimeError as e:
        return str(e) or "refused"


G = cli.GRANTS
r = {"other_tab": b.run("vault", "type-password", "801", env=e3), "other_item": b.run("vault", "show", "Bank", env=e3),
     "here": refused(cli.login_item, "a1b2c3d4", "galaxus.localhost"), "other_site": refused(cli.login_item, "", "other.localhost"),
     "item_elsewhere": refused(cli.login_item, "a1b2c3d4", "other.localhost"),
     "token_elsewhere": G.covers_site(S3, "other.localhost", "login") or bool(G.live(S3, own=True)),
     "new": G.covers_site(S3, "galaxus.localhost", "new-password")}
os.environ["CLAUDE_CODE_SESSION_ID"] = S1
b.run("vault-admin", "revoke", "--any-session", env={**env2, **admin})
b.case("V25", "standing grant, every other check the same: another session's tab, another item, another website (an item, a token), "
       "a new password: refused; the website's item passes", r["other_tab"][0] == 1 and "another session" in r["other_tab"][1]
       and r["other_item"][0] == 1 and r["here"] == "" and "no grant" in r["other_site"] and "nothing typed" in r["item_elsewhere"]
       and not r["token_elsewhere"] and not r["new"], r)
c1, o1 = b.run("vault-admin", "revoke", S3, env=admin)
c2, o2 = b.run("vault", "list", env=e3)
c3, o3 = b.run("vault-admin", "revoke", "--any-session", "site:other.localhost", env=admin)
c4, o4 = b.run("vault-admin", "revoke", "--any-session", "site:galaxus.localhost", env=admin)
c5, o5 = b.run("vault", "list", env=e3)
c6, o6 = b.run("vault", "list")
b.case("V26", "standing grant: revoking a session keeps it; revoke --any-session <its site> ends it, and only it",
       "0 grant" in o1 and c2 == 0 and "0 grant" in o3 and "1 grant" in o4 and c5 == 1 and "no grant" in o5 and c6 == 0, [o1, o3, o4, o5, o6])

c1, o1 = b.run("vault-admin", "revoke", "--all", env=admin)
c2, o2 = b.run("vault-admin", "status")
c3, o3 = b.run("vault-admin", "sync", stdin="testmaster\n")
b.run("vault-admin", "unlock", stdin="testmaster\n")
c4, o4 = b.run("vault-admin", "lock")
c5, o5 = b.run("vault-admin", "status")
b.case("V19", "the vault stays unlocked after the last grant; sync refreshes then locks; Jean's lock",
       "unlocked" in o2 and "synced, then locked" in o3 and "vault locked" in o4 and "vault: locked" in o5, [o2, o3, o4, o5])
names = ["the VM `H-Frank-1` and the NAS", "ssh H-Frank-1 uptime", "model GPT-4o-mini", "task 6j46mjRQ2xJC99G3", "Python3.12",
         "at 2026-11-21T21:16:17+01:00", "count=5 since=2026-11-21", "?a=Xk9#mQ2v&b=1", "q=%2B41%2079", "1.795292e+09", "Machine: chan-lescut-macbook-pro"]
c1, o1 = b.run("vault", "mask", stdin=json.dumps(names))
c2, o2 = b.run("vault", "mask", stdin=json.dumps(["new one: Zx8!kQ2mLp4w", "pw=Rt4n#B8vL3sQ"]))
b.case("V21", "names, ids, versions, dates, assignments, query strings stay clear; a word with lower, upper, digit and a symbol is suspected",
       c1 == 0 and json.loads(o1.split("\n")[0]) == names and o2.count("<suspected-secret ") == 2, [o1, o2])
share = ("https://www.facebook.com/sharer/sharer.php?u=https%3A%2F%2Felmi.hbku.edu.qa%2Fen%2Fpublications%2Fabrasion&t=Abrasion+of+PV+"
         "Antireflective+Coatings+by+Robot+Cleaning&quote=Figgis+B+et+al+2024+Vol+14+No+5+pp+824-829+IEEE+Journal+of+Photovoltaics+DOI+10.1109")
c, o = b.run("vault", "mask", stdin=json.dumps(["Share: " + share]))
b.case("V22", "a long share link is never cut into slices that look like passwords", c == 0 and json.loads(o.split("\n")[0]) == ["Share: " + share], o)
b.done([PW, OLD, CARD, IBAN, AHV, TEMP, "Zz9-Second-Pw-77", "Zx8!kQ2mLp4w", "Rt4n#B8vL3sQ"], allowed=(IBAN,))  # V20 shows another folder's IBAN on purpose
