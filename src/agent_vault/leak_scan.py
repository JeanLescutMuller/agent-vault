"""`sudo vault-admin leak-scan [--deep] [--only] [<path>…]` (REQUIREMENTS.md R11): is any secret of the vault written where an
agent can read it? Jean only: sudo (to read av-vault's Bitwarden login) and the master password.

Unlocks a temporary copy of av-vault's bw login (the real one is never written by root), reads every secret of every folder
(Vault.secrets: passwords and their history, cards, identity numbers, hidden fields, keys), then looks for each in Jean's
agents' transcripts and logs: any 8-character piece of it (case-sensitive) and its URL-encoded form. Prints and writes only
item ids, file paths and counts, never a value. Not seen: a value drawn inside an image, runs of 5,000+ characters without
a space (counted, not read).
Reads: <AV_HOME>/bw/main (a copy), and by default ~/.claude, ~/.codex, /private/tmp/claude-<uid>, ~/opt/agent-session-manager,
$TMPDIR, of the user who ran sudo. Writes: <AV_OUT>/leak_scan_<dt>.txt (counts only).
"""
import datetime
import getpass
import os
import pwd
import re
import shutil
import sys
import tempfile
import urllib.parse

from . import bitwarden as BWM
from .common import BW_DIR, OUT

W = 8  # piece length: 70 symbols ** 8 = 5.8e14, a random match in a few GB of text is unlikely
MAX_RUN = 5000
RX_RUN = re.compile(rb"[A-Za-z0-9._!@#%+=-]{8,}")


def main(argv):
    if os.geteuid() != 0:
        sys.exit("leak-scan needs sudo (to read agent-vault's Bitwarden login): sudo vault-admin leak-scan")
    user = os.environ.get("SUDO_USER") or pwd.getpwuid(os.getuid()).pw_name
    home = pwd.getpwnam(user).pw_dir
    tmp = tempfile.mkdtemp(prefix="lv_leak_")
    try:
        shutil.copytree(BW_DIR, os.path.join(tmp, "bw"))
        BWM.BW_DIR = os.path.join(tmp, "bw")  # bw writes into its folder: a copy, so av-vault's stays its own
        v = BWM.Vault()
        v.ready = lambda: None  # no sync: the copy is read as it is
        try:  # the password through a named pipe in a private folder, as the daemon does
            v.unlock(getpass.getpass("Bitwarden master password: "))
        except RuntimeError as e:
            sys.exit(str(e))
        l_sec = v.secrets()
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    d_piece, d_pw = {}, {}
    for n, (iid, cat, val) in enumerate(l_sec):
        for form, s in (("plain", val), ("url-encoded", urllib.parse.quote(val, safe=""))):
            if form != "plain" and s == val:
                continue
            b, k = s.encode(), (iid[:8], cat, form, n)
            d_pw[k] = {b[i:i + W] for i in range(len(b) - W + 1)}
            for pc in d_pw[k]:
                d_piece.setdefault(pc, set()).add(k)
    n_sec = len(l_sec)
    del l_sec
    S = set(d_piece)
    l_root = [] if "--only" in argv else [os.path.join(home, x) for x in (".claude", ".codex", "opt/agent-session-manager")] + \
        [f"/private/tmp/claude-{pwd.getpwnam(user).pw_uid}", os.environ.get("TMPDIR", "/tmp")]
    l_root += [a for a in argv if not a.startswith("--")]
    d_hit, n = {}, {"file": 0, "byte": 0, "blob": 0}

    def scan(path):
        try:
            data = open(path, "rb").read()
        except OSError:
            return
        n["file"], n["byte"] = n["file"] + 1, n["byte"] + len(data)
        for m in RX_RUN.finditer(data):
            run = m.group(0)
            if len(run) > MAX_RUN:
                n["blob"] += 1
                continue
            found = {run[i:i + W] for i in range(len(run) - W + 1)} & S
            for k in {k for pc in found for k in d_piece[pc]}:
                d = d_hit.setdefault((k[0], path), {})
                kind = f"WHOLE ({k[1]}, {k[2]})" if d_pw[k] <= found else f"piece ({k[1]}, {k[2]})"
                d[kind] = d.get(kind, 0) + 1

    for root in l_root:
        if os.path.isfile(root):
            scan(root)
            continue
        for dirpath, _, l_f in os.walk(root):
            for f in l_f:
                scan(os.path.join(dirpath, f))
        print(f"scanned {root}", flush=True)
    dt = datetime.datetime.now().strftime("%Y-%m-%d_%H%M")
    l_out = [f"leak scan {dt}: {n_sec} secrets, {n['file']:,} files, {n['byte'] / 1e9:.2f} GB, {n['blob']:,} long blobs not read",
             f"{len(d_hit)} (item, file) pairs with a hit" + (": NONE, clean" if not d_hit else ":")]
    for (iid, path), d in sorted(d_hit.items()):
        l_out.append(f"  item {iid}  {', '.join(f'{k} ×{v}' for k, v in sorted(d.items())):55s} {path}")
    os.makedirs(OUT, exist_ok=True)
    out = os.path.join(OUT, f"leak_scan_{dt}.txt")
    open(out, "w").write("\n".join(l_out) + "\n")
    os.chmod(out, 0o640)
    print("\n".join(l_out) + f"\n→ {out}")
