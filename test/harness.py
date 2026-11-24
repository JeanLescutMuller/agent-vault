"""The vault's tests' shared sandbox: a fresh run folder with a fake vault (a JSON file behind a fake `bw`) and agent-vault's
state in it, the two commands run as subprocesses, every case tagged with its ID (V01-V22, N05, N06, N10), and a leak check
over every output. Nothing on the Mac changes; no sudo, no Chrome, no Claude session.

  from harness import Box;  b = Box("vault");  b.case("V01", "…", cond);  b.done()
"""
import json
import os
import subprocess
import sys
from collections import Counter

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from paths import AV, BW_STUB, run_dir  # noqa: E402

S1, S2 = "11111111-2222-3333-4444-555555555555", "99999999-8888-7777-6666-555555555555"
USER, PW, OLD = "me@example.com", "Kq7mW2xZ9pLr4tVb", "Old-Pass-Rt4nB8vL3s"
CARD, IBAN, AHV = "4539 1488 0343 6467", "CH93 0076 2011 6238 5295 7", "756.1234.5678.97"
TEMP, PHONE, ADDR = "Ph8#nQ2vLx5w", "+41 79 555 01 23", "Musterstrasse 1, 8000 Zürich"
TABS = {"801": "http://galaxus.localhost/checkout", "802": "http://other.localhost/x", "803": "http://reviews.localhost/x"}
ITEMS = [{"id": "a1b2c3d4e5", "folderId": "F1", "type": 1, "name": "galaxus", "notes": "", "fields": [], "revisionDate": "2026-11-01",
          "creationDate": "2026-01-01T00:00:00Z", "passwordHistory": [{"password": OLD, "lastUsedDate": "2026-10-01T00:00:00Z"}],
          "login": {"username": USER, "password": PW, "uris": [{"uri": "http://galaxus.localhost/login"}]}},
         {"id": "c0ffee0001", "folderId": "F2", "type": 3, "name": "Visa", "card": {"number": CARD}},
         {"id": "1ba11ba111", "folderId": "F2", "type": 2, "name": "Bank", "fields": [{"name": "IBAN", "value": IBAN, "type": 0}]},
         {"id": "1d1d1d1d01", "folderId": "F2", "type": 4, "name": "Jean", "identity": {"ssn": AHV}}]


class Box:
    def __init__(self, kind):
        self.dir = run_dir(kind)
        self.home, self.out, self.chrome = (os.path.join(self.dir, x) for x in ("home", "out", "chrome"))
        for d in (os.path.join(self.home, "bw", "main"), self.out, self.chrome):
            os.makedirs(d, exist_ok=True)
        self.fake_vault(self.home)
        self.task = self.script("task", f"echo \"$@\" >> {self.dir}/tasks.log\necho T-4242")
        json.dump({t: {"session_id": S1, "url": u} for t, u in TABS.items()} | {"888": {"session_id": S2, "url": "http://galaxus.localhost/x"}},
                  open(os.path.join(self.chrome, "open.json"), "w"))
        self.env = {k: v for k, v in os.environ.items() if not k.startswith(("CLAUDE_CODE_", "AV_"))}
        self.env.update(AV_HOME=self.home, AV_OUT=self.out, AV_BW=self.bw, AV_CHROME_STATE=self.chrome,
                        CLAUDE_CODE_SESSION_ID=S1, CLAUDE_CODE_ENTRYPOINT="sdk-cli")
        self.outputs, self.ids, self.fails = [], Counter(), []
        print(f"sandbox: {self.dir}")

    def script(self, name, body):
        p = os.path.join(self.dir, name)
        open(p, "w").write(f"#!/bin/sh\n{body}\n")
        os.chmod(p, 0o755)
        return p

    def fake_vault(self, home, items=None):
        os.makedirs(os.path.join(home, "bw", "main"), exist_ok=True)
        json.dump({"folders": [{"id": "F1", "name": "Agent auto-login"}, {"id": "F2", "name": "Other"}], "items": items or ITEMS},
                  open(os.path.join(home, "bw", "main", "db.json"), "w"))
        self.bw = self.script("bw", f"exec {sys.executable} {BW_STUB} \"$@\"")

    def run(self, prog, *a, stdin="", env=None):
        """vault or vault-admin (agent-vault's bin): (exit code, output)."""
        p = subprocess.run([os.path.join(AV, "bin", prog)] + list(a), input=stdin, capture_output=True, text=True,
                           env={**self.env, **(env or {})}, timeout=60)
        self.outputs.append(p.stdout + p.stderr)
        return p.returncode, (p.stdout + p.stderr).strip()

    def case(self, cid, name, cond, detail=""):
        self.ids[cid] += 1
        if not cond:
            self.fails.append(cid)
        print(f"{'ok  ' if cond else 'FAIL'}  {cid:<6} {name}" + ("" if cond else f"   ({str(detail)[:180]})"))

    def done(self, secrets, allowed=()):
        """The leak check (every secret, in every output, minus those revealed on purpose) and the summary; exits 1 on a fail."""
        blob = "\n".join(self.outputs).replace(" ", "")
        leaks = [s[:4] + "…" for s in secrets if s.replace(" ", "") in blob and s not in allowed]
        print(f"\n{len(self.outputs)} outputs checked: " + ("clean" if not leaks else f"LEAK {leaks}"))
        print(f"RESULT: {'all ok' if not self.fails else str(len(self.fails)) + ' FAIL ' + ' '.join(sorted(set(self.fails)))} | "
              f"{'no leak' if not leaks else 'LEAK'} | {sum(self.ids.values())} checks, {len(self.ids)} cases | sandbox {self.dir}")
        json.dump(sorted(self.ids), open(os.path.join(self.dir, "case_ids.json"), "w"))
        sys.exit(1 if self.fails or leaks else 0)
