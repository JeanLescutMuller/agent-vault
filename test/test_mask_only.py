"""agent-vault's mask-only copy (the NAS) and the sealed copy of the Mac's fingerprints, cases N05, N06, N10: the mask-only vault
(Bitwarden, grants and typing refused; mask and status answer), the Mac's key and fingerprints sealed for the NAS's av-vault
(only that key opens them, only through sudo), the first import dropping the suspected secrets kept under the NAS's own key.
Runs on the Mac and on Linux; nothing real is read or changed; no sudo.

  bash test/run_all.sh nas
"""
import json
import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from harness import PW, Box  # noqa: E402
from paths import AV  # noqa: E402

b = Box("nas")

# N05: the mask-only vault (the NAS): mask works; Bitwarden, grants and typing refused; status says so
mo = {"AV_MASK_ONLY": "1"}
r = {v: b.run("vault", *a, env=mo)[0] for v, a in {"type-password": ("type-password", "801"), "list": ("list",), "save-token": ("save-token", "x", "--site", "a.ch")}.items()}
r["unlock"] = b.run("vault-admin", "unlock", stdin="testmaster\n", env=mo)[0]
r["grant"] = b.run("vault-admin", "grant", "x", "y", env={**mo, "AV_ADMIN_OK": "1"})[0]
c_mask, o_mask = b.run("vault", "mask", stdin=json.dumps(["hello, a plain text"]), env=mo)
c_st, o_st = b.run("vault", "status", env=mo)
b.case("N05", "mask-only vault: type-password, list, save-token, unlock, grant refused; mask answers; status says mask only",
       set(r.values()) == {1} and c_mask == 0 and "a plain text" in o_mask and c_st == 0 and "mask only" in o_st, [r, o_mask, o_st])

# N06: the Mac's fingerprints, sealed for the NAS's av-vault: only that key opens them, only through sudo; then the NAS masks
# the Mac's vault secrets with the same tokens
mac = Box("nas-mac")  # a second box: "the Mac", whose vault knows the items
c_u, _ = mac.run("vault-admin", "unlock", stdin="testmaster\n")
c_m, o_m = mac.run("vault", "mask", stdin=json.dumps([f"pw {PW}"]))
nas_env = {**mo, "AV_HOME": b.home + "-nas", "AV_OUT": b.out}
os.makedirs(b.home + "-nas", exist_ok=True)
c_k, pub = b.run("vault-admin", "mask-key", env=nas_env)
payload = json.dumps({"key": __import__("base64").b64encode(open(os.path.join(mac.home, "key"), "rb").read()).decode(),
                      "fingerprints": json.load(open(os.path.join(mac.home, "fingerprints.json")))})
venv_py = sys.executable
seal_code = "import sys, json; sys.path.insert(0, sys.argv[1]); from agent_vault.bundle import seal_from; print(json.dumps(seal_from(*sys.argv[2:])))"
seal = subprocess.run([venv_py, "-I", "-c", seal_code, os.path.join(AV, "src"), mac.home, pub, ""], capture_output=True, text=True, timeout=30)
n_sealed, bundle = json.loads(seal.stdout) if seal.returncode == 0 else (0, "")
seal_cut = subprocess.run([venv_py, "-I", "-c", seal_code, os.path.join(AV, "src"), mac.home, pub, "card,iban,ahv"], capture_output=True, text=True, timeout=30)
n_cut = json.loads(seal_cut.stdout)[0] if seal_cut.returncode == 0 else -1
other = subprocess.run([sys.executable, "-I", "-c", "import sys; sys.path.insert(0, sys.argv[1]); from agent_vault.bundle import seal, key_pair; "
                        "import json, tempfile, os; p = os.path.join(tempfile.mkdtemp(), 'k'); print(seal(json.loads(sys.stdin.read()), key_pair(p)))",
                        os.path.join(AV, "src")], input=payload, capture_output=True, text=True, timeout=30).stdout
c_no, o_no = b.run("vault-admin", "import-mask", stdin=bundle, env=nas_env)
c_wrong, o_wrong = b.run("vault-admin", "import-mask", stdin=other, env={**nas_env, "AV_ADMIN_OK": "1"})
c_imp, o_imp = b.run("vault-admin", "import-mask", stdin=bundle, env={**nas_env, "AV_ADMIN_OK": "1"})
c_nm, o_nm = b.run("vault", "mask", stdin=json.dumps([f"pw {PW}"]), env=nas_env)
b.case("N06", "the sealed copy: no import without sudo, another key's bundle refused, then the NAS masks the Mac's secret with the Mac's token and counts the items sealed; --leave-out card,iban,ahv drops those items; no value in the bundle",
       (c_u, c_m, c_k, seal.returncode, c_no, c_wrong, c_imp, c_nm) == (0, 3, 0, 0, 1, 1, 0, 3) and "another one" in o_wrong
       and o_nm.split("\n")[0] == o_m.split("\n")[0] and PW not in bundle and f"of {n_sealed} items" in o_imp and n_sealed == 4 and n_cut == 1,
       [c_u, c_m, c_k, seal.stderr[-200:], o_no, o_wrong, o_imp, o_nm, o_m, n_sealed, n_cut])
# N10: the first import drops the suspected secrets kept under the NAS's own first key (else unreadable: every mask would fail)
os.makedirs(b.home + "-nas2", exist_ok=True)
n2 = {**nas_env, "AV_HOME": b.home + "-nas2"}
c_s, o_s = b.run("vault", "mask", stdin=json.dumps(["password: Zq8-Temp-Pass-11"]), env=n2)
sid = o_s.split("<suspected-secret ")[1][:8] if "<suspected-secret " in o_s else ""
b.run("vault", "reveal", f"<suspected-secret {sid}>", "--temporary", "--why", "a one-time code that expires within the hour", env=n2)
c_k2, pub2 = b.run("vault-admin", "mask-key", env=n2)
bundle2 = json.loads(subprocess.run([venv_py, "-I", "-c", seal_code, os.path.join(AV, "src"), mac.home, pub2, ""], capture_output=True, text=True, timeout=30).stdout)[1]
c_i2, o_i2 = b.run("vault-admin", "import-mask", stdin=bundle2, env={**n2, "AV_ADMIN_OK": "1"})
c_m2, o_m2 = b.run("vault", "mask", stdin=json.dumps(["hello, a plain text"]), env=n2)
b.case("N10", "the first import: a suspected secret kept (and revealed) before it is dropped, said so; masking still works",
       c_s == 3 and bool(sid) and c_i2 == 0 and "1 suspected secret(s)" in o_i2 and c_m2 == 0 and not os.listdir(os.path.join(b.home + "-nas2", "suspected")),
       [o_s, o_i2, o_m2])


b.done([PW])
