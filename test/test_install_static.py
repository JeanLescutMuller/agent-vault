"""The install scripts, checked without running them (no sudo, nothing installed): every shell script parses (bash -n), the
options are validated before anything happens, no script reaches a ../ root script, and no old layer-* / lv-vault / LV_ name is
left in the code (the exceptions are listed here). Cases S01-S04.

  bash test/run_all.sh static
"""
import os
import re
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from harness import Box  # noqa: E402
from paths import AV  # noqa: E402

b = Box("static")
sh = sorted(os.path.join(AV, f) for f in ("install.sh", "install_system.sh", "uninstall_system.sh", "tools/mask_to_nas.sh", "src/alerts.sh",
                                          "bin/vault", "bin/vault-admin", "bin/vault-run", "bin/vault-type"))
bad = [f for f in sh if subprocess.run(["bash", "-n", f], capture_output=True).returncode]
b.case("S01", f"every shell script parses with bash -n ({len(sh)} scripts)", not bad, bad)

r = [subprocess.run(["bash", os.path.join(AV, f), "--bogus"], capture_output=True, text=True).returncode for f in ("install.sh", "install_system.sh")]
r2 = subprocess.run(["bash", os.path.join(AV, "install_system.sh"), "--recopy"], capture_output=True, text=True)
b.case("S02", "install.sh and install_system.sh refuse an unknown option, and --recopy without --from-layer, before doing anything",
       r == [2, 2] and r2.returncode == 2, [r, r2.returncode])

up = [f for f in sh if re.search(r'\$SRC/\.\./|\$d/\.\./\.venv|\.\./install', open(f).read())]
b.case("S03", "no install script reaches a ../ root script or a parent venv (self-contained)", not up, up)

# old names: allowed only in install_system.sh / install.sh (the --from-layer copy), the notes matcher, the doc of the switch
ALLOWED = {"install_system.sh", "install.sh", "bitwarden.py", "switch_from_layer.md", "test_install_static.py", "AGENTS.md", "DESIGN.md", "README.md"}
pat = re.compile(r"layer[-_]vault|layer[-_]firewall|layer[-_]chrome|lv-vault|\bLV_[A-Z]|(?<!doc/)agent-interfaces")
hits = []
for root, dirs, files in os.walk(AV):
    dirs[:] = [d for d in dirs if d not in (".git", ".venv", "runs", "__pycache__")]
    for f in files:
        if f in ALLOWED or f == "uv.lock":
            continue
        try:
            txt = open(os.path.join(root, f)).read()
        except (UnicodeDecodeError, OSError):
            continue
        if pat.search(txt):
            hits.append(os.path.relpath(os.path.join(root, f), AV))
b.case("S04", "no old name (layer-*, lv-vault, LV_*, agent-interfaces) outside the files that copy from or document the old layer-vault", not hits, hits)
b.done([])
