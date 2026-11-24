#!/bin/bash
# Copy what `vault mask` needs to the NAS's mask-only vault (task D5): the Mac's agent-vault key and fingerprints (never a
# value), sealed for the NAS's av-vault. Run by Jean on the Mac, in his own Terminal (sudo here, then sudo on the NAS), after
# the NAS's install_system.sh and the Mac's own `sudo bash install_system.sh` (its root-owned code must have bundle.py), and
# again after vault-admin sync when new passwords should be masked on the NAS too.
#   bash /Users/jeanlescut/dev/agents/agent-vault/tools/mask_to_nas.sh [--leave-out card,iban,ahv]
#   1. ssh babisnas: the public half of the NAS av-vault's import key (/var/agent-vault-out/import.pub)
#   2. sudo (the Mac's password): root, in the root-owned /usr/local/agent-vault code, reads /var/agent-vault/key and
#      fingerprints.json and seals them (bundle.seal_from): the key never passes through a process of Jean's user; only the
#      sealed bundle does → ~/.cache/agent-vault-mask.bundle on the NAS (ciphertext: only the NAS's av-vault opens it)
#      --leave-out: those categories are not sent (the NAS then neither masks them nor can guess them offline); default: all
#   3. ssh -t babisnas: sudo vault-admin import-mask (the NAS's password) → its key and fingerprints; the bundle file deleted
#   4. the check (a second, plain ssh: vault status): the NAS counts the same items as were sealed here (a swapped bundle would not)
set -euo pipefail
NAS=babisnas
SYS=/usr/local/agent-vault
LEAVE_OUT=""
[ "${1:-}" = --leave-out ] && LEAVE_OUT="${2:?--leave-out card,iban,ahv}"
[[ "$LEAVE_OUT" =~ ^[a-z,]*$ ]] || { echo "--leave-out: categories separated by commas (card,iban,ahv)"; exit 2; }
[ -f "$SYS/src/agent_vault/bundle.py" ] || { echo "$SYS has no bundle.py yet: sudo bash /Users/jeanlescut/dev/agents/agent-vault/install_system.sh first"; exit 1; }
pub=$(ssh -o LogLevel=ERROR "$NAS" 'cat /var/agent-vault-out/import.pub' 2>/dev/null | head -1)
[[ "$pub" =~ ^[A-Za-z0-9+/]{43}=$ ]] || { echo "no import key on the NAS (/var/agent-vault-out/import.pub): sudo bash install_system.sh there first"; exit 1; }
echo "the Mac's sudo password (root seals agent-vault's key and fingerprints; nothing is shown):"
out=$(sudo "$SYS/venv/bin/python" -I -c 'import sys; sys.path.insert(0, "/usr/local/agent-vault/src")
from agent_vault.bundle import seal_from
n, bundle = seal_from("/var/agent-vault", sys.argv[1], sys.argv[2])
print(n); print(bundle)' "$pub" "$LEAVE_OUT")
n_mac=${out%%$'\n'*}
printf '%s\n' "${out#*$'\n'}" | ssh -o LogLevel=ERROR "$NAS" 'mkdir -p ~/.cache && umask 077 && cat > ~/.cache/agent-vault-mask.bundle'
echo "  ok   sealed bundle on the NAS: ~/.cache/agent-vault-mask.bundle ($n_mac items${LEAVE_OUT:+, without $LEAVE_OUT})"
echo "the NAS's sudo password (its av-vault opens the bundle):"
# in sight: the NAS's sudo prompt, a "Sorry, try again", the import's own line; then the count, by a second plain call
ssh -t -o LogLevel=ERROR "$NAS" 'sudo /usr/local/agent-vault/bin/vault-admin import-mask < ~/.cache/agent-vault-mask.bundle; rm -f ~/.cache/agent-vault-mask.bundle' || true
r=$(ssh -o LogLevel=ERROR "$NAS" '/usr/local/agent-vault/bin/vault status' 2>&1)   # (not ~/.local/bin/vault: it may run before the NAS's install.sh)
echo "  NAS: $r"
n_nas=$(sed -n 's/.* pieces of \([0-9]*\) items.*/\1/p' <<<"$r")
if [ "$n_nas" = "$n_mac" ]; then echo "  ok   the NAS masks the same $n_mac items as were sealed here"
else echo "  FAILED  the NAS reports ${n_nas:-no count} items, $n_mac were sealed: run this again"; exit 1; fi
