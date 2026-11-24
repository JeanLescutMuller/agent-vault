#!/bin/bash
# agent-vault's system part (DESIGN.md §5): run once by Jean, and after every change of src or bin. Idempotent.
#   sudo bash /Users/jeanlescut/dev/agents/agent-vault/install_system.sh [--from-layer [--recopy]]      (self-contained: no ../ script)
#   Side by side with the live layer-vault (other user, folders, sudoers file, label): installing this changes nothing of it.
#   --from-layer: COPIES the old vault's state from /var/layer-vault and /var/layer-vault-out (the key and fingerprints = the
#       mask list, grants, suspected secrets, events, alerts, the Bitwarden login and its unlock session) into the new
#       folders, owned by av-vault. Never moves, changes or deletes the old. Done once (a marker /var/agent-vault/.from-layer);
#       --recopy copies again (overwrites the new side: use it only before the switch, doc/switch_from_layer.md).
# Makes:
#   the hidden Mac user and group av-vault (an id in 450-499, no login, no password, shell /usr/bin/false)
#   /usr/local/agent-vault/        root:wheel 755: src, bin (vault, vault-admin, vault-run, vault-type), venv (Python 3.12 + requirements.txt)
#   /var/agent-vault/              av-vault 700: the Bitwarden login (bw/main), session, key, fingerprints, grants, suspected secrets
#   /var/agent-vault-out/          av-vault:staff 750: alerts.jsonl, events (what Jean's user may read: never a value)
#   /etc/sudoers.d/agent-vault     root 440, checked with visudo:
#       Jean's user → vault-run as av-vault, no password (agents call `vault`; CLAUDE_CODE_SESSION_ID kept: whose grant, whose tab)
#       av-vault    → vault-type as Jean's user, no password (the Apple Events into his Chrome; the tab record in his home)
#   Bitwarden: with --from-layer the old login is copied; else the `bw login` line to type is printed. Then Jean unlocks:
#   vault-admin unlock (his master password).
# Linux (the NAS, task D5): a mask-only copy. The same users and folders (useradd, Jean's own group instead of staff), the
# file MASK_ONLY beside src/ (cli.py: mask, reveal, status, the import of the Mac's fingerprints; no Bitwarden, no grant,
# no typing: no vault-type sudoers line), Python: a root-owned copy of Jean's uv Python 3.14 (skill runtime-environments) in
# /usr/local/agent-vault/python with the venv on it; av-vault's import key, its public half in /var/agent-vault-out/import.pub.
# Then, on the Mac: bash /Users/jeanlescut/dev/agents/agent-vault/tools/mask_to_nas.sh (the Mac's key and fingerprints, sealed for this av-vault).
set -euo pipefail
SRC="$(cd "$(dirname "$0")" && pwd)"
SYS=/usr/local/agent-vault VAR=/var/agent-vault OUTD=/var/agent-vault-out SUDOERS=/etc/sudoers.d/agent-vault
LVAR=/var/layer-vault LOUT=/var/layer-vault-out   # the live layer-vault's folders: read by --from-layer, never written
PY=/Library/Frameworks/Python.framework/Versions/3.12/bin/python3.12
FROM_LAYER=0 RECOPY=0
for a in "$@"; do case "$a" in
    --from-layer) FROM_LAYER=1 ;; --recopy) RECOPY=1 ;;
    *) echo "usage: sudo bash $0 [--from-layer [--recopy]]"; exit 2 ;; esac; done
[ "$RECOPY" = 0 ] || [ "$FROM_LAYER" = 1 ] || { echo "--recopy needs --from-layer"; exit 2; }
OS=$(uname -s) GRP=wheel
[ "$OS" = Linux ] && GRP=root
step() { printf '\n%s\n' "$1"; }
ok() { printf '  ok   %s\n' "$1"; }
die() { printf '  FAILED  %s\n' "$1"; exit 1; }

[ "$(id -u)" = 0 ] || die "run as root: sudo bash $SRC/install_system.sh"
JEAN="${SUDO_USER:-}"
[ -n "$JEAN" ] && [ "$JEAN" != root ] || die "run through sudo from Jean's user"
if [ "$OS" = Darwin ]; then
    JHOME=$(dscl . -read "/Users/$JEAN" NFSHomeDirectory | awk '{print $2}')
    [ -x "$PY" ] || die "Python 3.12 missing: $PY (python.org installer)"
    OUTG=staff
else
    JHOME=$(getent passwd "$JEAN" | cut -d: -f6)
    OUTG=$(id -gn "$JEAN")   # what Jean's user may read (alerts), as staff on the Mac
    UVPY=$(readlink -f "$JHOME/.local/bin/python3" || true)   # …/uv/python/cpython-3.14.x-linux-x86_64-gnu/bin/python3.14
    case "$UVPY" in */cpython-3.14*/bin/python3.14) PYHOME="${UVPY%/bin/*}" ;; *) die "uv's Python 3.14 missing as $JHOME/.local/bin/python3 (skill runtime-environments)" ;; esac
fi

step "repo"
sudo -u "$JEAN" git -C "$SRC" diff --quiet HEAD -- src bin requirements.txt install_system.sh \
    || die "uncommitted changes in agent-vault's src or bin: commit them, read the diff, run again"
ok "commit $(sudo -u "$JEAN" git -C "$SRC" log -1 --format='%h %s' | cut -c1-90)"

step "user av-vault"
if [ "$OS" = Linux ]; then
    if ! getent passwd av-vault >/dev/null; then
        used=$( (getent passwd; getent group) | cut -d: -f3)
        id=""; for i in $(seq 450 499); do grep -qx "$i" <<<"$used" || { id=$i; break; }; done
        [ -n "$id" ] || die "no free id in 450-499"
        getent group av-vault >/dev/null || groupadd --system --gid "$id" av-vault
        useradd --system --uid "$id" --gid av-vault --home-dir "$VAR" --no-create-home --shell /usr/sbin/nologin --comment agent-vault av-vault
    fi
    usermod --home "$VAR" --shell /usr/sbin/nologin av-vault
elif ! dscl . -read /Users/av-vault >/dev/null 2>&1; then
    used=$( (dscl . -list /Users UniqueID; dscl . -list /Groups PrimaryGroupID) | awk '{print $2}')
    id=""; for i in $(seq 450 499); do grep -qx "$i" <<<"$used" || { id=$i; break; }; done
    [ -n "$id" ] || die "no free id in 450-499"
    dscl . -create /Groups/av-vault && dscl . -create /Groups/av-vault PrimaryGroupID "$id" && dscl . -create /Groups/av-vault RealName "agent-vault"
    dscl . -create /Users/av-vault && dscl . -create /Users/av-vault UniqueID "$id"
fi
if [ "$OS" = Darwin ]; then
    gid=$(dscl . -read /Groups/av-vault PrimaryGroupID | awk '{print $2}')
    dscl . -create /Users/av-vault PrimaryGroupID "$gid"
    dscl . -create /Users/av-vault UserShell /usr/bin/false
    dscl . -create /Users/av-vault NFSHomeDirectory "$VAR"
    dscl . -create /Users/av-vault RealName "agent-vault"
    dscl . -create /Users/av-vault IsHidden 1
    dscl . -create /Users/av-vault Password '*'
fi
ok "av-vault, id $(id -u av-vault)"

step "folders"
dir() { mkdir -p "$1" && chown "$2" "$1" && chmod "$3" "$1"; }
dir "$VAR" av-vault:av-vault 700 && dir "$VAR/bw" av-vault:av-vault 700
dir "$OUTD" "av-vault:$OUTG" 750
ok "$VAR (700) · $OUTD (750, group $OUTG)"

if [ "$FROM_LAYER" = 1 ]; then
step "state copied from layer-vault"
if [ -e "$VAR/.from-layer" ] && [ "$RECOPY" = 0 ]; then
    ok "already copied ($(cat "$VAR/.from-layer")): --recopy to copy again (overwrites $VAR)"
else
    [ -d "$LVAR" ] || die "$LVAR missing: nothing to copy (the old layer-vault is not installed here)"
    cp -Rp "$LVAR/." "$VAR/" && chown -R av-vault:av-vault "$VAR" && chmod 700 "$VAR"
    if [ -d "$LOUT" ]; then cp -Rp "$LOUT/." "$OUTD/" && chown -R "av-vault:$OUTG" "$OUTD" && chmod 750 "$OUTD"; fi
    date -u +%Y-%m-%dT%H:%M:%SZ > "$VAR/.from-layer" && chown av-vault:av-vault "$VAR/.from-layer"
    ok "copied $LVAR ($(find "$LVAR" -type f 2>/dev/null | wc -l | tr -d ' ') files) and $LOUT; the old one untouched"
fi
fi
if [ "$OS" = Darwin ]; then
step "Bitwarden login"
if [ -f "$VAR/bw/main/data.json" ]; then
    ok "$VAR/bw/main already there"
else
    printf '  todo  log agent-vault in once, in your Terminal (or run this script again with --from-layer):\n        sudo -u av-vault env HOME=%s BITWARDENCLI_APPDATA_DIR=%s/bw/main /opt/homebrew/bin/bw login\n' "$VAR" "$VAR"
fi
fi

step "code"
# Not yet (D5 check, 2026-11-22): pip --require-hashes --only-binary :all: from a hashed lock. uv.lock (requires-python >= 3.14)
# holds no cffi wheel for the Mac's python.org 3.12, so a lock exported from it would break the Mac's venv: first the Mac's
# root-owned Python moves to 3.14 (skill runtime-environments, migration step 7), then one hashed requirements.txt for both.
NEW="$SYS.new"
[ ! -e "$NEW" ] || rm -r /usr/local/agent-vault.new
mkdir -p "$NEW"
cp -R "$SRC/src" "$SRC/bin" "$SRC/requirements.txt" "$NEW/"
find "$NEW" -name __pycache__ -type d -prune -exec rm -r {} +
if [ "$OS" = Linux ]; then  # the venv on a root-owned copy of uv's 3.14, built in $NEW, then its paths set to $SYS (after the swap)
    cp -R "$PYHOME" "$NEW/python"
    "$NEW/python/bin/python3" -m venv "$NEW/venv" && "$NEW/venv/bin/python" -m pip -q install --disable-pip-version-check --no-cache-dir -r "$NEW/requirements.txt" || die "venv"
    "$NEW/venv/bin/python" -I -c "import sys; sys.path.insert(0, '$NEW/src'); import agent_vault.cli, agent_vault.bundle, cryptography" \
        || die "the code does not import with $NEW/venv"
    sed -i "s#$NEW/#$SYS/#g" "$NEW/venv/pyvenv.cfg"
    for l in "$NEW"/venv/bin/python*; do [ ! -L "$l" ] || ln -sfn "$(readlink "$l" | sed "s#^$NEW/#$SYS/#")" "$l"; done
    touch "$NEW/MASK_ONLY"   # cli.py: mask only (no Bitwarden, no grant, no typing on this machine)
elif [ -x "$SYS/venv/bin/python" ] && cmp -s "$SRC/requirements.txt" "$SYS/requirements.txt"; then
    cp -R "$SYS/venv" "$NEW/venv"                                  # the same packages: no new download
else
    "$PY" -m venv "$NEW/venv" && "$NEW/venv/bin/pip" -q install --disable-pip-version-check -r "$NEW/requirements.txt" || die "venv"
fi
[ "$OS" = Linux ] || "$NEW/venv/bin/python" -I -c "import sys; sys.path.insert(0, '$NEW/src'); import agent_vault.cli, agent_vault.chrome, cryptography" \
    || die "the code does not import with $NEW/venv"
chown -R "root:$GRP" "$NEW" && chmod -R go-w "$NEW" && chmod -R a+rX "$NEW" && chmod 755 "$NEW"/bin/*
[ ! -e "$SYS" ] || mv "$SYS" "$SYS.old"
mv "$NEW" "$SYS"
[ ! -e "$SYS.old" ] || rm -r /usr/local/agent-vault.old
"$SYS/venv/bin/python" -I -c "import cryptography" || die "$SYS/venv does not run after the move"
ok "$SYS: $(ls "$SYS/bin" | tr '\n' ' ')$([ ! -e "$SYS/MASK_ONLY" ] || echo '(mask only)')"

step "sudoers"
T=$(mktemp)
cat > "$T" <<SUD
# agent-vault (agents/agent-vault/install_system.sh): agents call vault; only vault-run runs as av-vault
Defaults!$SYS/bin/vault-run env_keep += "CLAUDE_CODE_SESSION_ID CLAUDE_CODE_ENTRYPOINT"
$JEAN ALL=(av-vault) NOPASSWD: $SYS/bin/vault-run
SUD
[ "$OS" = Linux ] || echo "av-vault ALL=($JEAN) NOPASSWD: $SYS/bin/vault-type" >> "$T"   # typing: the Mac only (Apple Events)
visudo -cf "$T" >/dev/null || { rm "$T"; die "the sudoers lines do not parse"; }
install -o root -g "$GRP" -m 440 "$T" "$SUDOERS" && rm "$T"
# the whole configuration: a real error fails; another file's mode (UGOS ships /etc/sudoers.d/README 644, which sudo
# only warns about and skips) is reported, not fatal (D5, 2026-11-23)
vc=$(visudo -c 2>&1) || { printf '%s\n' "$vc" | grep -v "bad permissions, should be mode 0440" | grep -qiE "error|>>>" &&
    die "sudoers broken after $SUDOERS: remove it ($vc)"; echo "  note: visudo: $(printf '%s' "$vc" | grep "bad permissions" | head -n 1) (not ours: sudo skips that file)"; }
ok "$SUDOERS"

step "check"
r=$(cd / && sudo -u "$JEAN" "$SYS/bin/vault" status 2>&1 | grep -m1 '^vault:' || true)
case "$r" in *vault*) ok "as $JEAN: vault status → $r" ;; *) die "vault status as $JEAN: $r" ;; esac
if [ "$OS" = Linux ]; then  # the import key's public half, for the Mac's tools/mask_to_nas.sh (Jean's user may read it)
    (cd / && sudo -u av-vault "$SYS/bin/vault-run" vault-admin mask-key) > "$OUTD/import.pub.new" && mv "$OUTD/import.pub.new" "$OUTD/import.pub"
    chown "av-vault:$OUTG" "$OUTD/import.pub" && chmod 640 "$OUTD/import.pub"
    ok "$OUTD/import.pub (then, on the Mac: bash $SRC/tools/mask_to_nas.sh)"
fi
printf '\nnext, as Jean (not sudo): bash %s/install.sh [--stage]   then: vault-admin unlock (not needed after --from-layer: the session is copied)\n' "$SRC"
