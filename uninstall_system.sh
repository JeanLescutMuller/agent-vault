#!/bin/bash
# Undo install_system.sh: the sudoers lines and the root-owned code. Keeps the data (/var/agent-vault: the Bitwarden login,
# grants, fingerprints, suspected secrets; /var/agent-vault-out) and the user av-vault unless --purge is given.
#   sudo bash /Users/jeanlescut/dev/agents/agent-vault/uninstall_system.sh [--purge]
set -euo pipefail
[ "$(id -u)" = 0 ] || { echo "run as root: sudo bash $0"; exit 1; }
[ ! -e /etc/sudoers.d/agent-vault ] || rm /etc/sudoers.d/agent-vault
[ ! -e /usr/local/agent-vault ] || rm -r /usr/local/agent-vault
echo "removed: /etc/sudoers.d/agent-vault, /usr/local/agent-vault"
if [ "${1:-}" = --purge ]; then
    [ ! -e /var/agent-vault ] || rm -r /var/agent-vault
    [ ! -e /var/agent-vault-out ] || rm -r /var/agent-vault-out
    if [ "$(uname -s)" = Linux ]; then  # the NAS's mask-only copy (task D5)
        userdel av-vault 2>/dev/null || true
        groupdel av-vault 2>/dev/null || true
    else
        dscl . -delete /Users/av-vault 2>/dev/null || true
        dscl . -delete /Groups/av-vault 2>/dev/null || true
    fi
    echo "purged: /var/agent-vault, /var/agent-vault-out, the user av-vault"
else
    echo "kept: /var/agent-vault, /var/agent-vault-out, the user av-vault (--purge removes them)"
fi
