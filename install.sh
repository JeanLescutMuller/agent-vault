#!/bin/bash
# agent-vault's part in Jean's user, after the system part (sudo bash install_system.sh). Idempotent. Self-contained.
#   bash /Users/jeanlescut/dev/agents/agent-vault/install.sh [--stage] [--from-layer]
#   --stage       side by side with the live layer-vault: files under ~/opt/agent-vault only; NO ~/.local/bin links, NO skill
#                 links, NO job (the live vault, its skill and its alerts job keep running); no switch until task L5
#   --from-layer  also COPIES the old alerts state (~/.local/state/layer-vault/alerts_filed.json: what was already filed, so
#                 the new job does not file it twice); the old is never changed
#   (no option)   the switch: links, skill, job. Run it after install_system.sh and the steps of doc/switch_from_layer.md
#   the dev venv: ./.venv from pyproject.toml + uv.lock (uv sync --locked), used by test/ and by bin/vault when not installed
# Makes (without --stage):
#   ~/.local/bin/vault, ~/.local/bin/vault-admin -> /usr/local/agent-vault/bin/… (the root-owned commands; they run as av-vault)
#   skill vault → ~/opt/agent-vault/skills/vault, linked from ~/.claude/skills and ~/.agents/skills
#   ~/opt/agent-vault/alerts.sh + com.jeanlescut.agent-vault.alerts.plist (linked from ~/Library/LaunchAgents; Linux: .service and
#   .timer linked from ~/.config/systemd/user): the job
#   agent-vault.alerts every 5 min (src/alerts.sh: an alert task per leak or suspicious page)
set -euo pipefail
SRC="$(cd "$(dirname "$0")" && pwd)"
P=$HOME/opt/agent-vault NAME=com.jeanlescut.agent-vault.alerts SYS=/usr/local/agent-vault
STAGE=0 FROM_LAYER=0
for a in "$@"; do case "$a" in --stage) STAGE=1 ;; --from-layer) FROM_LAYER=1 ;; *) echo "usage: bash $0 [--stage] [--from-layer]"; exit 2 ;; esac; done
ok() { printf '  ok         %s\n' "$1"; }
OS=$(uname -s)   # Linux (the NAS, task D5): the alerts job's trigger is a systemd --user timer (skill jobs-and-services)
mkdir -p "$P" "$HOME/.local/bin"
[ -x "$SYS/bin/vault-run" ] || { echo "  FAILED     $SYS missing: sudo bash $SRC/install_system.sh first"; exit 1; }
if command -v uv >/dev/null && [ -f "$SRC/uv.lock" ]; then (cd "$SRC" && uv sync --locked -q) && ok "dev venv $SRC/.venv (uv sync --locked)"; fi
[ "$STAGE" = 1 ] || for c in vault vault-admin; do ln -sfn "$SYS/bin/$c" "$HOME/.local/bin/$c" && ok "~/.local/bin/$c -> $SYS/bin/$c"; done

for s in "$SRC"/skills/*/; do
    s="${s%/}"; name=$(basename "$s"); dst="$P/skills/$name"
    mkdir -p "$P/skills"; [ ! -d "$dst" ] || { chmod -R u+w "$dst" && rm -r "$dst"; }
    cp -R "$s" "$dst" && chmod -R a-w "$dst"
    if [ "$STAGE" = 0 ]; then for home in "$HOME/.claude/skills" "$HOME/.agents/skills"; do
        mkdir -p "$home"; ln -sfn "$dst" "$home/$name"
    done; fi
    ok "skill $name$([ "$STAGE" = 0 ] || echo ' (copied, not linked: --stage)')"
done

OLDST=$HOME/.local/state/layer-vault/alerts_filed.json NEWST=$HOME/.local/state/agent-vault/alerts_filed.json
if [ "$FROM_LAYER" = 1 ] && [ -f "$OLDST" ] && [ ! -e "$NEWST" ]; then
    mkdir -p "$(dirname "$NEWST")" && cp -p "$OLDST" "$NEWST" && ok "alerts state copied from $OLDST (the old one untouched)"
fi
cp "$SRC/src/alerts.sh" "$P/alerts.sh" && chmod +x "$P/alerts.sh"
if [ "$STAGE" = 1 ]; then ok "staged: no job, no link; the live layer-vault is untouched"
else
if [ "$OS" = Darwin ]; then
mkdir -p "$HOME/Library/LaunchAgents"
cat > "$P/$NAME.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>$NAME</string>
  <key>ProgramArguments</key><array><string>/bin/bash</string><string>$P/alerts.sh</string></array>
  <key>StartInterval</key><integer>300</integer><key>RunAtLoad</key><true/><key>AbandonProcessGroup</key><true/>
</dict></plist>
PLIST
ln -sfn "$P/$NAME.plist" "$HOME/Library/LaunchAgents/$NAME.plist"
launchctl bootout "gui/$(id -u)/$NAME" 2>/dev/null || true
launchctl bootstrap "gui/$(id -u)" "$HOME/Library/LaunchAgents/$NAME.plist"
ok "LaunchAgent $NAME (every 5 min): job agent-vault.alerts"
else
cat > "$P/$NAME.service" <<UNIT
# Written by agent-vault/install.sh; linked from ~/.config/systemd/user/. The job agent-vault.alerts (src/alerts.sh).
[Unit]
Description=agent-vault: alerts (its job-runner entrypoint)

[Service]
Type=oneshot
ExecStart=/bin/bash $P/alerts.sh
KillMode=process
TimeoutStartSec=infinity
UNIT
cat > "$P/$NAME.timer" <<UNIT
# Written by agent-vault/install.sh; linked from ~/.config/systemd/user/.
[Unit]
Description=agent-vault: alerts, every 300 s

[Timer]
OnBootSec=2min
OnUnitActiveSec=300s
Persistent=true
AccuracySec=10s

[Install]
WantedBy=timers.target
UNIT
mkdir -p "$HOME/.config/systemd/user"
for k in service timer; do ln -sfn "$P/$NAME.$k" "$HOME/.config/systemd/user/$NAME.$k"; done
loginctl enable-linger "$USER" 2>/dev/null || true
systemctl --user daemon-reload && systemctl --user enable --now "$NAME.timer" >/dev/null 2>&1
ok "systemd timer $NAME (every 5 min): job agent-vault.alerts"
fi
fi
V="$HOME/.local/bin/vault"; [ "$STAGE" = 0 ] || V="$SYS/bin/vault"
r=$("$V" status 2>&1 | head -1) && ok "vault status: $r" || { echo "  FAILED     vault status: $r"; exit 1; }
