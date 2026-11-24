# Switching from layer-vault to agent-vault (tasks L5 Mac, L6 NAS)

The ordered steps that install agent-vault beside the live layer-vault, copy its data, stop the old, and put the old aside. Every step ends with a check; stop at the first check that fails and read "Rollback". Jean types every `sudo`; agents run the rest. Nothing here deletes the old: it is renamed, so a rollback is a rename back.

```
today          install (1-3)             switch (4-7)                quarantine (8)
layer-vault ─► layer-vault  (live)  ─►  layer-vault  (stopped)  ─►  layer-vault.quarantine
               agent-vault  (staged)     agent-vault  (live)         agent-vault  (live)
```

| Old | New |
|---|---|
| `/usr/local/layer-vault`, `/var/layer-vault`, `/var/layer-vault-out` | `/usr/local/agent-vault`, `/var/agent-vault`, `/var/agent-vault-out` |
| user `lv-vault`, `/etc/sudoers.d/layer-vault` | user `av-vault`, `/etc/sudoers.d/agent-vault` |
| `~/opt/layer-vault`, job `com.jeanlescut.layer-vault.alerts` (job-runner id `layer-vault.alerts`) | `~/opt/agent-vault`, job `com.jeanlescut.agent-vault.alerts` (id `agent-vault.alerts`, from the folder name) |
| `~/.local/state/layer-vault/alerts_filed.json` | `~/.local/state/agent-vault/alerts_filed.json` |
| `vault`, `vault-admin` (`~/.local/bin`) | the same names, relinked in step 6 |

What `--from-layer` copies (`cp -Rp`, then `chown av-vault`; the old is only read): all of `/var/layer-vault` (the Bitwarden login `bw/main`, the unlock `session`, `key`, `fingerprints.json` = the mask list, `grants.json`, `suspected/`, `pending_saves.json`, `events.jsonl`) and `/var/layer-vault-out` (`alerts.jsonl`, events). The key is the same, so every `<vault-secret ...>` and `<suspected-secret ...>` token keeps its meaning. A marker `/var/agent-vault/.from-layer` stops a second copy by accident; `--recopy` overwrites the new side.

## Before (both machines)

- agent-chrome is installed (the tab record is at `~/opt/chrome-gateways/state/open.json` since 2026-11-24, renamed from agent-chrome: vault-type reads it) and agent-firewall's hooks call the command `vault` by its PATH name (no change needed).
- `git -C /Users/jeanlescut/dev/agents/agent-vault status --short` is empty and `bash /Users/jeanlescut/dev/agents/agent-vault/test/run_all.sh` ends with `all ok` in each part.
- Keep a baseline of the old vault: `vault status | head -1` (note "pieces of N items" and the unlock state) and `vault-admin status`.

## Mac (task L5)

Run steps 4 and 5 back to back, and make no `vault save-token` or grant between them: they write to the old side, and the copy in step 4 is the last one.

| # | Step | Command | Check |
|---|---|---|---|
| 1 | Install the new system part and copy the state (Jean, sudo) | `sudo bash /Users/jeanlescut/dev/agents/agent-vault/install_system.sh --from-layer` | ends with `ok  as <user>: vault status`; `dscl . -list /Users \| grep vault` lists `av-vault` and `lv-vault`; `ls -ld /usr/local/agent-vault /var/agent-vault /var/agent-vault-out`; `/usr/local/agent-vault/bin/vault status \| head -1` shows the same item count as the baseline; the old `vault status` still answers and `ls -l /usr/local/layer-vault/bin/vault` is unchanged |
| 2 | Same key, same mask list (Jean, sudo; prints nothing) | `sudo cmp /var/layer-vault/key /var/agent-vault/key && sudo cmp /var/layer-vault/fingerprints.json /var/agent-vault/fingerprints.json && echo same` | `same` |
| 3 | Install the user part staged: files only, no link, no job | `bash /Users/jeanlescut/dev/agents/agent-vault/install.sh --stage --from-layer` | `ls ~/opt/agent-vault` has `alerts.sh skills`; `readlink ~/.local/bin/vault` still `/usr/local/layer-vault/bin/vault`; `launchctl list \| grep vault` shows only `layer-vault.alerts`; `/Users/jeanlescut/dev/agents/agent-vault/.venv` exists |
| 4 | Stop the old job, then copy the last state (Jean, sudo) | `launchctl bootout gui/$(id -u)/com.jeanlescut.layer-vault.alerts` then `sudo bash /Users/jeanlescut/dev/agents/agent-vault/install_system.sh --from-layer --recopy` | `launchctl list \| grep layer-vault` is empty; the script ends `ok`; step 2's `cmp` again prints `same` |
| 5 | Switch: links, skill, new job | `bash /Users/jeanlescut/dev/agents/agent-vault/install.sh` | `readlink ~/.local/bin/vault ~/.local/bin/vault-admin ~/.claude/skills/vault` all name `agent-vault`; `launchctl list \| grep agent-vault.alerts`; last line `ok  vault status: ...` with the baseline's item count |
| 6 | The hooks still work (they fail closed: a broken `vault` hides every tool output) | `echo '["a plain text"]' \| vault mask; echo $?` then any Bash tool call in a new Claude session | `["a plain text"]` and `0`; the session's tool outputs are readable; `agent-firewall`'s selftest (its own command) is green |
| 7 | The new job runs once | `launchctl kickstart gui/$(id -u)/com.jeanlescut.agent-vault.alerts` | the job-runner status of `agent-vault.alerts` is SUCCESS (not SKIP "agent-vault not installed"); no second Todoist task for an alert already filed (the state file was copied) |
| 8 | Quarantine the old (renames only; Jean for the sudo ones) | `sudo mv /etc/sudoers.d/layer-vault /etc/sudoers.d/layer-vault.quarantine` · `sudo mv /usr/local/layer-vault /usr/local/layer-vault.quarantine` · `mv ~/Library/LaunchAgents/com.jeanlescut.layer-vault.alerts.plist ~/Library/LaunchAgents/com.jeanlescut.layer-vault.alerts.plist.quarantine` · `mv ~/opt/layer-vault ~/opt/layer-vault.quarantine` | `sudo -n -u lv-vault true` fails (sudo ignores a sudoers file with a dot in its name; `sudo visudo -c` is clean); `which vault` still works; `/var/layer-vault*` and the user `lv-vault` are left as they are (data for a rollback) |

After a quiet day (agents logged in with `vault`, no alert task about the vault itself), the old data and the user go with the frozen old uninstaller, `sudo bash /Users/jeanlescut/dev/agent-interfaces/layer-vault/uninstall_system.sh --purge` (Jean's decision, not part of L5), and job-runner's old status `layer-vault.alerts` is retired.

## NAS (task L6): mask only

The NAS has no Bitwarden and no typing: a copy that only masks (`MASK_ONLY`), fed by the Mac. Needs: the repo on GitHub (a separate task) and step 5 done on the Mac. The NAS installs from a temporary clone; there is no `~/dev/agent-vault` there.

| # | Step | Command | Check |
|---|---|---|---|
| 1 | Install system part, copy the NAS's old state (Jean types the NAS sudo password) | `ssh -t babisnas 'd=$(mktemp -d) && git clone git@github.com:JeanLescutMuller/agent-vault.git "$d/agent-vault" && sudo bash "$d/agent-vault/install_system.sh" --from-layer'` | `ls /usr/local/agent-vault/MASK_ONLY`; `/usr/local/agent-vault/bin/vault status` says `mask only` and the item count of `/usr/local/layer-vault/bin/vault status`; `/var/agent-vault-out/import.pub` exists; old `vault status` still answers |
| 2 | Stage the user part | `ssh babisnas 'cd <the clone> && bash install.sh --stage --from-layer'` | `ls ~/opt/agent-vault`; `readlink ~/.local/bin/vault` still the old; `systemctl --user list-timers \| grep vault` only `layer-vault.alerts` |
| 3 | Stop the old timer, copy the last state | `ssh babisnas 'systemctl --user disable --now com.jeanlescut.layer-vault.alerts.timer'` then step 1's command with `--recopy` | no `layer-vault` timer listed; the item count unchanged |
| 4 | Switch | `ssh babisnas 'cd <the clone> && bash install.sh'` | links name `agent-vault`; `systemctl --user list-timers \| grep agent-vault.alerts`; `vault mask` of a plain text exits 0 |
| 5 | Same masks as the Mac (optional, when the Mac's list changed) | on the Mac: `bash /Users/jeanlescut/dev/agents/agent-vault/tools/mask_to_nas.sh` (Mac sudo, then NAS sudo) | ends `ok  the NAS masks the same N items as were sealed here` |
| 6 | Quarantine the old | `ssh -t babisnas 'sudo mv /etc/sudoers.d/layer-vault /etc/sudoers.d/layer-vault.quarantine && sudo mv /usr/local/layer-vault /usr/local/layer-vault.quarantine'` and `ssh babisnas 'for k in service timer; do mv ~/.config/systemd/user/com.jeanlescut.layer-vault.alerts.$k ~/.config/systemd/user/com.jeanlescut.layer-vault.alerts.$k.quarantine; done; mv ~/opt/layer-vault ~/opt/layer-vault.quarantine; systemctl --user daemon-reload'` | `sudo -n -u lv-vault true` fails; `vault status` (new) still answers |

## Rollback (any machine, any point)

| After step | Undo |
|---|---|
| 1-3 (staged) | nothing to undo: the old runs untouched. Optional: `sudo bash /Users/jeanlescut/dev/agents/agent-vault/uninstall_system.sh --purge` |
| 4-7 (switched) | `ln -sfn /usr/local/layer-vault/bin/vault ~/.local/bin/vault`; same for `vault-admin`; `ln -sfn ~/opt/layer-vault/skills/vault ~/.claude/skills/vault`; `launchctl bootout gui/$(id -u)/com.jeanlescut.agent-vault.alerts`; `launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/com.jeanlescut.layer-vault.alerts.plist` (NAS: `systemctl --user enable --now` the old and disable the new timer). What the new side wrote since the switch (suspected secrets, grants, events) is not in the old: copy by hand if it matters |
| 8 (quarantined) | rename each `.quarantine` back (the same `mv`, reversed), then the line above |
