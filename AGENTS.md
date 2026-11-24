# agent-vault

The only thing that can access Jean's Bitwarden and do things with it, for agents, so that no long-lived secret ever reaches an agent's transcript: "making sure a clear password never appears in an agent transcript" (Jean, 2026-11-21). Development home: Mac. Read by agent-firewall's sandbox at `AV_REPO` (its tests of the vault with the two hooks load this repo's `bin/` and `src/`; never move them without telling agent-firewall).

Stage (2026-11-23): **version 2, own repo since the split of agent-interfaces (names layer-vault, lv-vault, LV_* became agent-vault, av-vault, AV_*; switch: `doc/switch_from_layer.md`), installed by its own `install_system.sh` and `install.sh`**: the commands are root-owned in `/usr/local/agent-vault/` and run as the Mac user `av-vault` (`bin/vault-run`, its sudoers line); the one step that needs Jean's login session, the Apple Events into his Chrome and the Chrome kit's tab record, runs as his user through `bin/vault-type`. Agents browse with Claude in Chrome and log in with skill `vault`; agent-firewall's two hooks call `vault mask` on every tool call. The old password layer (pwlayer) is retired (stopped 2026-11-21); version 1 (a daemon with its own Chromium): commit `4be3f51`.

## Rules

- **No long-lived secret ever reaches what an agent is aware of** (a password, a card, AHV or IBAN number, an API key, a private key): not a reply, a log, a file, an argument, an environment variable. Login codes and reset links may pass: they expire (Jean, 2026-11-21) → `DESIGN.md` §0.
- **Only agent-vault runs `bw`**; no agent runs it or reads agent-vault's folders (Jean's global rule; this project is its one exception).
- **A password in Bitwarden is never changed** (Jean, 2026-11-11): a site that refuses it is left to Jean.
- **Unlock and grants are Jean's**: `vault-admin unlock` asks the master password; `sudo vault-admin grant` needs his sudo. No agent runs either → §5, §6.
- **A value travels only on stdin** (bw, osascript), never in an argument or the environment; a reply never holds a value, and every reply passes `MASK.mask` as the second net → §3, §8.
- **The incoming hook fails closed**: any error hides the tool's output; never change that → agent-firewall `DESIGN.md` §6.
- **The vault stays unlocked** until Jean locks it; a grant is the only gate to typing an item's secret; `vault reveal` only for a secret the agent is sure is temporary → §5.
- Tests use a fake `bw` (a JSON file); the one test on Jean's real vault reads and writes folder "Agent sandbox test" only (`AV_ONLY_FOLDER`, `AV_FOLDER`), and Jean types his logins himself; the vault's own tests are in `test/`; the tests with the hooks are agent-firewall's sandbox (`/Users/jeanlescut/dev/agents/agent-firewall/sandbox/`). Never run `vault-admin sync` or a leak scan on the real vault: Jean does.
- Parked features (card numbers, hidden fields, TOTP) are not built without Jean's yes → §9.
- Never run `install_system.sh`, `uninstall_system.sh` or anything with sudo: Jean does. `install.sh` (no sudo) is the agents' to run after a commit.

## Test and install

| What | Command |
|---|---|
| the vault's own tests (fake `bw`, no sudo, no Chrome) | `bash /Users/jeanlescut/dev/agents/agent-vault/test/run_all.sh [vault\|nas\|static]` |
| the tests with agent-firewall's hooks (unit, battle, end to end) | agent-firewall's `sandbox/run_all.sh` (reads this repo at `AV_REPO`) |
| the dev venv | `/Users/jeanlescut/dev/agents/agent-vault/.venv` (`uv sync --locked` from `pyproject.toml` + `uv.lock`; `install.sh` makes it on the Mac) |
| install (Jean: the sudo part; then his user) | `sudo bash /Users/jeanlescut/dev/agents/agent-vault/install_system.sh [--from-layer]` · `bash /Users/jeanlescut/dev/agents/agent-vault/install.sh [--stage]` (`--stage`: side by side with the old layer-vault, no link, no job) |
| the switch from layer-vault (L5 Mac, L6 NAS) | `doc/switch_from_layer.md` |

## Vocabulary

| Word | Means | Never say |
|---|---|---|
| **agent-vault** | this project: its two commands and its Mac user `av-vault` | password layer, pwlayer, secret layer, secret-guard, agent-bitwarden |
| **layer-vault** | the old name (before 2026-11-23), replaced on 2026-11-23 (projects restructure); it was installed at `/usr/local/layer-vault`, `/var/layer-vault*`, user `lv-vault`; named only in `install_system.sh --from-layer` and `doc/switch_from_layer.md` | |
| **the vault** | Jean's Bitwarden, every folder, every Bitwarden account | the store, the DB |
| **item** | one Bitwarden item (login, card, note, identity) | entry, record |
| **`vault`** | the agents' command: `type-username`, `type-password`, `type-new-password`, `type-token`, `save-token`, `mask`, the item commands (`DESIGN.md` §3) | pwl, `vault browser`, `vault internal` (version 1) |
| **`vault-admin`** | Jean's command: unlock, sync, lock, grant, revoke, leak-scan | |
| **grant** | Jean's permission for one Claude session: some items or a whole folder, for a time, with abilities (`--can login,new-password`) | token, lease, scope |
| **tab** | a Claude in Chrome tab, by its tab id; the Chrome kit records which session opened it | site key |
| **unlock** | Jean gives agent-vault a Bitwarden session with his master password | |
| **sync** | the fingerprints of every vault secret refreshed, then the vault locked | register, import |
| **fingerprint** | a keyed one-way hash (BLAKE2b) of a secret or a piece of one | hash (alone) |
| **long-lived secret** | a password, a card, AHV or IBAN number, a TOTP setup key, a private key: still valid months later | |
| **mask** | `vault mask [--out]`: a text in, the same text out with each long-lived secret replaced by a token; exit 3 when anything was masked | redact, filter, check-no-secrets |
| **token** | what replaces a secret: `<vault-secret <item id>>` (a vault item) or `<suspected-secret <random id>>` (looks like a password, not in the vault, stored by agent-vault) | placeholder |
| **alert task** | the Todoist task agent-vault files when `vault mask --out` finds a vault secret in a text leaving: the item to change, never the value | |
| **agent-firewall** | Jean's firewall for every message and web call in or out (`/Users/jeanlescut/dev/agents/agent-firewall`); owns the two hooks | gateway, communication-gateway |
| **incoming hook** / **outgoing hook** | agent-firewall's hook after every tool (masks, obfuscates) / before every tool (checks what leaves) | ingress, egress (Jean, 2026-11-21), proxy, filter |

## Where to look

| What | Where |
|---|---|
| what Jean gets | `REQUIREMENTS.md` |
| what we build and why | `DESIGN.md` |
| rogue agents (out of scope): threats and ideas | `CONSIDERATIONS.md` |
| the code | `src/agent_vault/`: `cli.py` (`vault`, `vault-admin`), `chrome.py` (typing into the tab), `masking.py`, `grants.py`, `bitwarden.py`, `scrub.py`, `leak_scan.py`; `bin/`; `src/alerts.sh` (the job) |
| the tests of the vault alone | `test/` (`harness.py`, `test_vault.py` V01-V22, `test_mask_only.py` N05 N06 N10, `test_install_static.py` S01-S04) |
| the whole design across the three repos, the sandbox with the hooks | `/Users/jeanlescut/dev/agents/agent-firewall/` (`doc/agent-interfaces/DESIGN.md`, `sandbox/`) |
| the hooks | `/Users/jeanlescut/dev/agents/agent-firewall/hooks/hook.py` `src/agent_firewall/tool_screen.py` |
| the check's origin | `/Users/jeanlescut/dev/agents/agent-firewall/doc/prompt_*_vault_check_2026-11-21.md` (named layer_vault before the rename)` |
