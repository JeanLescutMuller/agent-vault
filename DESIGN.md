# agent-vault: design (version 2)

What we build and why. Requirements: `REQUIREMENTS.md` (P1–P6, R1–R13). Words: `AGENTS.md` "Vocabulary". Version 2, Jean 2026-11-21: no browser of its own, no daemon; agents browse with Claude in Chrome, and two hooks on every tool call (owned by agent-firewall) keep secrets out of what an agent is aware of. Version 1 (a daemon with its own Chromium): commit `4be3f51`, its design in that commit's `DESIGN.md`. Status: built and tested in the sandbox, end to end (§11, 2026-11-21), not installed.

| | |
|---|---|
| Commands | `vault` (agents; `mask`, `save-token`: anyone, no grant), `vault-admin` (Jean) |
| Runs as | production: the hidden Mac user `av-vault`, through `sudo -n -u av-vault` (one sudoers line, as agent-firewall); sandbox: Jean's user, `AV_HOME` a sandbox folder |
| Reads | the vault (`bw`, one login per Bitwarden account); the open tabs recorded by chrome-gateways (`~/opt/chrome-gateways/state/open.json`) |
| Writes | the vault (folder "Agent auto-login" only); `AV_HOME` (700): the Bitwarden session, key, fingerprints, suspected secrets, grants, events; `AV_OUT`: alerts |
| Acts | types a password into the agent's Chrome tab (Apple Events, §8) |
| Called by | agent-firewall's two hooks (`vault mask`, `vault mask --out`), agents, Jean |

## 0. The goal, and what is out of scope

**No long-lived secret ever reaches what an agent is aware of** (its transcript, on the Mac and on Anthropic's servers). Out of scope (`REQUIREMENTS.md`): temporary secrets, rogue agents, screenshots, files already on the Mac, Jean's own prompts, the Claude in Chrome relay's transit.

## 1. The picture

```
                       ┌──────────────── Claude Code session ────────────────┐
 Jean ── prompt ──────►│ model ◄── tool output ── INGRESS hook (after .*) ◄──┐ │
                       │   │                       vault mask → tokens       │ │
                       │   └─ tool call ─► EGRESS hook (before .*) ─► tool ──┘ │
                       │                   firewall check + vault mask --out   │
                       └──────────────────────────────────────────────────────┘
 tools: Bash, Read, WebFetch, every MCP (Claude in Chrome, WhatsApp, Outlook…), subagents
 vault type-password <tab> ─► Apple Events ─► the agent's Chrome tab ─► password field of the item's own website
```

**End to end, one login (the mockup the sandbox plays, §11):**

```
Jean      sudo vault-admin grant <session> site:shop.test --for 2h --can login
agent     Claude in Chrome: navigate tab 123 → https://shop.test/login
          page text: "Your old password was Kq7…" ─► ingress hook ─► "Your old password was <vault-secret 1a2b3c4d>"
agent     vault type-username 123            ─► "username typed: me@example.com"
agent     vault type-password 123            ─► vault: grant? tab 123 is this session's? page on shop.test = the item's site?
                                                 field is input[type=password]? ─► Apple Events fill it ─► "typed (20 chars)"
agent     Claude in Chrome: click "Log in"   ─► egress hook: nothing leaves but a click
agent     javascript_tool: pw.value          ─► ingress hook ─► "<vault-secret 1a2b3c4d>"
Jean      the transcript (local and remote): no password, anywhere
```

## 2. The two hooks (agent-firewall's; what they ask agent-vault)

| Hook | When | Asks agent-vault | On error |
|---|---|---|---|
| ingress | after every tool (`PostToolUse`, matcher `.*`) | `vault mask`: every string of the tool's output, each long-lived secret → a token | **fails closed**: the output becomes `[hidden: the secret check failed]` |
| egress | before every tool (`PreToolUse`, matcher `.*`) | `vault mask --out`: every string of the tool's input; a vault secret → deny + an alert task (R11) | the firewall's rule (logged, the call goes on) |

Claude Code applies the ingress rewrite (`updatedToolOutput`) before the model sees the output and before the transcript is written, for every tool, MCP tools and Claude in Chrome included [verified 2026-11-21, Claude Code 2.1.330: 0 copies of the test password in the transcript]. A hook in Jean's own `~/.claude/settings.json` may rewrite an output unless `CLAUDE_CODE_RESTRICT_PERSONAL_CONFIG` is set [read in the code, 2.1.330].

## 3. The commands

`<tab>` = the Claude in Chrome tab id (from `tabs_context_mcp`) · `<item>` = a Bitwarden id prefix or an item's exact name.

| Command | What | Grant |
|---|---|---|
| `vault type-username <tab> [--item <item>]` | the item's username into the page's username field (shown: no secret) | `login` |
| `vault type-password <tab> [--item <item>] [--nth N]` | the item's password into the Nth password field (default 1) | `login` |
| `vault type-new-password <tab> --username <login> [--length 20] [--no-symbols]` | a random password, saved in the vault, then typed into every empty password field (new + confirm) | `new-password` |
| `vault type-token <tab> <token> [--nth N]` | a `<suspected-secret …>` into a password field | `login` |
| `vault save-token <token> --site <domain> [--username <login>]` | a suspected secret becomes a vault item (now if unlocked, else at the next unlock) | none |
| `vault mask [--out]` | JSON list of texts on stdin → the same list with tokens; exit 3 when anything was masked | none |
| `vault list` · `find <text>` · `show <item>` | the granted items' details, never a secret | any live grant |
| `vault rename · set-username · add-website · delete <item> …` | tidy an item (R5) | on the item |
| `vault status` | locked or not, the caller's grants | none |
| `vault-admin unlock` · `lock` · `sync` · `status` | Jean: master password; fingerprints refreshed | – |
| `sudo vault-admin grant <session> <item>… \| site:<domain> \| folder:"<name>" --for 2h --can login,new-password` · `grant --any-session site:<domain> --forever --can login` · `revoke <session> \| --any-session [site:<domain>] \| --all` | Jean only (root) | – |

The caller's session is `$CLAUDE_CODE_SESSION_ID` (trusted: rogue agents are out of scope). A refusal names the missing grant, so the agent can tell Jean.

**Removed from version 1:** the daemon and its socket, `vault browser …` (open, look, click, fill, shot, download, done: Claude in Chrome does it), `vault email …` (agents read mail through agent-firewall; codes are shown in clear), the reply scrub and the screenshot refusal (the ingress hook masks every tool output), Playwright and its Chromium.

## 4. Runs as, and where

Production: `/usr/local/agent-vault/bin/vault` (root-owned) runs `sudo -n -u av-vault /usr/local/agent-vault/bin/vault-run …`, one sudoers line, as agent-firewall does; `AV_HOME=/var/agent-vault` (700), `AV_OUT=/var/agent-vault-out` (750, group staff: alerts). **Why another user, still:** an agent grepping `~/.config` by mistake must find no fingerprint key and no Bitwarden session (§0: accidents). Cost: sudo's start-up on each hook call, to measure (§11).

Sandbox: the same code as Jean's user, every path from the environment (`AV_HOME`, `AV_OUT`, `AV_BW` = the fake `bw`, `AV_CHROME_STATE` = the Chrome kit's state folder).

## 5. Unlock, lock

`vault-admin unlock` asks the master password (hidden input; on stdin when not a terminal, for the tests) and gives it to `bw unlock --raw --passwordfile` through a named pipe in `AV_HOME` (never an argument or the environment). The session key goes to `AV_HOME/session` (600, only `av-vault` reads it in production), then the fingerprints are refreshed (§7) and pending `save-token`s are written. **The vault then stays unlocked** until Jean runs `vault-admin lock` (`bw lock`, the session file deleted). Jean, 2026-11-21: "Why can't we have the vault being completely continuously unlocked?"; the lock at the last grant is gone, and the grants alone decide who may use an item (`/Users/jeanlescut/dev/agent-interfaces/DESIGN.md` §12.1, §12.2).

**`vault reveal <token> --temporary --why "…"`** (Jean, 2026-11-21): a suspected secret the agent is sure is temporary is printed once, shown in clear by every later mask, never saved (`save-token` refuses it), and reported by `mask --out` as `revealed:<id>` so the outgoing hook sends it back to its source only (`AV_HOME/revealed.json`). A saved token is never revealed.

## 6. Grants

Unchanged from version 1: `AV_HOME/grants.json` [{ts, dt, session, targets, can, until_ts}]; targets: items, `site:<domain>` (an account not yet in the vault), `folder:"<name>"`; abilities `login`, `new-password`. `grant` and `revoke` only from root (production: the caller's uid; sandbox: `AV_ADMIN_OK=1`).

**Standing grant** (Jean, 2026-11-24: "any Claude session can log in to my Oxylabs dashboard on its own, with no expiry"): `sudo vault-admin grant --any-session site:<domain> --forever --can login` stores `session: "*"`, `until_ts: null`. It applies to every session (`vault list`, `vault status`, `vault-admin status` show it as "any session, forever"), and is ended only by `sudo vault-admin revoke --any-session [site:<domain>]` or `--all` (`revoke <session>` keeps it).

| Limit | Why |
|---|---|
| exactly one `site:<domain>` target: no item, no `folder:` | a standing grant stays one website |
| ability `login` only: no `new-password` | no account made, no item written, by any session |
| `--forever` only with `--any-session` | a session's own grant still takes `--for` |
| `type-token` on another website still needs the session's own grant | a standing grant never opens other sites |

Every other check is unchanged: the tab is this session's own Claude in Chrome tab, the page is on the item's site, look-alikes refused (§8). Tests: `test/test_vault.py` V23–V26.

## 7. Fingerprints and `mask`

Unchanged from version 1 (`src/agent_vault/masking.py`): every long-lived secret of every item (passwords and their history, TOTP keys, hidden fields, private keys, card numbers, identity numbers, IBANs) kept as keyed BLAKE2b fingerprints of its 12-character pieces (8–11 characters: whole); `mask` slides windows over each text's forms (compact, look-alikes folded, reversed, decoded Base64 / hex / URL runs) → `<vault-secret <item id>>`; a value that looks like a password and is not in the vault (after "password:", or mixed letters, digits and symbols) → `<suspected-secret <random id>>`, its value stored encrypted in `AV_HOME/suspected/` for good. `mask --out`: vault secrets only; a hit → one alert line in `AV_OUT/alerts.jsonl` (the job turns it into a Todoist task). Speed [measured 2026-11-21]: 20 KB in 0.06 s, 2 KB in 6 ms.

## 8. Typing into the agent's tab (serves R1–R3)

Chrome lets an outside program into a page only through Apple Events (`execute javascript`, with Chrome's "Allow JavaScript from Apple Events" turned on by Jean in the agent profiles; his own profile keeps it off, so nothing can run there), or through an extension. **Choice: Apple Events, from JavaScript for Automation**: nothing new runs inside Chrome. **Rejected:** a Claude in Chrome tool (the value would be in the tool's input, so in the transcript); Chrome's remote control (refused on the profiles' data folder since Chrome 136); keystrokes (Chrome would have to come to the front); `tell application "Google Chrome"` by name (it reached a Chrome a script had started, with no window [sandbox, 2026-11-21]).

```
vault type-password <tab>
  1 grant: a live grant of this session covers the item, ability login (§6)
  2 tab:   <tab> is in the Chrome kit's open.json, opened by this very session (never Jean's own tabs)
  3 Chrome: the main Chrome by its process ID (started without --user-data-dir; exactly one, else refused)
  4 page:  the tab by its id (the same number as Claude in Chrome's tab id [verified 2026-11-21]); its address's registrable
           domain is one of the item's websites
  5 type:  one script on osascript's stdin (never an argument) runs in that tab: the page's domain checked again inside the
           page; the Nth visible input[type=password]; value set through the native setter, then input and change events
           (React, Vue): "ok" | "no field" | "wrong site" | "mismatch"
  6 reply: "typed into 1 password field(s) (16 chars)": never the value; an event in AV_HOME/events.jsonl
```

**Limits:** the main frame only (a login inside a frame from another site: "no field"; then the fallback is a feature of Jean's existing extension "Agent tab notes", through its native host); a password already typed stays readable by a page script (`javascript_tool` … `.value`): the ingress hook turns it into its token [verified 2026-11-21].

## 9. Parked features (no use case now)

`type-card`, `type-field` (a hidden field, an identity number), `type-totp`; the caller's process checked against the granted session (rogue agents).

## 10. Layout

```
agent-vault/
  REQUIREMENTS.md  DESIGN.md  AGENTS.md  CONSIDERATIONS.md  README.md
  bin/vault  bin/vault-admin
  src/agent_vault/
    cli.py         vault, vault-admin: grants, unlock, lock, the item commands, mask, save-token (§3, §5)
    chrome.py      the tab check and the script that types, through Apple Events (§8)
    bitwarden.py   bw; masking.py (§7); grants.py (§6); scrub.py; common.py; leak_scan.py
  test/          the vault's own tests (fake bw, no sudo, no Chrome): run_all.sh
  doc/           switch_from_layer.md
  (the tests of the vault together with the hooks: agent-firewall's sandbox, which reads this repo at AV_REPO)
```

## 11. The sandbox, and what it proves

The vault's own tests are in `test/` (V01-V26, N05, N06, N10; `bash test/run_all.sh`). The tests of the vault together with the two hooks (battle, end to end) are agent-firewall's sandbox (`/Users/jeanlescut/dev/agents/agent-firewall/sandbox/`), which finds this repo through `AV_REPO` (Jean, 2026-11-23: agent-interfaces split in three). As first measured here: everything runs from the repos with a fake vault; nothing on the Mac changes (no sudo, no `~/.claude/settings.json`: the test sessions get the hooks through `claude --settings <sandbox>/settings.json`).

| Test | Proves | Result (2026-11-21) |
|---|---|---|
| `test/test_v2.py` (no Claude, ~30 s) | every command, grant and refusal; mask (password, card, IBAN, base64, suspected); the ingress hook on recorded tool calls (masked, injection hidden, request for a secret, a form's labels left alone, a code kept, fails closed, a screenshot untouched, a local file not screened); the egress hook (a vault secret, a kept code, a code after a request for a secret, data in a page address, Jean's phone asked, then denied after a request for a secret, a page script sending data) | 46 checks ok, no leak; a hook call 137 ms (median of 7) |
| `test/e2e/run.py tools` (a Claude session, ~1 min) | a fake WhatsApp MCP server (an injection, a request for a password), a reply with Jean's phone after it, a subagent reading a file with a vault password | injection hidden, the reply denied, the password a token in the main and the subagent transcript: 0 copies |
| `test/e2e/run.py chrome` (a Claude session with Claude in Chrome, profile "Claude - Account B", ~2.5 min) | the login of §1 (`type-username`, `type-password`, the site checks them), a new password on a signup page (saved, typed twice), `javascript_tool` reading the field, a page showing two passwords, an injection page, a page asking for the password, a page address carrying data | login ok and account created (the site's own check), the field read as its token, both passwords on the page as tokens, injection hidden, request obfuscated, the address refused: 0 copies of any of the 5 passwords in the transcript |
| agent-firewall `bash test/run.sh quick` | its own 694 attack and leak cases, unchanged | 0 fails |

## 12. Build order

| Step | What | Touches the Mac? |
|---|---|---|
| 1 | these files; the code on branch `v2-hooks` in both repos | no |
| 2 | sandbox tests all green; times measured | no |
| 3 | Jean reviews; install: `av-vault` and its sudoers line, `install_system.sh` | yes, Jean |
| 4 | the hooks in `~/.claude/settings.json` (agent-firewall's `install.sh`), dry run a few days, then enforce | yes, Jean |
| 5 | the migration's prompts move from `pwl page/login` to Claude in Chrome + `vault type-*` | other repo |

## The mask-only copy (the NAS, task D5; built 2026-11-22, not installed)

On Linux `install_system.sh` makes a copy that only masks (the file `MASK_ONLY` beside `src/`): `vault mask`, `reveal`, `status`, `vault-admin mask-key | import-mask | file-alerts`; Bitwarden, grants and typing are refused (typing stays on the Mac: Apple Events). The fingerprints and their key come from the Mac, sealed for the NAS's av-vault (`src/agent_vault/bundle.py`: X25519, HKDF-SHA256, AES-256-GCM): `bash tools/mask_to_nas.sh [--leave-out card,iban,ahv]` on the Mac: root seals them inside the root-owned code (`bundle.seal_from`; the key never in a process of Jean's user), sudo on the NAS imports them, and the NAS's item count is compared with the sealed one. The first import drops the suspected secrets the NAS kept under its own first key (they could no longer be read). A copy: secrets added on the Mac are masked on the NAS after the next run. Tests: `sandbox/unit/test_nas.py` N05, N06, N10.

