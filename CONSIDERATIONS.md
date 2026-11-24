# agent-vault: rogue agents (out of scope today)

Out of scope since 2026-11-21 (Jean): **any attack by one of Jean's own agents, on this very Mac**: a rogue agent, a fooled one (a prompt injection in a page or a mail), or one that simply goes too far. agent-vault's goal is narrower (`DESIGN.md` §0): no long-lived secret reaches a transcript **by accident**. This file lists what such an agent could do against the design as it stands (`DESIGN.md`, 2026-11-21), and ideas to stop each one, in case Jean ever brings this threat into scope. It states no design choice, on purpose. Nothing here was tried against the real setup; **[assumed]** marks what was not tested.

The attacker below is a process running as Jean's Mac user `jeanlescut`, like every agent: it can read and write all of Jean's files, run any program, use tmux, and call `vault`. It cannot become root or `av-vault` without a password.

## Already closed by the current design

| Hole in the copied password layer (`src/pwlayer.py`) | Closed by |
|---|---|
| Chrome's debugging port `127.0.0.1:9785` open to every local process: read a password field after it was typed [verified 2026-11-21 with `lsof`] | a pipe to Chromium, no port (§9) |
| stop the layer, listen on its TCP port 8785, catch the session key at Jean's next unlock | a socket in a folder only `av-vault` owns; the client checks its owner (§1) |
| change `pwlayer.py`, its `.venv` or `/Applications/Google Chrome.app` (all Jean's), so the next start leaks | root-owned code and Chromium in `/usr/local/agent-vault/` (§1) |
| read the daemon's memory, the `bw` logins, the fingerprint key, the suspected secrets | another Mac user (`av-vault`); macOS lets only root read another user's process memory [assumed] |

## 1. Posing as someone else

- **A lie about the session UUID.** The client sends `$CLAUDE_CODE_SESSION_ID` and the daemon trusts it (§2), so an agent can send a granted session's UUID (UUIDs are in `~/.claude/*/sessions/`, transcripts' paths, `ares`). *Ideas:* check the caller's process ancestry against the granted session's `pid` and `procStart` (parked in `DESIGN.md` §13).
- **A forged session file at grant time.** With the ancestry check, `grant` reads `sessions/<pid>.json` as root; an agent could first write a file that maps the UUID Jean is about to grant to its own pid. *Ideas:* `grant` shows the session's folder, name and start time and asks Jean to confirm; or Jean picks the session from a list of live `claude` processes (their pids from `ps`, not from a file); or grant by tmux pane.
- **A fake agent-vault for other callers.** `~/.local/bin/vault` (Jean's) can be rewritten so other agents, or agent-firewall, talk to a fake that answers `mask` with the text unchanged: masking silently off. *Ideas:* every caller, agent-firewall first, runs the root-owned path `/usr/local/agent-vault/bin/vault`, never a wrapper in Jean's folders; agent-firewall's sudoers already fixes `secure_path`.

## 2. Jean's terminal

- **Catching the master password at unlock.** An agent rewrites Jean's `.zshrc`, adds an alias or a shell function named `vault-admin` or `sudo`, or puts a wrapper earlier in `PATH`; Jean types the master password into it. *Ideas:* Jean runs `/usr/local/agent-vault/bin/vault-admin` by its full path, from a shell started without his startup files (`zsh -f`, or a Terminal profile that does so); or the daemon asks for the password itself, in a window it opens as root (`osascript` from a LaunchDaemon cannot do that simply [assumed]); or unlock with Touch ID once the master password is stored where only root can read it (a change of what the vault's security rests on).
- **Typing into Jean's pane.** `tmux send-keys -t <Jean's pane> 'sudo vault-admin grant …' Enter`: if Jean ran sudo in that pane a few minutes earlier, sudo's ticket (5 minutes by default) lets it through without a password [assumed: not tried, never on Jean's tmux server]. The same with `osascript` keystrokes into Terminal, if an agent's terminal has the Accessibility permission. *Ideas:* `Defaults timestamp_timeout=0` for `vault-admin` in sudoers (a password every time); Touch ID for sudo (`pam_tid.so`): a finger cannot be sent by tmux; run `vault-admin` outside tmux, in a separate Terminal window; agents on their own tmux server (socket) so they cannot reach Jean's panes.
- **Reading Jean's pane.** `tmux capture-pane` shows whatever Jean's terminal printed. A hidden password is never printed, but a `status` or a mistake typed in clear would be. *Ideas:* the same separate tmux server; `vault-admin` clears its own output.
- **A fake prompt.** An agent opens a dialog ("Bitwarden: enter your master password", `osascript display dialog`) or prints a fake `vault-admin` prompt in a pane. *Ideas:* Jean types the master password only into a `vault-admin` he started himself; the real prompt shows a phrase Jean chose at install (an anti-phishing phrase), which no agent can read.
- **Asking Jean nicely.** An agent asks Jean to grant a whole folder for a day, or to run a command "to fix the vault". *Ideas:* `grant` prints a one-line summary (sessions, items, abilities, until) and asks `yes`; a maximum `--for` (8 h); a folder other than "Agent auto-login" needs an extra flag.

## 3. Through the browser, within a grant

A granted agent may type a password on the item's website. Ways to get it out from there:

- **The clipboard.** `browser key <tab> Meta+A`, `Meta+C` in the password field, then `browser open` an attacker's page and `Meta+V` into its form: the attacker's server gets the password. The reply scrub never sees it [assumed: `key` passes modifiers today]. *Ideas:* `key` refuses modifier combinations; the page's init script blocks `copy` and `cut` on a field the daemon filled; Chrome without clipboard access (policy); the field cleared once the form is sent.
- **The wrong field.** `type-password` into a text field on the right website (a search box, a comment box): the password goes into a URL, a public comment, the site's analytics and third-party scripts. *Ideas:* type only into `input[type=password]` (or `autocomplete=current-password` / `new-password`).
- **The right domain, someone else's page.** The website check compares domains; on a domain that hosts users' pages (`sites.google.com`, `*.github.io`, a shop's seller pages), an attacker's page on the same domain gets the typed password. *Ideas:* match the item's exact origins, not the registrable domain; a list of domains that host users' content, where typing is refused.
- **A website added to an item.** `internal add-website <item> https://attacker.example`, then `type-password` there. The copied layer accepts only a domain related to the item (same folder, aliases); the new design says only "a grant on the item". *Ideas:* keep the copied rule; or every new website needs Jean's yes (`vault-admin`).
- **`type-token` anywhere.** A suspected secret has no website, so it can be typed into any page, including an attacker's. *Ideas:* `mask` records the sender's domain with each suspected secret; `type-token` only there.
- **Seeing it drawn.** Click the "show password" eye, or make the page draw the value in a canvas or an image, then `browser shot`: the refusal looks at page text, not pixels [assumed]. *Ideas:* no screenshot on a tab after a password was typed, until it leaves the page; fields the daemon filled masked by CSS (done today) and checked again just before the shot.
- **Files.** `browser download` saves a page's file (recovery codes, an export of the account); a rogue agent opens it. *Ideas:* downloads go to a folder only Jean reads, and the agent gets only the file's name and size.
- **Old or other items.** `internal same` answers yes/no between two items: a slow oracle, harmless alone. `internal delete` sends items to the trash (30 days to restore): damage, not a leak. *Ideas:* `delete` asks Jean (`vault-admin`).

## 4. Guessing through `mask`

`mask` says whether a text holds a vault secret. Card and AHV numbers have ~10^9 possible values, Swiss IBANs ~10^12: an agent sending every valid number finds Jean's in hours (cards, AHV) or weeks (IBANs) [estimate, 2026-11-21: ~10^5 checks per second]. Random passwords (10^19 values and more) cannot be guessed this way. *Ideas* (designed once, then dropped, `DESIGN.md` "Superseded decisions"): a daily budget on valid-looking card, AHV and IBAN numbers only (1,000 a day → 10^9 guesses take ~2,700 years), counted inside `mask` so no caller can avoid it; used up → every answer says "secret" and one alert task. Measure the real count of such numbers in a month of mail first, then set the budget at ~10× the busiest day.

## 5. Turning the checks off

- **Claude Code's hooks** (`~/.claude/settings.json`, Jean's file) are where agent-firewall's outgoing check is wired; an agent can remove them. *Ideas:* the hooks in Claude Code's managed settings (`/Library/Application Support/ClaudeCode/managed-settings.json`, root-owned), which a user's settings cannot override.
- **Flooding the daemon.** Many calls at once make `mask` slow; agent-firewall then fails closed and blocks all mail (a denial of service, no leak). *Ideas:* a per-caller limit on calls in flight.
- **Calling agent-firewall as a client it is not.** agent-firewall's clients are named by the caller (`--client jean`), and some get login codes (out of scope: codes expire). *Ideas:* in agent-firewall, `code` allowed to `av-vault` only (its sudoers).

## 6. Outside agent-vault

Secrets agent-vault does not hold, so its design cannot protect them: Chrome's `Default` profile (Jean's password vault, off-limits by rule only), the macOS Keychain, every `~/.config/<tool>/secrets.env`, the `gws` and Claude logins. A rogue agent reads them directly. *Ideas:* each moves behind a Mac user of its own, as agent-firewall did for the mail logins (`/Users/jeanlescut/dev/agents/agent-firewall/DESIGN.md` E1), or into the vault, used only through agent-vault.

## If this ever comes into scope: what closes the most for the least

| Step | Closes | Cost |
|---|---|---|
| Touch ID for sudo, `timestamp_timeout=0` for `vault-admin`, `vault-admin` outside tmux | §2: typing into Jean's pane, sudo tickets | a sudoers line, a PAM line |
| `key` without modifiers; copy and cut blocked on filled fields; `type-password` only into password fields | §3: the clipboard, the wrong field | a few lines in the browser code |
| callers use `/usr/local/agent-vault/bin/vault` | §1: a fake agent-vault | one path in agent-firewall |
| the caller's process ancestry checked against the grant | §1: lying about the session | parked design, `DESIGN.md` §13 |
| the budget inside `mask` | §4: guessing cards, AHV, IBAN | the dropped design, back |
| exact origins; `add-website` and `delete` through Jean; `type-token` bound to the sender's domain | §3: other pages, other websites | moderate |
| managed settings for the hooks | §5: turning the checks off | a root-owned file |
