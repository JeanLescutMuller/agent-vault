---
name: vault
description: Log in to a website, create an account's password, or use a password Jean keeps in Bitwarden, without ever seeing it - agent-vault's `vault` command types the username and password into the agent's Claude in Chrome tab (Apple Events), makes and saves new passwords, and turns the `<vault-secret …>` and `<suspected-secret …>` tokens agents see into typing, saving or (temporary only) revealing. Use before any login, sign-up, password field, password reset, or when a tool output shows a `<vault-secret …>` or `<suspected-secret …>` token. Never `bw`, never a password in chat, never form_input for a password.
---

# vault: logins without seeing a password

Before a login, decide how to get into the account: skill `site-access` (an API? one of Jean's real accounts? a kept session?); this skill is the how of a password login.

agent-vault (`/Users/jeanlescut/dev/agents/agent-vault`) is the only thing that reads Jean's Bitwarden. It runs as its own Mac user (`av-vault`); agents call `vault`, which checks Jean's grant, the tab and the website, then types into the page. No password ever reaches a transcript: agent-firewall's incoming hook replaces every one in every tool output by a token.

## Rules

- **Never** run `bw`, read `/var/agent-vault`, ask Jean for a password in chat, or type a password with `form_input`, `computer` or JavaScript. A password field is filled only by `vault type-*`.
- **A token is not a password**: `<vault-secret a1b2c3d4>` is a Bitwarden item (its id prefix); `<suspected-secret 9f3e…>` looks like a password a page or a mail showed, kept by agent-vault. Never try to guess or decode one.
- **A refusal is a rule**: wrong site, look-alike site, a password asked in a clear text field, a field turned clear, a frame from another website, no grant. Stop on that site and tell Jean; agent-vault already filed an alert task when it was a risk. Never work around it.
- **A password in Bitwarden is never changed** (Jean, 2026-11-11): a site that refuses it is left to Jean.

## 1. The grant (Jean's)

`vault list` shows the items this session may use. `no grant` → ask Jean (interactive), or file a task (a job), for:

```
sudo vault-admin grant <this session: $CLAUDE_CODE_SESSION_ID> site:<domain> --for 2h --can login          # one website
sudo vault-admin grant <session> 'folder:Agent auto-login' --for 8h --can login,new-password             # every agent login
```

A **standing grant** (`any session, forever` in `vault list`): Jean lets every session log in to one website, with no expiry (`sudo vault-admin grant --any-session site:<domain> --forever --can login`). It covers `login` on that website only: a new password, another website or another item still needs a grant of this session's own; the tab and website checks are the same.

## 2. The tab

Claude in Chrome only, per skill `chrome`: `agent-chrome authorize-tab …`, `select_browser` (this account's agent profile), `tabs_context_mcp createIfEmpty` → TAB (the number). The profile needs Chrome's **View → Developer → Allow JavaScript from Apple Events** (Jean, once per profile); `vault` says so when it is off.

## 3. Commands

| To | Run (TAB = the Claude in Chrome tab id) |
|---|---|
| log in | navigate TAB to the login page; `vault type-username TAB`; `vault type-password TAB`; click the button with Claude in Chrome; read the page |
| two items for one website | the refusal names them: add `--item <id>` |
| a form with several password fields | `--nth 2` (the second one) |
| sign up (a new password) | `vault type-new-password TAB --username <login>`: made, saved in folder "Agent auto-login", typed in every empty password field (new + confirm); type the login yourself with `form_input` |
| a site's temporary password from a mail or a page (`<suspected-secret …>`) | `vault type-token TAB <token>` |
| keep a suspected secret as a vault item | `vault save-token <token> --site <domain> --username <login>` |
| a suspected secret you are **sure** expires soon (a one-time code shaped like a password) | `vault reveal <token> --temporary --why "<why it expires>"`: shown in clear; never saved afterwards |
| the item's details (never a secret) | `vault find <text>` · `vault show <item>` |
| rename, username, another address of the same website, trash | `vault rename|set-username|add-website|delete <item> …` |

A login code (4-8 digits) stays readable in tool outputs; type it back only into the site that sent it (the outgoing hook refuses it anywhere else).

## 4. What Jean does, once

`sudo bash /Users/jeanlescut/dev/agents/agent-vault/install_system.sh` (the system part), `bash /Users/jeanlescut/dev/agents/agent-vault/install.sh`, then `vault-admin unlock` (his master password). The vault stays unlocked until he runs `vault-admin lock`; grants are the only gate.
