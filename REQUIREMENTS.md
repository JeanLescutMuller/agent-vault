# agent-vault: requirements

From Jean's point of view only: the benefit, never the mechanism (that is `DESIGN.md`). Words: `AGENTS.md` "Vocabulary". Version 2 (Jean, 2026-11-21): agents browse with Claude in Chrome; agent-vault has no browser of its own (Jean: "I'm really not a fan of this separate chrome browser that complexify everything"). The version with its own browser: commit `4be3f51`.

## Goal (Jean, 2026-11-21)

"This layer should be the only thing that can access my Bitwarden, and do things with it." "The layer should not provide any kind of password to the agent, and making sure a clear password never appears in an agent transcript."

Made precise the same day: what matters is **what an agent is aware of**: "no matter what, the transcript will be written on my computer, and we don't want those transcripts to contain secrets written in clear text." A transcript is the conversation an agent sees: kept on the Mac and on Anthropic's servers. A **long-lived secret** is a password, a card, AHV or IBAN number, an API key, a private key: anything still valid months later.

## The protections, with agent-firewall (Jean, 2026-11-21)

The two projects share this list; the last column says which one owns each line.

| # | Direction | Protection | Owner |
|---|---|---|---|
| P1 | in | a prompt injection (a page, a mail, any tool's output) is obfuscated or blocked, and the agent is told why | agent-firewall |
| P2 | in | a stranger asking for a secret without good reason is flagged; personal facts sent back to that conversation are denied | agent-firewall |
| P3 | in | **no long-lived secret ever reaches an agent's transcript**: one shown on a page, in a mail, in any tool's output is replaced by a token before the agent sees it | **agent-vault** (the check), agent-firewall (calls it on every tool output) |
| P4 | out | secrets and personal facts never go to a recipient without good reason | agent-firewall (asks agent-vault about secrets) |
| P5 | out | data hidden in a link or a URL is stopped | agent-firewall |
| P6 | out | a temporary secret (a login code, a reset link) is never sent to a stranger | agent-firewall |

## What agents can do for Jean (agent-vault's part)

| # | Requirement |
|---|---|
| R1 | An agent logs in to a website with the vault's username and password, without ever seeing the password; the password goes only into a password field of a page on the item's own website. |
| R2 | An agent gives an account a new password when it is unknown, lost, or only in clear text somewhere; the new password is in the vault before it is typed. A password already in the vault is never changed (Jean, 2026-11-11). |
| R3 | An agent reuses a password it only saw as a token (a site's generated password in a mail): typed into a page, or saved to the vault for a website, without ever seeing it. |
| R4 | An agent sees an item's details (folder, username, websites, when its password changed), never a password, a note or a secret field. |
| R5 | An agent tidies an item: rename it, set its username, add an address of a website it already has, send it to Bitwarden's trash (never deleted for good). |
| R6 | Agents keep doing everything else as today: browse with Claude in Chrome, read and send mail and messages through agent-firewall (Jean, 2026-11-21: "Agents can still log in (if authorized), or create password (if authorized), browse online, read emails, send emails, communicate"). |

## What Jean controls

| # | Requirement |
|---|---|
| R7 | Jean unlocks the vault with his Bitwarden master password, in his own terminal; nothing else can unlock it. |
| R8 | Jean grants one Claude session the use of some items, a website or a whole folder, for a time, for some abilities (log in, new password). Outside a live grant, logging in and new passwords are refused. |
| R9 | Jean sees who holds which grant, and ends one at any time. The vault locks itself when the last grant ends. |
| R10 | Jean refreshes, with one command, agent-vault's knowledge of every secret in the vault (every folder, every Bitwarden account); it prints counts only. |
| R11 | A vault secret found in a text leaving (P4) is a red flag: the text is blocked, and Jean gets an alert task naming the item to change, never the value. |

## Out of scope (Jean, 2026-11-21)

| What | Why |
|---|---|
| temporary secrets (login codes, reset links, one-time passwords) reaching a transcript | they expire; they still never go to a stranger (P6) |
| a rogue agent on this Mac attacking Jean | Jean's agents are not rogue; a **fooled** agent (a prompt injection) stays in scope: P1, P2, P4–P6 exist for it. Ideas for later: `CONSIDERATIONS.md` |
| screenshots | a password is typed only into a password field, which shows dots; a page showing a secret in clear in a screenshot is accepted |
| every file already on the Mac: CLAUDE.md, skills, `@` attachments, downloads, logs | files are assumed to hold no secret an agent reads |
| a password Jean pastes into his own prompt | his own choice |
| page text passing through Anthropic's Claude in Chrome relay (`bridge.claudeusercontent.com`) before the hook masks it | not a transcript (measured 2026-11-21: the relay carries page text in clear; the hook cleans it before the model and the local transcript) |
| card numbers, hidden fields, identity numbers or TOTP codes typed into pages | no use case now; parked (`DESIGN.md` §9) |
| Jean's personal facts (address, phone) | agent-firewall's |

## Secondary (later)

| # | Requirement |
|---|---|
| R12 | A second Bitwarden account (the banks) is covered like the first. |
| R13 | A monthly reminder to refresh agent-vault's knowledge of the vault (R10). |

## Decided questions

| Question | Answer |
|---|---|
| agent-vault's own browser? | no: Claude in Chrome, and a hook on every tool output (Jean, 2026-11-21) |
| Guard the traffic to Anthropic, or what the agent is aware of? | what the agent is aware of: a hook on each tool's output cleans the local and the remote transcript at once; a proxy cleans only what goes to Anthropic (measured 2026-11-21: 4 copies of the test password in the local transcript with the proxy, 0 with the hook) |
| A daemon, or a command? | a command (`vault`, `vault-admin`), as agent-firewall's (Jean, 2026-11-21) |
| May an agent see a mail's login code or reset link? | yes: temporary (Jean, 2026-11-21) |
| Does unlocking need sudo? | no: the master password is enough |
| Does a grant need sudo? | yes: `sudo vault-admin grant …` |
| How long is a suspected secret kept? | for good: a token can be used at any time later |
| Lock the vault when the last grant ends? | yes |
