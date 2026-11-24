#!/bin/bash
# ~/opt/agent-vault/alerts.sh: job agent-vault.alerts (job-runner). Every 5 min on the Mac.
# Requirements:
#   - each new alert of `vault internal mask --out` (a vault secret in a text leaving: it reached a transcript) becomes one
#     Todoist task, once per item and day: `vault-admin file-alerts` (Jean's user: it holds the Todoist login, av-vault does not)
#   - agent-vault not installed yet (no /usr/local/agent-vault): skip
#   - timeout 5 min
. ~/opt/job-runner/lib.sh
[ -x /usr/local/agent-vault/bin/vault-admin ] || jr_skip "agent-vault not installed (sudo bash ~/dev/agents/agent-vault/install_system.sh)"
jr_execute 5 /usr/local/agent-vault/bin/vault-admin file-alerts
