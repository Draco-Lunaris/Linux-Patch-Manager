# Credential Bootstrap & Skill Restoration Plan

## Problem
SSH keys and Vaultwarden access are lost on every container restart. This causes repeated auth failures at session start.

## Changes

### 1. Restore vaultwarden-secrets skill to /a0/skills/
- Source: `/tmp/vaultwarden-secrets/` (cloned from gitea)
- Destination: `/a0/skills/vaultwarden-secrets/`
- Files: SKILL.md, README.md, scripts/vw_client.py, scripts/bw-wrapper.sh
- This makes `vw_client.py` available at the path referenced in system prompt
- Verify pycryptodome is installed (needed by vw_client.py)

### 2. Add Session Bootstrap section to echo profile
- File: `/a0/usr/agents/echo/prompts/01-identity.md`
- Add a **Session Bootstrap** section that instructs Echo to verify credentials at the start of every new conversation
- Checks to perform:
  1. **SSH key**: If `~/.ssh/id_ed25519` doesn't exist, retrieve from Vaultwarden using vw_client.py and install
  2. **Vaultwarden skill**: Verify `/a0/skills/vaultwarden-secrets/scripts/vw_client.py` exists and works
  3. **bw CLI**: Check if `bw` is installed; if not, install it (fallback for vw_client.py)
  4. **Gitea SSH key**: Verify `/a0/usr/credentials/gitea-lxc/gitea_id_ed25519` exists for git operations
- Bootstrap runs silently unless a check fails (then report to user)

### 3. Update Credential Type Registry in 02-architecture.md
- Add Vaultwarden as the **authoritative source** for SSH keys
- Clarify that `/a0/usr/storage/echo-ssh-setup/` is a backup, not primary
- Add vw_client.py as the primary credential retrieval method

### 4. Update lessons.md
- Add lesson about credential bootstrap being a systemic fix

## Implementation Order
1. Restore vaultwarden-secrets skill (prerequisite for everything else)
2. Verify vw_client.py works with current credentials
3. Add Session Bootstrap to 01-identity.md
4. Update Credential Type Registry in 02-architecture.md
5. Update lessons.md
6. Test full bootstrap flow

## Approval Needed
- [ ] Modifying echo profile prompts (01-identity.md, 02-architecture.md)
- [ ] Installing skill files to /a0/skills/
- [ ] Installing bw CLI if missing
