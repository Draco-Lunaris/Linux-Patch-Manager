# Linux Patch Manager — Lessons Learned

## 2026-04-24: CI/CD First, Not Manual Builds
**Pattern:** When creating release packages, set up CI/CD pipeline (Gitea Actions) FIRST before manually building.
**Why:** Manual builds are one-off and not reproducible. CI/CD ensures every push/tag produces a fresh, consistent package built on the correct target OS (Ubuntu 24.04), with proper glibc compatibility.
**Action:** Always create `.gitea/workflows/` pipeline for automated builds. Use `scripts/build-package.sh` only for local dev testing.

## 2026-04-24: Verify Runner Before Workflow
**Pattern:** Before creating Gitea Actions workflows, verify the act-runner is registered and online.
**Why:** A workflow file without a running runner is dead code.
**Action:** Check runner status via Gitea API (`/api/v1/repos/echo/linux_patch_manager/actions/runners`) or web UI before assuming CI/CD will work.

## 2026-04-24: Dig Deeper on Infrastructure Issues
**Pattern:** When troubleshooting infrastructure, investigate fully — don't stop at the surface error.
**Why:** The runner was crash-looping with a content-type error. The surface cause was a wrong GITEA_INSTANCE_URL, but the deeper issues were: a corrupted `/home/§echo` directory from unresolved `§§secret()` substitution, corrupted authorized_keys entries (§echo comment, sh-ed25519 with missing 's'), and stale runner registration.
**Action:** When troubleshooting, check for cascading issues: file system artifacts, config corruption, stale state. Don't fix one thing and declare victory.

## 2026-04-24: Don't Remove SSH Keys Without Verifying Which Key You're Using
**Pattern:** When cleaning up authorized_keys, verify which key is your current access path before removing entries.
**Why:** I removed the '§echo' key entry thinking it was corrupted, but that was the key I was using to SSH into the runner LXC. Now I'm locked out.
**Action:** Before modifying authorized_keys, check `ssh-add -l` or verify which key file maps to which entry. Never remove a key you're actively using.
