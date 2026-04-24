# Linux Patch Manager — Lessons Learned

## 2026-04-24: CI/CD First, Not Manual Builds
**Pattern:** When creating release packages, set up CI/CD pipeline (Gitea Actions) FIRST before manually building.
**Why:** Manual builds are one-off and not reproducible. CI/CD ensures every push/tag produces a fresh, consistent package built on the correct target OS (Ubuntu 24.04), with proper glibc compatibility.
**Action:** Always create `.gitea/workflows/` pipeline for automated builds. Use `scripts/build-package.sh` only for local dev testing.

## 2026-04-24: Verify Runner Before Workflow
**Pattern:** Before creating Gitea Actions workflows, verify the act-runner is registered and online.
**Why:** A workflow file without a running runner is dead code. The runner at gitea-runner-lxc.moon-dragon.us needs to be verified as operational.
**Action:** Check runner status via Gitea API (`/api/v1/repos/echo/linux_patch_manager/actions/runners`) or web UI before assuming CI/CD will work.
