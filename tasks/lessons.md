# Linux Patch Manager — Lessons Learned

## 2026-04-24: CI/CD First, Not Manual Builds
**Pattern:** When creating release packages, set up CI/CD pipeline (Gitea Actions) FIRST before manually building.
**Why:** Manual builds are one-off and not reproducible. CI/CD ensures every push/tag produces a fresh, consistent package built on the correct target OS (Ubuntu 24.04), with proper glibc compatibility.
**Action:** Always create `.gitea/workflows/` pipeline for automated builds. Use `scripts/build-package.sh` only for local dev testing.

## 2026-04-24: Verify Runner Before Workflow
**Pattern:** Before creating Gitea Actions workflows, verify the act-runner is registered and online.
**Why:** A workflow file without a running runner is dead code.
**Action:** Check runner status via Gitea API or web UI before assuming CI/CD will work.

## 2026-04-24: Dig Deeper on Infrastructure Issues
**Pattern:** When troubleshooting infrastructure, investigate fully — don't stop at the surface error.
**Why:** The runner was crash-looping with a content-type error. The surface cause was a wrong GITEA_INSTANCE_URL, but the deeper issues were: a corrupted `/home/§echo` directory from unresolved `§§secret()` substitution, corrupted authorized_keys entries (§echo comment, sh-ed25519 with missing 's'), and stale runner registration.
**Action:** When troubleshooting, check for cascading issues: file system artifacts, config corruption, stale state. Don't fix one thing and declare victory.

## 2026-04-24: Don't Remove SSH Keys Without Verifying Which Key You're Using
**Pattern:** When cleaning up authorized_keys, verify which key is your current access path before removing entries.
**Why:** I removed the '§echo' key entry thinking it was corrupted, but that was the key I was using to SSH into the runner LXC. Now I'm locked out.
**Action:** Before modifying authorized_keys, check `ssh-add -l` or verify which key file maps to which entry. Never remove a key you're actively using.

## 2026-04-24: Docker-in-Docker Fails in LXC
**Pattern:** Docker-in-Docker (spawning sibling containers from a Docker-based act_runner) fails with SIGKILL (exit 137) in LXC environments, even with `--privileged` mode.
**Why:** LXC containers don't support the full Docker daemon nesting required for act_runner's Docker mode. Containers get killed after ~45 seconds regardless of privileged flag.
**Action:** For LXC-based runners, install act_runner as a native binary on the host with systemd service. Use `runs-on: linux` (maps to `linux:host`) to execute steps directly on the LXC host. Pre-install build tools (Rust, Node.js) on the host.

## 2026-04-24: Gitea Actions Runner — Native Binary vs Docker
**Pattern:** For self-hosted Gitea Actions runners on LXC, use native act_runner binary with systemd service, not Docker container.
**Why:** Docker-in-Docker fails in LXC (SIGKILL after 45s). Native binary runs directly on the host, supports `linux:host` label for direct execution, and avoids all nesting issues.
**Setup:**
1. Download: `curl -sL https://gitea.com/gitea/act_runner/releases/download/v0.3.1/act_runner-0.3.1-linux-amd64 -o /home/echo/act_runner`
2. Register: `./act_runner register --instance http://<GITEA_IP>:3000 --token <TOKEN> --labels "ubuntu-latest:docker://ubuntu:24.04,linux:host,docker:host"`
3. Systemd service: `/etc/systemd/system/act-runner.service`
4. GITEA_INSTANCE_URL must use internal IP (http://192.168.2.189:3000), NOT external domain (https://gitea.moon-dragon.us returns HTML, not API protobuf)

## 2026-04-24: No GitHub Action Dependencies in Gitea Workflows
**Pattern:** Don't use `uses: actions/checkout@v4`, `actions/cache@v3`, etc. in Gitea Actions workflows.
**Why:** Self-hosted runners may not have reliable internet access to github.com to clone those actions. The runner gets stuck cloning GitHub repos.
**Action:** Use pure shell steps: `git clone ${GITHUB_SERVER_URL}/${GITHUB_REPOSITORY}.git .` for checkout, skip caching, and avoid any `uses:` directives that reference github.com.

## CI/CD Runner Dual-Registration Root Cause (2026-04-24)

**Problem:** CI jobs kept failing with 'apt-get: command not found' and 'curl: command not found' despite multiple PATH fixes.

**Root Cause:** TWO runners registered with the same name 'echo-runner-01':
- Docker container runner (ID 5) - running inside minimal Alpine container where apt-get doesn't exist
- Native systemd runner (ID 6) - running on Ubuntu 24.04 LXC host

The Docker container intercepted some jobs and ran them in its Alpine environment. The native runner ran other jobs on the host.

**Fix:** Stopped and removed the Docker container runner. Switched workflow to `runs-on: ubuntu-latest` which uses `ubuntu-latest:docker://ubuntu:24.04` label to create proper Ubuntu 24.04 containers for each job.

**Lesson:** When debugging CI failures, check for multiple runners with the same name. The error pattern (some jobs succeeding, some failing) was the key clue that different execution contexts were involved. Stop after 2 attempts and diagnose root cause instead of making 5+ superficial fixes.

## CI/CD Runner Dual-Registration Root Cause (2026-04-24)

**Problem:** CI jobs kept failing with apt-get/curl command not found despite multiple PATH fixes.

**Root Cause:** TWO runners registered with same name echo-runner-01:
- Docker container runner (ID 5) - minimal Alpine, no apt-get
- Native systemd runner (ID 6) - Ubuntu 24.04 LXC host
- Docker container intercepted some jobs and ran them in Alpine where tools dont exist

**Fix:** Stopped Docker container runner. Switched to runs-on: ubuntu-latest with docker://ubuntu:24.04 containers.

**Lesson:** Check for multiple runners with same name. Stop after 2 attempts and diagnose root cause.

## 2026-05-05: Always Use Git → Gitea → Runner CI/CD Pipeline for Deployment
**Pattern:** When deploying code changes to any environment, always commit and push to Gitea and let the CI/CD pipeline handle building and deployment.
**Why:** Manually copying built files (scp, etc.) bypasses quality gates (format, clippy, test, lint) and is not reproducible. The CI pipeline ensures every change passes all checks before reaching any environment.
**Action:** Never manually copy files to servers. Always: commit → push to Gitea → let CI/CD run → deploy through proper pipeline.

## 2026-05-05: Verify API Response Structure Matches Frontend Expectations
**Pattern:** When frontend data doesn't appear, check the API response structure before assuming the UI code is wrong.
**Why:** Health checks list was always empty because backend returns `{ checks: [...], total: N }` but frontend used `Array.isArray(res.data) ? res.data : []` which returned `[]` for an object. Maintenance windows worked because they correctly used `res.data?.windows ?? []`.
**Action:** When adding new API endpoints, verify the response wrapper structure matches what the frontend expects. Check existing working patterns (like maintenance windows) for the correct data extraction approach.

## 2026-05-05: Run cargo fmt Before Pushing to Avoid CI Failures
**Pattern:** Always run `cargo fmt --all` locally before pushing Rust code changes.
**Why:** The CI pipeline has a Rust Format Check gate that will fail if code isn't formatted. This wastes CI runner time and delays deployment.
**Action:** Run `cargo fmt --all` as part of local pre-push checklist, alongside `npm run build` for frontend changes.

## 2026-05-06: Pre-Commit/Pre-Push Hooks Must Match CI Checks Exactly
**Pattern:** The git pre-commit and pre-push hooks must run the same checks as the CI pipeline to prevent CI failures.
**Why:** Initially the hooks only ran `cargo fmt` and `tsc --noEmit`, but CI also runs ESLint. Three ESLint errors (eqeqeq, duplicate imports) slipped through the hooks and failed CI.
**Action:** Pre-commit hook now runs: cargo fmt --all, ESLint (--max-warnings 0), tsc --noEmit. Pre-push hook verifies the same checks pass before allowing push. Hooks are stored in `scripts/git-hooks/` and installed via `scripts/git-hooks/install.sh`.

## 2026-05-06: Always Restart Services After .deb Installation
**Pattern:** After installing a .deb package, services must be explicitly restarted. The postinst script only does `systemctl daemon-reload` — it does NOT restart the services.
**Why:** After `dpkg -i`, the old binary is still running in memory. The new binary on disk is only picked up after `systemctl restart`. This caused health checks to not appear because the v0.1.1 binary was still serving requests despite v0.1.2 being installed.
**Action:** Always run `systemctl restart patch-manager-web patch-manager-worker` after .deb installation. Also run database migrations if new migrations were added.

## 2026-05-06: debian/control Version Must Match Cargo.toml
**Pattern:** The debian/control file has a hardcoded `Version: 1.0.0-1` that doesn't match the Cargo.toml version.
**Why:** When dpkg sees the same version number (1.0.0-1) for both old and new packages, it may not properly replace files. The build-package.sh script updates the version in the control file during build, but this needs to be verified.
**Action:** Ensure build-package.sh always updates debian/control Version to match Cargo.toml version before building the .deb.
