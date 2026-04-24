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
