# Contributing to Linux-Patch-Manager

Thank you for your interest in contributing to Linux-Patch-Manager! We appreciate every contribution — from bug reports and documentation improvements to new features and security fixes.

## Code of Conduct

This project follows the [Contributor Covenant v2.1](https://www.contributor-covenant.org/version/2/1/code_of_conduct/) code of conduct. By participating, you are expected to uphold this standard. Please report unacceptable behavior to the maintainers.

## How to Contribute

1. **Fork** the repository
2. Create a **feature branch** from `master`:
   ```bash
   git checkout -b feat/my-feature
   ```
3. Make your changes
4. Ensure all CI checks pass:
   ```bash
   # Rust backend
   cargo fmt --check --all
   cargo clippy --all-targets --all-features
   cargo test --workspace --all-features --lib --bins --tests

   # TypeScript/React frontend
   cd frontend
   npx eslint src/ --ext .ts,.tsx --max-warnings 0
   npx tsc --noEmit
   ```
5. **Commit** using conventional commit format (see below)
6. Open a **Pull Request** against `master`

## Development Setup

### Prerequisites

- **Rust toolchain** (stable) — [rustup](https://rustup.rs/)
- **Node.js** 20+ (for the frontend) — [nvm](https://github.com/nvm-sh/nvm) recommended
- **System dependencies**:
  ```bash
  sudo apt-get install build-essential pkg-config libssl-dev libfontconfig1-dev
  ```

### Build & Run

```bash
# Backend
cargo build
cargo test

# Frontend
cd frontend
npm install
npm run build
npm test
```

## Commit Messages

We use [Conventional Commits](https://www.conventionalcommits.org/):

| Prefix   | Usage                  |
|----------|------------------------|
| `feat:`  | New feature            |
| `fix:`   | Bug fix                |
| `docs:`  | Documentation changes  |
| `chore:` | Maintenance tasks      |
| `refactor:` | Code refactoring    |
| `test:`  | Adding or updating tests |
| `ci:`    | CI configuration changes |

Example:
```
feat: add patch scheduling to manager dashboard
```

## Pull Request Requirements

- All CI checks must pass (fmt, clippy, test, audit, build)
- One feature or fix per PR — keep changes focused
- Include a clear description of what changed and why
- Update documentation if your change affects behavior

## Releasing

Releases are built by CI from a pushed tag, and **CI creates the GitHub Release
itself** — every release is authored by `github-actions[bot]`. Nobody creates one
by hand.

The version bump goes through a pull request like any other change:

```bash
# 1. from a clean master, cut the release branch and open the PR
just check                # the slow CI gates; release.sh does not run them
just release patch        # or minor / major

# 2. a maintainer reviews and merges that PR

# 3. tag the merged master to trigger the build
git checkout master && git pull
just release-tag
```

`scripts/release.sh <patch|minor|major>` creates `release/vX.Y.Z`, bumps every
version source, commits, pushes the branch and opens the PR. **It never commits
to master and never pushes a tag.**

`scripts/release.sh tag` reads the version from the merged `origin/master`,
confirms no such tag exists, and pushes it. This is the step that prevents the
one failure mode that matters: tagging a commit whose `Cargo.toml` does not
match the tag. `ci.yml`'s `version-check` job refuses such a build, so the tag
publishes nothing and the tag has to be deleted before retrying.

Before cutting a release, `release.sh` runs `cargo audit`, because a new
advisory against an unchanged dependency is the gate most likely to have gone
red since the last release. Patch any advisories on their own PR first.

### Which files record a version

`scripts/bump-version.sh` owns all of them and verifies they agree, exiting
non-zero rather than leaving the tree half-bumped:

| File | Written by |
|------|-----------|
| `Cargo.toml` | the source of truth |
| `Cargo.lock` | cargo, via `cargo metadata` — never hand-edited |
| `debian/changelog` | new `N.N.N-1` entry |
| `debian/control` | `Version:` field |
| `frontend/package.json` | its own `version` field |
| `frontend/package-lock.json` | its own `version` fields (two) |

`scripts/build-package.sh` needs no bump — it derives the version from
`Cargo.toml`.

## Reporting Issues

Use [GitHub Issues](https://github.com/Draco-Lunaris/Linux-Patch-Manager/issues) to report bugs, request features, or ask questions. Please include:

- Steps to reproduce (for bugs)
- Expected vs. actual behavior
- Relevant logs or error messages

## License

By contributing, you agree that your contributions are licensed under the [Apache License 2.0](LICENSE), the same license as this project.
