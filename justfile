# Linux-Patch-Manager task runner — single source of truth for local + CI.
# Local:   just check           (dev loop; warm cache on the dev box)
# Release: just release patch    (opens a release PR; never touches master)
#          then, once merged: just release-tag
#          CI builds the .deb + Docker image from the tag and creates the
#          GitHub Release itself. Nobody creates one by hand.

default:
    @just --list

# one-time: install the cargo tools the gates need
tools:
    cargo install cargo-audit --locked

# --- quality gates (the dev loop; `just check` runs all) ---
fmt:
    cargo fmt --all -- --check

# NOTE: matches current CI (warnings reported, not fatal). clippy.toml documents
# -D warnings intent, but the tree has pre-existing lints (e.g. too_many_arguments);
# tightening to -D warnings is a follow-up, not part of the releases-only change.
clippy:
    cargo clippy --all-targets --all-features

test:
    cargo test --workspace --all-features --lib --bins --tests

audit:
    cargo audit

# --- frontend gates ---
frontend-deps:
    @cd frontend && [ -d node_modules ] || npm ci

frontend-lint: frontend-deps
    cd frontend && npx eslint src/ --ext .ts,.tsx --max-warnings 0

frontend-typecheck: frontend-deps
    cd frontend && npx tsc --noEmit

frontend-build: frontend-deps
    cd frontend && npm run build

check: fmt clippy test audit frontend-lint frontend-typecheck
    @echo "all gates passed"

# --- build / package ---
build:
    cargo build --release

# system deps (lifted from ci.yml; run on the matching distro)
deps-deb:
    sudo apt-get update && sudo apt-get install -y pkg-config libssl-dev libfontconfig1-dev dpkg-dev

# build the .deb (cargo release + frontend + dpkg-deb)
# depends on frontend-deps so build-package.sh sees a full node_modules and skips
# its own `npm ci --production` (which omits devDeps vite/tsc and would break the build)
# invoked via bash so the committed non-executable mode is left untouched
pkg-deb: frontend-deps
    bash scripts/build-package.sh

# --- release (CI remains the official builder) ---
# Step 1: cut release/vX.Y.Z, bump, commit, push the branch, open the PR.
# Never commits to master, never pushes a tag. Refuses a dirty tree, a
# non-master branch, a master out of sync with origin, an existing tag or
# branch, or a tree that fails cargo audit.
release KIND:
    ./scripts/release.sh "{{KIND}}"

# Step 3 (after the release PR is merged): tag master so CI builds and publishes.
# Verifies origin/master really carries that version before the tag exists.
release-tag:
    ./scripts/release.sh tag

# bump every version source without committing, branching or tagging
bump VERSION:
    ./scripts/bump-version.sh "{{VERSION}}"
