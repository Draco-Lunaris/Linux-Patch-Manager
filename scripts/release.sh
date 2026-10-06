#!/usr/bin/env bash
# Cut a release: verify, bump, commit, tag, push — in that order.
#
# Usage: ./scripts/release.sh <patch|minor|major> [--skip-audit] [--yes]
#    or: just release patch
#
# CI builds the official .deb and Docker image from the pushed tag and
# publishes the GitHub Release itself, with SHA256SUMS, a detached GPG
# signature and a build-provenance attestation.
#
# Never run `gh release create`. It tags whatever master currently points at,
# so if the release commit has not been pushed you get an empty public release
# and a build that fails the version-check gate.
set -euo pipefail

KIND=""; SKIP_AUDIT=0; ASSUME_YES=0
for arg in "$@"; do
    case "$arg" in
        patch|minor|major) KIND="$arg" ;;
        --skip-audit)      SKIP_AUDIT=1 ;;
        --yes|-y)          ASSUME_YES=1 ;;
        *) echo "unknown argument: $arg" >&2; exit 1 ;;
    esac
done
[[ -n "$KIND" ]] || { echo "Usage: release.sh <patch|minor|major> [--skip-audit] [--yes]" >&2; exit 1; }

cd "$(git rev-parse --show-toplevel)"
die() { printf '\nerror: %s\n' "$*" >&2; exit 1; }

# ── preflight: refuse to build a release from a tree we cannot vouch for ────
echo "=== preflight ==="

# A dirty tree used to be swept into the release commit by `git add -A`.
[[ -z "$(git status --porcelain)" ]] \
    || die "working tree is not clean. Commit or stash first — a release commit must contain only the version bump."

BRANCH="$(git rev-parse --abbrev-ref HEAD)"
[[ "$BRANCH" == "master" ]] \
    || die "on '$BRANCH', not master. CI only builds releases from tags on master's history."

git fetch --quiet origin master
[[ "$(git rev-parse HEAD)" == "$(git rev-parse origin/master)" ]] \
    || die "local master and origin/master differ. Pull or push first, so the tag lands on a commit that exists upstream."

OLD="$(awk -F'"' '/^version = /{print $2; exit}' Cargo.toml)"
IFS='.' read -r MAJOR MINOR PATCH <<< "$OLD"
case "$KIND" in
    major) NEW="$((MAJOR+1)).0.0" ;;
    minor) NEW="$MAJOR.$((MINOR+1)).0" ;;
    patch) NEW="$MAJOR.$MINOR.$((PATCH+1))" ;;
esac

# A tag that already exists anywhere means this version was at least attempted.
git rev-parse -q --verify "refs/tags/v$NEW" >/dev/null \
    && die "tag v$NEW already exists locally. Delete it or pick another version."
[[ -z "$(git ls-remote --tags origin "v$NEW" 2>/dev/null)" ]] \
    || die "tag v$NEW already exists on origin. Remove it (gh release delete v$NEW --cleanup-tag) or pick another version."

echo "  tree clean, on master, in sync with origin"
echo "  v$OLD -> v$NEW"

# ── run the gates CI will run, before committing to a version number ───────
# cargo audit is the gate most likely to have gone red since the last release
# through no change of ours: a new advisory against an existing dependency.
if (( SKIP_AUDIT )); then
    echo "  cargo audit SKIPPED (--skip-audit)"
elif command -v cargo-audit >/dev/null || cargo audit --version >/dev/null 2>&1; then
    echo ""
    echo "=== cargo audit (required by CI) ==="
    cargo audit || die "cargo audit failed. Patch the advisories (cargo update -p <crate>) and commit that before releasing."
else
    echo "  cargo audit NOT INSTALLED — run 'just tools' (cargo install cargo-audit --locked)"
    die "cannot verify advisories; install cargo-audit or pass --skip-audit"
fi

echo ""
echo "Reminder: 'just check' runs the remaining CI gates (fmt, clippy, test, frontend)."
echo "          This script does not, because it takes minutes; CI will."

# ── confirm ─────────────────────────────────────────────────────────────────
if (( ! ASSUME_YES )); then
    echo ""
    read -r -p "Release v$NEW? This pushes a commit and a tag to origin. [y/N] " reply
    [[ "$reply" == [yY] ]] || { echo "aborted"; exit 1; }
fi

# ── bump ────────────────────────────────────────────────────────────────────
echo ""
./scripts/bump-version.sh "$NEW" "$OLD"

# Stage only the files that record a version. Never `git add -A`.
git add -- Cargo.toml Cargo.lock debian/changelog debian/control \
           frontend/package.json frontend/package-lock.json
[[ -z "$(git diff --name-only)" ]] \
    || die "the bump modified files outside the known version set: $(git diff --name-only | tr '\n' ' ')"

git commit -q -m "release v$NEW"
echo "committed $(git rev-parse --short HEAD)"

# ── last check: the guard CI enforces (ci.yml version-check) ───────────────
COMMITTED="$(awk -F'"' '/^version = /{print $2; exit}' Cargo.toml)"
[[ "$COMMITTED" == "$NEW" ]] \
    || die "committed Cargo.toml says '$COMMITTED', tag would say '$NEW'. CI would refuse this build."

git tag "v$NEW"

# ── push: commit first, then the tag that triggers the build ───────────────
echo ""
echo "=== pushing ==="
git push origin master
git push origin "v$NEW"

cat <<DONE

=== v$NEW pushed ===

CI is now building the official .deb and Docker image and will publish the
GitHub Release with SHA256SUMS, SHA256SUMS.asc and a provenance attestation.

  gh run watch "\$(gh run list --branch "v$NEW" --limit 1 --json databaseId --jq '.[0].databaseId')"

Once it finishes, verify the published artifacts as an operator would —
see docs/release-signing.md.
DONE
