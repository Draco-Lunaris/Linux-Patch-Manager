#!/usr/bin/env bash
# Release helper. Two steps, matching how this repo actually releases.
#
#   ./scripts/release.sh <patch|minor|major>   # step 1: bump on a branch, open a PR
#   ./scripts/release.sh tag                   # step 3: tag merged master, trigger CI
#
# The flow:
#   1. This script creates release/vX.Y.Z, bumps every version source, commits
#      and opens a pull request. It never commits to master.
#   2. A maintainer reviews and merges that PR.
#   3. `release.sh tag` verifies the merged master really carries that version,
#      then pushes the tag.
#   4. CI builds the .deb and Docker image from the tag and publishes the
#      GitHub Release itself, with SHA256SUMS, a detached GPG signature and a
#      build-provenance attestation. Every release is authored by
#      github-actions[bot]; nobody creates one by hand.
#
# Tagging a commit whose Cargo.toml does not match the tag is the one failure
# this guards: ci.yml's version-check refuses the build, so the tag publishes
# nothing. Step 3 checks it before the tag exists.
set -euo pipefail

MODE=""; SKIP_AUDIT=0; ASSUME_YES=0
for arg in "$@"; do
    case "$arg" in
        patch|minor|major|tag) MODE="$arg" ;;
        --skip-audit)          SKIP_AUDIT=1 ;;
        --yes|-y)              ASSUME_YES=1 ;;
        *) echo "unknown argument: $arg" >&2; exit 1 ;;
    esac
done
[[ -n "$MODE" ]] || {
    echo "Usage: release.sh <patch|minor|major|tag> [--skip-audit] [--yes]" >&2; exit 1; }

cd "$(git rev-parse --show-toplevel)"
die() { printf '\nerror: %s\n' "$*" >&2; exit 1; }
confirm() {
    (( ASSUME_YES )) && return 0
    read -r -p "$1 [y/N] " r; [[ "$r" == [yY] ]] || { echo "aborted"; exit 1; }
}

git fetch --quiet origin master

# ── step 3: tag the merged master ───────────────────────────────────────────
if [[ "$MODE" == "tag" ]]; then
    VER="$(git show origin/master:Cargo.toml | awk -F'"' '/^version = /{print $2; exit}')"
    [[ -n "$VER" ]] || die "could not read the version from origin/master:Cargo.toml"
    echo "=== tagging v$VER at origin/master ==="
    echo "  origin/master: $(git log -1 --format='%h %s' origin/master)"
    echo "  Cargo.toml:    $VER"

    git rev-parse -q --verify "refs/tags/v$VER" >/dev/null \
        && die "tag v$VER already exists locally — delete it or check the version"
    [[ -z "$(git ls-remote --tags origin "v$VER")" ]] \
        || die "tag v$VER already exists on origin. If its build failed, remove it first: gh release delete v$VER --cleanup-tag"

    # The exact comparison ci.yml's version-check performs.
    echo "  version-check will compare tag '$VER' against Cargo.toml '$VER' -> PASS"
    confirm "Push tag v$VER? CI will build and publish the release."
    git tag "v$VER" "$(git rev-parse origin/master)"
    git push origin "v$VER"
    echo ""
    echo "pushed v$VER. CI is building; it creates the GitHub Release itself."
    echo "  gh run watch \"\$(gh run list --branch v$VER --limit 1 --json databaseId --jq '.[0].databaseId')\""
    exit 0
fi

# ── step 1: bump on a branch and open a PR ─────────────────────────────────
echo "=== preflight ==="
[[ -z "$(git status --porcelain)" ]] \
    || die "working tree is not clean. Commit or stash first — a release commit must contain only the version bump."
[[ "$(git rev-parse --abbrev-ref HEAD)" == "master" ]] \
    || die "not on master. The release branch is cut from master."
[[ "$(git rev-parse HEAD)" == "$(git rev-parse origin/master)" ]] \
    || die "local master and origin/master differ. Pull first."
command -v gh >/dev/null || die "gh not found — needed to open the pull request"

OLD="$(awk -F'"' '/^version = /{print $2; exit}' Cargo.toml)"
IFS='.' read -r MAJOR MINOR PATCH <<< "$OLD"
case "$MODE" in
    major) NEW="$((MAJOR+1)).0.0" ;;
    minor) NEW="$MAJOR.$((MINOR+1)).0" ;;
    patch) NEW="$MAJOR.$MINOR.$((PATCH+1))" ;;
esac
BRANCH="release/v$NEW"

git rev-parse -q --verify "refs/tags/v$NEW" >/dev/null \
    && die "tag v$NEW already exists locally"
[[ -z "$(git ls-remote --tags origin "v$NEW")" ]] \
    || die "tag v$NEW already exists on origin. Remove it first: gh release delete v$NEW --cleanup-tag"
[[ -z "$(git ls-remote --heads origin "$BRANCH")" ]] \
    || die "branch $BRANCH already exists on origin"

echo "  tree clean, on master, in sync with origin"
echo "  v$OLD -> v$NEW  (branch $BRANCH)"

# cargo audit is the gate most likely to have gone red since the last release
# through no change of ours: a new advisory against an existing dependency.
if (( SKIP_AUDIT )); then
    echo "  cargo audit SKIPPED (--skip-audit)"
else
    [ -f "$HOME/.cargo/env" ] && . "$HOME/.cargo/env"   # rustup --no-modify-path
    command -v cargo-audit >/dev/null || cargo audit --version >/dev/null 2>&1 \
        || die "cargo-audit not found. Run 'just tools', or pass --skip-audit."
    echo ""
    echo "=== cargo audit (required by CI) ==="
    cargo audit || die "cargo audit failed. Patch the advisories (cargo update -p <crate>) on their own PR first."
fi

echo ""
echo "Reminder: 'just check' runs the remaining CI gates (fmt, clippy, test, frontend)."
echo "          This script does not, because it takes minutes."
confirm "Open a release PR for v$NEW?"

git checkout -q -b "$BRANCH"
echo ""
./scripts/bump-version.sh "$NEW" "$OLD"

git add -- Cargo.toml Cargo.lock debian/changelog debian/control \
           frontend/package.json frontend/package-lock.json
[[ -z "$(git diff --name-only)" ]] \
    || die "the bump modified files outside the known version set: $(git diff --name-only | tr '\n' ' ')"
git commit -q -m "release v$NEW"

COMMITTED="$(awk -F'"' '/^version = /{print $2; exit}' Cargo.toml)"
[[ "$COMMITTED" == "$NEW" ]] || die "committed Cargo.toml says '$COMMITTED', expected '$NEW'"

git push -q -u origin "$BRANCH"
gh pr create --base master --head "$BRANCH" \
    --title "release v$NEW" \
    --body "Version bump only — every source that records a version, verified to agree by \`scripts/bump-version.sh\`.

Once this is merged, tag it to trigger the build:

\`\`\`bash
./scripts/release.sh tag
\`\`\`

That verifies the merged \`master\` really carries \`$NEW\` before the tag exists, then pushes \`v$NEW\`. CI builds the \`.deb\` and Docker image and publishes the GitHub Release with \`SHA256SUMS\`, a detached GPG signature and a build-provenance attestation."

cat <<DONE

=== release PR opened for v$NEW ===

  1. Review and merge the PR.
  2. Then: git checkout master && git pull && ./scripts/release.sh tag

Nothing is tagged yet, and master is untouched.
DONE
