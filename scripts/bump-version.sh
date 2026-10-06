#!/usr/bin/env bash
# Bump the project version across every file that records it, then prove they agree.
#
# Usage: ./scripts/bump-version.sh <new-version> [expected-current-version]
#
# Cargo.toml is the single source of truth for the current version; it is read,
# not passed in. The optional second argument is checked against it and the
# script aborts on a mismatch, so a stale caller cannot bump the wrong thing.
#
# Releases are published by CI from a pushed tag (.github/workflows/ci.yml).
# Do NOT run `gh release create`: it tags whatever master currently points at,
# which produces an empty release and a build that fails the version-check gate.
# Use scripts/release.sh, which bumps, commits, tags and pushes in that order.
set -euo pipefail

NEW="${1:?Usage: bump-version.sh <new-version> [expected-current-version]}"
EXPECTED="${2:-}"

cd "$(cd "$(dirname "$0")/.." && pwd)"

die()  { printf '\nerror: %s\n' "$*" >&2; exit 1; }
step() { printf '  %-26s %s\n' "$1" "$2"; }

# ── preconditions ───────────────────────────────────────────────────────────
[[ "$NEW" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] \
    || die "'$NEW' is not a bare semver version (want N.N.N, no leading 'v')"

# cargo is required, not optional: Cargo.lock records the workspace crates'
# versions too, and a lock left behind is exactly how the tree drifted to
# Cargo.toml=1.6.13 / Cargo.lock=1.6.12 before this was fixed.
command -v cargo >/dev/null \
    || die "cargo not found — required to keep Cargo.lock in step with Cargo.toml"
command -v python3 >/dev/null \
    || die "python3 not found — required to edit the JSON files safely"

CUR="$(awk -F'"' '/^version = /{print $2; exit}' Cargo.toml)"
[[ -n "$CUR" ]] || die "could not read the workspace version from Cargo.toml"
[[ -z "$EXPECTED" || "$EXPECTED" == "$CUR" ]] \
    || die "caller expected current version '$EXPECTED' but Cargo.toml says '$CUR'"
[[ "$NEW" != "$CUR" ]] || die "already at $NEW — nothing to do"

echo "=== bumping $CUR -> $NEW ==="

# ── 1. Cargo.toml (source of truth) ─────────────────────────────────────────
# Anchored to the first `version = ` line, which is [workspace.package].
# An unanchored substitution would also rewrite any dependency pinned at the
# same version string.
sed -i "0,/^version = \"$CUR\"/s//version = \"$NEW\"/" Cargo.toml
step "Cargo.toml" "$NEW"

# ── 2. Cargo.lock (cargo owns it — never hand-edit) ─────────────────────────
# Resolving rewrites the workspace members' versions to match the manifest.
cargo metadata --format-version 1 >/dev/null 2>&1 \
    || cargo metadata --format-version 1 --offline >/dev/null \
    || die "cargo could not refresh Cargo.lock"
step "Cargo.lock" "refreshed by cargo"

# ── 3. debian/changelog ─────────────────────────────────────────────────────
{
    echo "linux-patch-manager ($NEW-1) unstable; urgency=low"
    echo ""
    echo "  * Release v$NEW"
    echo ""
    echo " -- Draco-Lunaris <noreply@users.noreply.github.com>  $(date -R)"
    echo ""
    cat debian/changelog
} > debian/changelog.new && mv debian/changelog.new debian/changelog
step "debian/changelog" "entry added for $NEW-1"

# ── 4. debian/control ───────────────────────────────────────────────────────
grep -q '^Version:' debian/control || die "debian/control has no Version: field"
sed -i "s/^Version: .*/Version: $NEW-1/" debian/control
step "debian/control" "$NEW-1"

# ── 5. frontend/package.json + package-lock.json ────────────────────────────
# Rewrites only the project's own version fields, leaving the rest of the file
# — including its formatting — untouched. package.json has one such field;
# the lockfile has two (top level and packages[""]).
python3 - "$NEW" <<'PY'
import json, re, sys
new = sys.argv[1]
for path, count in (("frontend/package.json", 1), ("frontend/package-lock.json", 2)):
    src = open(path).read()
    out, n = re.subn(r'("version"\s*:\s*)"[^"]*"', lambda m: m.group(1) + f'"{new}"', src, count=count)
    if n != count:
        sys.exit(f"error: {path}: rewrote {n} version field(s), expected {count}")
    json.loads(out)                      # refuse to write invalid JSON
    open(path, "w").write(out)
d = json.load(open("frontend/package-lock.json"))
if d.get("version") != new or d.get("packages", {}).get("", {}).get("version") != new:
    sys.exit("error: frontend/package-lock.json version fields did not take")
PY
step "frontend/package.json" "$NEW"
step "frontend/package-lock.json" "$NEW"

# ── verify: every source must agree, or this is not a release ───────────────
echo ""
echo "=== verifying ==="
FAIL=0
check() {
    if [[ "$2" == "$3" ]]; then step "$1" "$2"
    else printf '  %-26s %s  (expected %s)  MISMATCH\n' "$1" "$2" "$3"; FAIL=1; fi
}
check "Cargo.toml"        "$(awk -F'"' '/^version = /{print $2; exit}' Cargo.toml)" "$NEW"
check "debian/control"    "$(awk '/^Version:/{print $2; exit}' debian/control)"     "$NEW-1"
check "debian/changelog"  "$(head -1 debian/changelog | sed -E 's/.*\(([^)]*)\).*/\1/')" "$NEW-1"
check "frontend/package.json" \
      "$(python3 -c 'import json;print(json.load(open("frontend/package.json"))["version"])')" "$NEW"
check "frontend/package-lock.json" \
      "$(python3 -c 'import json;print(json.load(open("frontend/package-lock.json"))["version"])')" "$NEW"

# Every workspace crate in Cargo.lock must carry the new version.
LOCK_VERS="$(python3 - "$NEW" <<'PY'
import sys, tomllib
want = sys.argv[1]
members = {"pm-web","pm-worker","pm-core","pm-agent-client","pm-auth","pm-ca","pm-reports","migrate-secrets"}
got = {p["version"] for p in tomllib.load(open("Cargo.lock","rb"))["package"] if p["name"] in members}
print(",".join(sorted(got)) if got else "NONE")
PY
)"
check "Cargo.lock (workspace)" "$LOCK_VERS" "$NEW"

# The lock must still be consistent with the manifests.
if cargo metadata --locked --format-version 1 >/dev/null 2>&1; then
    step "cargo metadata --locked" "consistent"
else
    printf '  %-26s %s\n' "cargo metadata --locked" "INCONSISTENT"; FAIL=1
fi

# build-package.sh must derive the version rather than hardcode it.
if grep -qE '^VERSION=\$\(' scripts/build-package.sh; then
    step "build-package.sh" "derives from Cargo.toml"
else
    printf '  %-26s %s\n' "build-package.sh" "hardcodes a version — update it"; FAIL=1
fi

# Stale references. Note the parentheses: the original wrote
#   grep ... || true | grep -v ...
# which parses as `grep ... || (true | grep -v ...)`, so the exclusions never
# applied to grep's own output.
echo ""
echo "=== stale references to $CUR ==="
# -F is required: "$CUR" is a literal version, but as a regex its dots match
# any character, so 1.6.13 matches "...1f6d13..." inside a hex checksum.
# Cargo.lock checksum lines are excluded as well — they are content hashes and
# can never be a meaningful version reference.
STALE="$(grep -rIFn "$CUR" \
            --include='*.toml' --include='*.lock' --include='*.json' \
            --include='*.sh' --include='control' . 2>/dev/null \
         | grep -vE '(^|/)(target|\.git|node_modules)/' \
         | grep -vE ':[0-9]+:[[:space:]]*checksum[[:space:]]*=' \
         | grep -v 'scripts/bump-version.sh' \
         | grep -v 'debian/changelog' || true)"
if [[ -n "$STALE" ]]; then echo "$STALE" | sed 's/^/  /'; FAIL=1
else echo "  none"; fi

(( FAIL == 0 )) || die "version bump is inconsistent — do not tag this tree"

cat <<NEXT

=== $NEW is consistent across every version source ===

Next steps (scripts/release.sh does all of this for you):

  1. Review:  git diff
  2. Commit:  git commit -am "release v$NEW"
  3. Push:    git push origin master        <- the commit MUST land first
  4. Tag:     git tag v$NEW && git push origin v$NEW

CI builds the .deb and the Docker image from the tag and publishes the
GitHub Release itself, with SHA256SUMS, a detached GPG signature and a
build-provenance attestation.

Do NOT run 'gh release create'. It tags whatever master points at, so if
the release commit is not pushed yet you get an empty release and a build
that fails the version-check gate.
NEXT
