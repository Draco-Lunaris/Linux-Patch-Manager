#!/bin/bash
# Bump version across all version source files for linux_patch_manager
# Usage: ./scripts/bump-version.sh <new_version> <old_version>
# Example: ./scripts/bump-version.sh 0.1.10 0.1.9
set -euo pipefail

NEW_VERSION="${1:?Usage: bump-version.sh <new_version> <old_version>}"
OLD_VERSION="${2:?Usage: bump-version.sh <new_version> <old_version>}"

REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_DIR"

echo "=== Bumping version from $OLD_VERSION to $NEW_VERSION ==="
echo ""

# 1. Cargo.toml (PRIMARY - workspace.package.version)
sed -i "s/version = \"$OLD_VERSION\"/version = \"$NEW_VERSION\"/" Cargo.toml
echo "[1/5] Cargo.toml: $OLD_VERSION -> $NEW_VERSION"

# 2. debian/changelog - Prepend new entry using temp file
TEMP_CHANGELOG=$(mktemp)
echo "linux-patch-manager ($NEW_VERSION-1) unstable; urgency=low" > "$TEMP_CHANGELOG"
echo "" >> "$TEMP_CHANGELOG"
echo "  * Release v$NEW_VERSION" >> "$TEMP_CHANGELOG"
echo "" >> "$TEMP_CHANGELOG"
echo " -- git-echo <git-echo@moon-dragon.us>  $(date -R)" >> "$TEMP_CHANGELOG"
echo "" >> "$TEMP_CHANGELOG"
cat debian/changelog >> "$TEMP_CHANGELOG"
mv "$TEMP_CHANGELOG" debian/changelog
echo "[2/5] debian/changelog: Added entry for $NEW_VERSION"

# 3. debian/control - Update Version field
if grep -q "^Version:" debian/control 2>/dev/null || true; then
    sed -i "s/^Version: .*/Version: $NEW_VERSION-1/" debian/control
    echo "[3/5] debian/control: -> $NEW_VERSION-1"
else
    echo "[3/5] debian/control: Version field not found, skipping"
fi

# 4. scripts/build-package.sh - Update VERSION variable
if [ -f scripts/build-package.sh ]; then
    sed -i "s/^VERSION=\".*\"/VERSION=\"$NEW_VERSION\"/" scripts/build-package.sh
    echo "[4/5] scripts/build-package.sh: -> $NEW_VERSION"
else
    echo "[4/5] scripts/build-package.sh: Not found, skipping"
fi

# 5. frontend/package.json - Update version field
if [ -f frontend/package.json ]; then
    sed -i "s/\"version\": \"[^\"]*\"/\"version\": \"$NEW_VERSION\"/" frontend/package.json
    echo "[5/5] frontend/package.json: -> $NEW_VERSION"
else
    echo "[5/5] frontend/package.json: Not found, skipping"
fi

echo ""
echo "=== Version bump complete ==="
echo ""
echo "Verification:"
echo "  Cargo.toml:            $(grep '^version' Cargo.toml | head -1)"
echo "  debian/changelog:      $(head -1 debian/changelog)"
if [ -f debian/control ]; then
    echo "  debian/control:        $(grep '^Version' debian/control)"
fi
if [ -f scripts/build-package.sh ]; then
    echo "  build-package.sh:      $(grep '^VERSION=' scripts/build-package.sh)"
fi
if [ -f frontend/package.json ]; then
    echo "  frontend/package.json: $(grep '"version"' frontend/package.json | head -1)"
fi

echo ""
echo "Stale references check:"
grep -r "$OLD_VERSION" --include='*.toml' --include='*.sh' --include='*.json' --include='control' . 2>/dev/null || true | grep -v 'target/' | grep -v '.git/' | grep -v 'node_modules/' | grep -v 'bump-version.sh' || echo "  No stale references found"

echo ""
echo "Next steps:"
echo "  1. Review changes: git diff"
echo "  2. Commit: git commit -am 'chore: bump version to $NEW_VERSION'"
echo "  3. Push: git push origin master"
echo "  4. Tag: git tag v$NEW_VERSION && git push origin v$NEW_VERSION"
echo "  5. Create release via Gitea API"
