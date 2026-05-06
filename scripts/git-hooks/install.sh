#!/usr/bin/env bash
# =============================================================================
# Linux Patch Manager — Git Hooks Installer
# =============================================================================
# Installs pre-commit and pre-push hooks into .git/hooks/
# Run from repo root: ./scripts/git-hooks/install.sh
# =============================================================================

set -euo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel)"
HOOKS_DIR="${REPO_ROOT}/.git/hooks"
SOURCE_DIR="${REPO_ROOT}/scripts/git-hooks"

echo "Installing git hooks from ${SOURCE_DIR} ..."

for hook in pre-commit pre-push; do
    if [[ -f "${SOURCE_DIR}/${hook}" ]]; then
        cp "${SOURCE_DIR}/${hook}" "${HOOKS_DIR}/${hook}"
        chmod +x "${HOOKS_DIR}/${hook}"
        echo "  ✓ Installed ${hook}"
    else
        echo "  ⚠ Skipped ${hook} (not found)"
    fi
done

echo "Done. Hooks will run automatically on commit and push."
