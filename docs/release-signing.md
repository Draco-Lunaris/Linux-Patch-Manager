# Release Signing and Verification

**Applies to:** Linux Patch Manager — release artifacts published to GitHub Releases

> **This is not the package-repository key.** Each manager instance generates its own
> GPG key at runtime to sign the packages it serves to agents; that key and its rotation
> are covered in [gpg-key-rotation.md](gpg-key-rotation.md). This document covers a
> separate, project-wide key used only to sign release artifacts in CI. The two are
> independent — rotating one does not affect the other.

## Why release artifacts are signed

The `.deb` installs as root, creates the internal CA, and from then on holds mTLS
authority over every managed host. An operator who installs a tampered package hands
over the entire fleet. So the release carries three artifacts, which answer three
different questions.

| Artifact | Question it answers | Catches a corrupted download | Catches a tampered release |
|----------|---------------------|:---:|:---:|
| `SHA256SUMS` | Did the file arrive intact? | yes | **no** |
| `SHA256SUMS.asc` | Was this checksum list signed by the project's key? | yes | yes |
| Build provenance attestation | Was this exact binary produced by this repo's release workflow? | yes | yes |

The checksum alone is not a security control. It is published in the same release as the
`.deb`, so anyone who can replace the package can replace the checksum list alongside it
and verification will pass. It protects against truncated downloads and bad mirrors,
nothing more.

The signature and the attestation each close that gap, by different means and with
different failure modes — which is why both are published:

- **The GPG signature** proves the checksum list was signed by a key the project
  controls. It verifies offline, needs only `gpg`, and keeps working if GitHub is
  unavailable or the project moves hosts. Its weakness is key custody: the private key
  exists and must be protected.
- **The provenance attestation** proves the binary came out of a specific workflow run
  in this repository, via [Sigstore](https://www.sigstore.dev/) and a short-lived
  identity token issued to that run. There is no long-lived private key to steal. Its
  weakness is the dependency on GitHub's attestation infrastructure and transparency
  log.

An attacker who compromised the repository would need the GPG private key to forge the
signature, and could not produce a valid attestation for a binary they built elsewhere.

## Verifying a release (operators)

### 1. Download the artifacts

```bash
gh release download --repo Draco-Lunaris/Linux-Patch-Manager \
  --pattern '*_amd64.deb' --pattern 'SHA256SUMS*'
```

### 2. Import the release signing key

```bash
gh release download --repo Draco-Lunaris/Linux-Patch-Manager \
  --pattern 'release-signing-key.asc'
gpg --import release-signing-key.asc
```

Trusting a key fetched from the same place as the artifact is circular. Confirm the
fingerprint against the one published in [SECURITY.md](../SECURITY.md) — and ideally
against a copy you obtained previously, since the value of a signing key is that it
stays the same across releases.

```bash
gpg --fingerprint releases@example.invalid   # or the key ID from the import output
```

### 3. Verify the signature, then the checksum

```bash
gpg --verify SHA256SUMS.asc SHA256SUMS     # the list is authentic
sha256sum --check --ignore-missing SHA256SUMS   # the .deb matches the list
```

Order matters. Checking the `.deb` against an unverified `SHA256SUMS` proves only that
the two files agree with each other.

Expect `Good signature from ...`. A `WARNING: This key is not certified with a trusted
signature` notice alongside it is normal — it means you have not signed the key in your
own web of trust, not that verification failed. A `BAD signature` is a hard stop.

### 4. Verify provenance

```bash
gh attestation verify linux-patch-manager_*_amd64.deb \
  --repo Draco-Lunaris/Linux-Patch-Manager
```

This reports the workflow, repository, and commit the artifact was built from. Check
that the repository is the one you expect.

## Setting up the signing key (maintainers)

Until `RELEASE_GPG_PRIVATE_KEY` is configured, the release workflow publishes
`SHA256SUMS` and the attestation but **no** `SHA256SUMS.asc`, and emits a CI warning
saying so. Releases are not blocked.

### 1. Generate a dedicated key

Use a key reserved for release signing — not a personal identity key, and not the
package-repository key.

```bash
gpg --batch --full-generate-key <<'KEYSPEC'
%echo Generating release signing key
Key-Type: eddsa
Key-Curve: ed25519
Key-Usage: sign
Name-Real: Linux Patch Manager Release Signing
Name-Email: releases@example.invalid
Expire-Date: 2y
%ask-passphrase
%commit
KEYSPEC
```

Replace `Name-Email` with an address you control. A 2-year expiry matches the
package-repository key convention and forces a deliberate rotation.

### 2. Record the fingerprint and export both halves

```bash
KEY_ID=$(gpg --list-secret-keys --with-colons 'releases@example.invalid' \
  | awk -F: '/^fpr:/ {print $10; exit}')
echo "$KEY_ID"

gpg --armor --export "$KEY_ID" > release-signing-key.asc

gpg --batch --yes --pinentry-mode loopback \
    --armor --export-secret-keys "$KEY_ID" > release-signing-key-private.asc
```

`--pinentry-mode loopback` is required for the private-key export: without it, a
non-interactive shell fails with `error receiving key from agent: Inappropriate ioctl
for device` and writes an **empty file** while still exiting 0. Check the result before
relying on it:

```bash
head -1 release-signing-key-private.asc   # -----BEGIN PGP PRIVATE KEY BLOCK-----
```

### 3. Add the CI secrets

```bash
gh secret set RELEASE_GPG_PRIVATE_KEY --repo Draco-Lunaris/Linux-Patch-Manager \
  < release-signing-key-private.asc
gh secret set RELEASE_GPG_PASSPHRASE  --repo Draco-Lunaris/Linux-Patch-Manager
```

Then destroy the exported private copy and keep the only offline backup somewhere
encrypted:

```bash
shred -u release-signing-key-private.asc
```

### 4. Publish the public key and its fingerprint

- **No action needed per release.** CI derives `release-signing-key.asc` from the
  imported private key and attaches it to every release, so the public key cannot drift
  from the key that actually signed the artifacts.
- **Record the fingerprint in [SECURITY.md](../SECURITY.md)** (there is a placeholder
  section waiting for it). This is the one step that matters: it puts the fingerprint
  somewhere outside the release, so verification is not purely circular.
- Optionally publish to `keys.openpgp.org` for a third, independent copy.

### 5. Consider making the signature mandatory

Once signing works end to end, the conditional skip in `.github/workflows/ci.yml` can be
tightened so a release that cannot be signed fails instead of warning. Do this only
after the first signed release has been verified by hand — otherwise a secret
misconfiguration blocks all releases.

## Rotation

Rotate before expiry, or immediately on suspected compromise.

1. Generate a new key (step 1) and record its fingerprint.
2. Update `RELEASE_GPG_PRIVATE_KEY` and `RELEASE_GPG_PASSPHRASE`.
3. Publish the new public key and fingerprint; keep the old public key available so
   previously published releases remain verifiable.
4. On compromise, revoke the old key (`gpg --gen-revoke`), publish the revocation
   certificate, and state in a security advisory which releases were signed with it.

Signatures on already-published releases are not re-made. An expired key still verifies
signatures it made while valid, provided the key itself remains available.
