-- 029_drop_gpg_signed_column.sql
-- Remove per-package gpg_signed column — packages are never individually signed.
-- Only repo metadata (Release, repomd.xml, APKINDEX.tar.gz, lpa-repo.db.tar.zst)
-- is signed by the manager's GPG key. Package integrity is verified transitively
-- via signed metadata checksums.
--
-- Issue #116 gap fix: per-package signing was unnecessary and should not have
-- been tracked in the database or displayed in the UI.

ALTER TABLE repo_packages DROP COLUMN IF EXISTS gpg_signed;
