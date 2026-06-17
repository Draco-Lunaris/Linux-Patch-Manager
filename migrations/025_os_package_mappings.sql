-- Migration: 025_os_package_mappings
-- Description: Add os_package_mappings table for OS-to-package-pattern mapping.
-- Issues: #91

CREATE TABLE os_package_mappings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    os_name TEXT NOT NULL,
    os_version TEXT NOT NULL,
    package_pattern TEXT NOT NULL,
    display_name TEXT NOT NULL,
    is_default BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(os_name, os_version)
);

-- Seed default mappings
INSERT INTO os_package_mappings (os_name, os_version, package_pattern, display_name, is_default) VALUES
    ('Ubuntu', '24.04', '_u2404_', 'Ubuntu 24.04', true),
    ('Ubuntu', '22.04', '_u2204_', 'Ubuntu 22.04', true),
    ('Debian', '12', '_debian12_', 'Debian 12 (Bookworm)', true),
    ('Debian', '13', '_debian13_', 'Debian 13 (Trixie)', true),
    ('Fedora', '43', '.fc43.', 'Fedora 43', true),
    ('AlmaLinux', '10', '.el10.', 'AlmaLinux 10', true),
    ('Alpine', '*', '-r\d+.apk$', 'Alpine', true),
    ('Arch', '*', '.pkg.tar.zst$', 'Arch Linux', true);
