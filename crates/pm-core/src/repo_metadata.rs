//! Pure Rust repository metadata generation.
//!
//! Replaces external tools: reprepro, createrepo_c, apk index, repo-add.
//! All package parsing and metadata generation is done in pure Rust,
//! using only the GPG binary for signing (via the `gpg` module).

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::path::Path;

use md5::Md5;
use sha1::Sha1;
use sha2::{Digest, Sha256};

// ===== Helpers =====

/// File checksums for apt Release and Packages files.
struct FileChecksums {
    md5: String,
    sha1: String,
    sha256: String,
    size: u64,
}

/// Compute MD5, SHA1, and SHA256 of a byte slice.
fn compute_data_checksums(data: &[u8]) -> FileChecksums {
    let mut md5 = Md5::new();
    md5.update(data);

    let mut sha1 = Sha1::new();
    sha1.update(data);

    let mut sha256 = Sha256::new();
    sha256.update(data);

    FileChecksums {
        md5: hex::encode(md5.finalize()),
        sha1: hex::encode(sha1.finalize()),
        sha256: hex::encode(sha256.finalize()),
        size: data.len() as u64,
    }
}

/// Compute MD5, SHA1, and SHA256 of a file.
fn compute_file_checksums(path: &str) -> Result<FileChecksums, anyhow::Error> {
    let data = std::fs::read(path)?;
    Ok(compute_data_checksums(&data))
}

/// Compute SHA256 of a file, returning hex-encoded digest.
fn compute_sha256_file(path: &str) -> Result<String, anyhow::Error> {
    let data = std::fs::read(path)?;
    let mut hasher = Sha256::new();
    hasher.update(&data);
    Ok(hex::encode(hasher.finalize()))
}

/// Decompress tar data based on extension (.gz, .xz, .zst, or uncompressed).
fn decompress_tar(data: &[u8], name: &str) -> Result<Vec<u8>, anyhow::Error> {
    if name.ends_with(".gz") {
        let mut decoder = flate2::read::GzDecoder::new(data);
        let mut buf = Vec::new();
        decoder.read_to_end(&mut buf)?;
        Ok(buf)
    } else if name.ends_with(".xz") {
        let mut decoder = xz2::read::XzDecoder::new(data);
        let mut buf = Vec::new();
        decoder.read_to_end(&mut buf)?;
        Ok(buf)
    } else if name.ends_with(".zst") {
        Ok(zstd::decode_all(data)?)
    } else {
        Ok(data.to_vec())
    }
}

/// Gzip compress data.
fn gzip_compress(data: &[u8]) -> Result<Vec<u8>, anyhow::Error> {
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(data)?;
    Ok(encoder.finish()?)
}

/// XML-escape a string.
fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

// ===== AR archive parsing (for .deb) =====

/// A single entry in an ar archive.
struct ArEntry {
    name: String,
    data: Vec<u8>,
}

/// Parse an ar archive (used by .deb files).
fn parse_ar(data: &[u8]) -> Vec<ArEntry> {
    let mut entries = Vec::new();
    if data.len() < 8 || &data[..8] != b"!<arch>\n" {
        return entries;
    }
    let mut pos = 8;
    while pos + 60 <= data.len() {
        let header = &data[pos..pos + 60];
        let name = String::from_utf8_lossy(&header[..16]).trim().to_string();
        let size_raw = String::from_utf8_lossy(&header[48..58]);
        let size_str = size_raw.trim();
        let size: usize = match size_str.parse() {
            Ok(s) => s,
            Err(_) => break,
        };
        pos += 60;
        if pos + size > data.len() {
            break;
        }
        let content = data[pos..pos + size].to_vec();
        entries.push(ArEntry {
            name,
            data: content,
        });
        pos += size;
        if size % 2 == 1 {
            pos += 1; // ar padding
        }
    }
    entries
}

// ===== Deb control parsing =====

/// Parsed .deb control fields.
#[derive(Debug, Default, Clone)]
pub struct DebControl {
    pub package: String,
    pub version: String,
    pub architecture: String,
    pub description: String,
    pub depends: String,
    pub installed_size: String,
    pub maintainer: String,
    pub section: String,
    pub priority: String,
    /// All raw fields from the control file.
    pub fields: BTreeMap<String, String>,
}

/// Parse RFC 822-style control fields.
fn parse_control_fields(content: &str) -> BTreeMap<String, String> {
    let mut fields = BTreeMap::new();
    let mut current_key = String::new();
    let mut current_val = String::new();

    for line in content.lines() {
        if line.is_empty() {
            continue;
        }
        if line.starts_with(' ') || line.starts_with('\t') {
            // Continuation of previous field.
            current_val.push('\n');
            current_val.push_str(line);
        } else if let Some(colon) = line.find(':') {
            if !current_key.is_empty() {
                fields.insert(current_key.clone(), current_val.trim().to_string());
            }
            current_key = line[..colon].trim().to_string();
            current_val = line[colon + 1..].trim().to_string();
        }
    }

    if !current_key.is_empty() {
        fields.insert(current_key, current_val.trim().to_string());
    }

    fields
}

/// Parse a .deb file's control section.
pub fn parse_deb_control(file_path: &str) -> Result<DebControl, anyhow::Error> {
    let data = std::fs::read(file_path)?;
    let ar_entries = parse_ar(&data);

    // Find control.tar.* entry.
    let control_entry = ar_entries
        .iter()
        .find(|e| e.name.starts_with("control.tar"))
        .ok_or_else(|| anyhow::anyhow!("No control.tar.* found in .deb"))?;

    let control_name = &control_entry.name;
    let control_data = &control_entry.data;

    // Decompress based on extension.
    let tar_data = decompress_tar(control_data, control_name)?;

    // Parse tar to find control file.
    let mut archive = tar::Archive::new(tar_data.as_slice());
    let mut control_content = String::new();

    for entry in archive.entries()? {
        let mut entry = entry?;
        let path = entry.path()?.display().to_string();
        let path = path.trim_start_matches("./").to_string();
        if path == "control" {
            entry.read_to_string(&mut control_content)?;
            break;
        }
    }

    if control_content.is_empty() {
        anyhow::bail!("No control file found in control.tar.*");
    }

    let fields = parse_control_fields(&control_content);

    Ok(DebControl {
        package: fields.get("Package").cloned().unwrap_or_default(),
        version: fields.get("Version").cloned().unwrap_or_default(),
        architecture: fields.get("Architecture").cloned().unwrap_or_default(),
        description: fields.get("Description").cloned().unwrap_or_default(),
        depends: fields.get("Depends").cloned().unwrap_or_default(),
        installed_size: fields.get("Installed-Size").cloned().unwrap_or_default(),
        maintainer: fields.get("Maintainer").cloned().unwrap_or_default(),
        section: fields.get("Section").cloned().unwrap_or_default(),
        priority: fields.get("Priority").cloned().unwrap_or_default(),
        fields,
    })
}

// ===== RPM header parsing =====

/// RPM header metadata.
#[derive(Debug, Default, Clone)]
pub struct RpmInfo {
    pub name: String,
    pub version: String,
    pub release: String,
    pub epoch: u32,
    pub arch: String,
    pub summary: String,
    pub description: String,
    pub url: String,
    pub license: String,
    pub build_time: u32,
    pub size: u32,
    pub archive_size: u32,
}

/// RPM header index entry: (tag, type, offset, count).
type RpmIndexEntry = (u32, u32, u32, u32);

/// Read an RPM header at the given offset.
/// Returns (index entries, data section).
fn read_rpm_header(
    data: &[u8],
    offset: usize,
) -> Result<(Vec<RpmIndexEntry>, Vec<u8>), anyhow::Error> {
    if offset + 16 > data.len() {
        anyhow::bail!("RPM header offset out of bounds");
    }

    // Check magic: 0x8e 0xad 0xe8.
    if data[offset..offset + 3] != [0x8e, 0xad, 0xe8] {
        anyhow::bail!("Invalid RPM header magic at offset {}", offset);
    }

    let num_entries = u32::from_be_bytes(data[offset + 8..offset + 12].try_into()?);
    let data_len = u32::from_be_bytes(data[offset + 12..offset + 16].try_into()?);

    let index_start = offset + 16;
    let data_start = index_start + 16 * num_entries as usize;

    if data_start + data_len as usize > data.len() {
        anyhow::bail!("RPM header data extends beyond file");
    }

    let mut entries = Vec::with_capacity(num_entries as usize);
    for i in 0..num_entries as usize {
        let e = index_start + i * 16;
        let tag = u32::from_be_bytes(data[e..e + 4].try_into()?);
        let type_ = u32::from_be_bytes(data[e + 4..e + 8].try_into()?);
        let off = u32::from_be_bytes(data[e + 8..e + 12].try_into()?);
        let count = u32::from_be_bytes(data[e + 12..e + 16].try_into()?);
        entries.push((tag, type_, off, count));
    }

    let header_data = data[data_start..data_start + data_len as usize].to_vec();
    Ok((entries, header_data))
}

/// Read a null-terminated string from header data at the given offset.
fn rpm_read_string(data: &[u8], offset: usize) -> String {
    if offset >= data.len() {
        return String::new();
    }
    let end = data[offset..]
        .iter()
        .position(|&b| b == 0)
        .unwrap_or(data.len() - offset);
    String::from_utf8_lossy(&data[offset..offset + end]).to_string()
}

/// Read a big-endian INT32 from header data at the given offset.
fn rpm_read_int32(data: &[u8], offset: usize) -> Option<u32> {
    if offset + 4 > data.len() {
        return None;
    }
    Some(u32::from_be_bytes(
        data[offset..offset + 4].try_into().ok()?,
    ))
}

/// Get a string-valued tag from the RPM header.
/// Types 6 (STRING) and 9 (I18NSTRING) are handled.
fn rpm_get_string(entries: &[RpmIndexEntry], data: &[u8], tag: u32) -> String {
    for &(t, ty, off, _) in entries {
        if t == tag && (ty == 6 || ty == 9) {
            return rpm_read_string(data, off as usize);
        }
    }
    String::new()
}

/// Get an INT32-valued tag from the RPM header.
fn rpm_get_int32(entries: &[RpmIndexEntry], data: &[u8], tag: u32) -> Option<u32> {
    for &(t, ty, off, _) in entries {
        if t == tag && ty == 4 {
            return rpm_read_int32(data, off as usize);
        }
    }
    None
}

/// Parse an RPM file's header to extract package metadata.
pub fn parse_rpm(file_path: &str) -> Result<RpmInfo, anyhow::Error> {
    let data = std::fs::read(file_path)?;

    if data.len() < 96 {
        anyhow::bail!("File too small to be an RPM");
    }

    // Verify RPM lead magic: 0xed 0xab 0xee 0xdb.
    if data[0..4] != [0xed, 0xab, 0xee, 0xdb] {
        anyhow::bail!("Invalid RPM lead magic");
    }

    // Skip 96-byte lead, read signature header size.
    let sig_offset = 96;
    if sig_offset + 16 > data.len() {
        anyhow::bail!("RPM file too small for signature header");
    }
    if data[sig_offset..sig_offset + 3] != [0x8e, 0xad, 0xe8] {
        anyhow::bail!("Invalid RPM signature header magic");
    }
    let sig_num_entries = u32::from_be_bytes(data[sig_offset + 8..sig_offset + 12].try_into()?);
    let sig_data_len = u32::from_be_bytes(data[sig_offset + 12..sig_offset + 16].try_into()?);
    let sig_header_size = 16 + 16 * sig_num_entries as usize + sig_data_len as usize;

    // Pad to 8-byte alignment for the main header.
    let total_after_sig = sig_offset + sig_header_size;
    let padding = (8 - (total_after_sig % 8)) % 8;
    let main_offset = total_after_sig + padding;

    // Read main header.
    let (entries, header_data) = read_rpm_header(&data, main_offset)?;

    // RPM tag constants (from rpmtag.h).
    const TAG_NAME: u32 = 1000;
    const TAG_VERSION: u32 = 1001;
    const TAG_RELEASE: u32 = 1002;
    const TAG_EPOCH: u32 = 1003;
    const TAG_SUMMARY: u32 = 1004;
    const TAG_DESCRIPTION: u32 = 1005;
    const TAG_BUILDTIME: u32 = 1006;
    const TAG_SIZE: u32 = 1009;
    const TAG_LICENSE: u32 = 1014;
    const TAG_URL: u32 = 1020;
    const TAG_ARCH: u32 = 1022;
    const TAG_ARCHIVESIZE: u32 = 1046;

    Ok(RpmInfo {
        name: rpm_get_string(&entries, &header_data, TAG_NAME),
        version: rpm_get_string(&entries, &header_data, TAG_VERSION),
        release: rpm_get_string(&entries, &header_data, TAG_RELEASE),
        epoch: rpm_get_int32(&entries, &header_data, TAG_EPOCH).unwrap_or(0),
        arch: rpm_get_string(&entries, &header_data, TAG_ARCH),
        summary: rpm_get_string(&entries, &header_data, TAG_SUMMARY),
        description: rpm_get_string(&entries, &header_data, TAG_DESCRIPTION),
        url: rpm_get_string(&entries, &header_data, TAG_URL),
        license: rpm_get_string(&entries, &header_data, TAG_LICENSE),
        build_time: rpm_get_int32(&entries, &header_data, TAG_BUILDTIME).unwrap_or(0),
        size: rpm_get_int32(&entries, &header_data, TAG_SIZE).unwrap_or(0),
        archive_size: rpm_get_int32(&entries, &header_data, TAG_ARCHIVESIZE).unwrap_or(0),
    })
}

// ===== APK parsing =====

/// APK package metadata from .PKGINFO.
#[derive(Debug, Default, Clone)]
pub struct ApkInfo {
    pub pkgname: String,
    pub pkgver: String,
    pub arch: String,
    pub size: u64,
    pub installed_size: u64,
    pub description: String,
    pub url: String,
    pub license: String,
    pub depends: String,
    pub provides: String,
    pub control_checksum: String,
}

/// Parse key = value format (used by .PKGINFO).
fn parse_keyvalue(content: &str) -> BTreeMap<String, String> {
    let mut fields = BTreeMap::new();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(eq) = line.find('=') {
            let key = line[..eq].trim().to_string();
            let val = line[eq + 1..].trim().to_string();
            if !key.is_empty() {
                fields.insert(key, val);
            }
        }
    }
    fields
}

/// Compute the APK control checksum (SHA256 of control tar entries).
/// The checksum covers all tar entries whose names start with `.` (control
/// entries like .PKGINFO, .SIGN.*), accumulated as raw tar bytes (header +
/// data + padding) from the decompressed gzip stream.
fn compute_apk_control_checksum(file_path: &str) -> Result<String, anyhow::Error> {
    let file = std::fs::File::open(file_path)?;
    let decoder = flate2::read::GzDecoder::new(file);
    let mut reader = std::io::BufReader::new(decoder);

    let mut hasher = Sha256::new();
    let mut header_buf = [0u8; 512];

    loop {
        match reader.read_exact(&mut header_buf) {
            Ok(()) => {},
            Err(ref e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(e.into()),
        }

        // End of archive marker.
        if header_buf.iter().all(|&b| b == 0) {
            break;
        }

        // Parse entry name (first 100 bytes, null-terminated).
        let name_end = header_buf[..100]
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(100);
        let name = String::from_utf8_lossy(&header_buf[..name_end]);

        // Parse entry size (octal ASCII at offset 124, 12 bytes).
        let size_raw = String::from_utf8_lossy(&header_buf[124..136]);
        let size_str = size_raw.trim_matches('\0').trim();
        let size = u64::from_str_radix(size_str, 8).unwrap_or(0);

        if name.starts_with('.') {
            // Control entry: accumulate raw bytes into checksum.
            hasher.update(header_buf);

            let mut remaining = size;
            let mut buf = [0u8; 8192];
            while remaining > 0 {
                let to_read = std::cmp::min(remaining as usize, buf.len());
                reader.read_exact(&mut buf[..to_read])?;
                hasher.update(&buf[..to_read]);
                remaining -= to_read as u64;
            }

            // Include tar padding.
            let padding = (512 - (size % 512)) % 512;
            if padding > 0 {
                let mut pad = vec![0u8; padding as usize];
                reader.read_exact(&mut pad)?;
                hasher.update(&pad);
            }
        } else {
            // Non-control entry: stop.
            break;
        }
    }

    Ok(format!("Q1{}", hex::encode(hasher.finalize())))
}

/// Parse an .apk file's .PKGINFO.
pub fn parse_apk(file_path: &str) -> Result<ApkInfo, anyhow::Error> {
    let file = std::fs::File::open(file_path)?;
    let decoder = flate2::read::GzDecoder::new(file);
    let mut archive = tar::Archive::new(decoder);

    let mut pkginfo_content = String::new();

    for entry in archive.entries()? {
        let mut entry = entry?;
        let path = entry.path()?.display().to_string();
        let path = path.trim_start_matches("./").to_string();
        if path == ".PKGINFO" {
            entry.read_to_string(&mut pkginfo_content)?;
            break;
        }
    }

    if pkginfo_content.is_empty() {
        anyhow::bail!("No .PKGINFO in .apk file");
    }

    let fields = parse_keyvalue(&pkginfo_content);
    let file_size = std::fs::metadata(file_path)?.len();
    let checksum = compute_apk_control_checksum(file_path).unwrap_or_default();

    Ok(ApkInfo {
        pkgname: fields.get("pkgname").cloned().unwrap_or_default(),
        pkgver: fields.get("pkgver").cloned().unwrap_or_default(),
        arch: fields.get("arch").cloned().unwrap_or_default(),
        size: file_size,
        installed_size: fields
            .get("installed_size")
            .and_then(|s| s.parse().ok())
            .unwrap_or(0),
        description: fields.get("pkgdesc").cloned().unwrap_or_default(),
        url: fields.get("url").cloned().unwrap_or_default(),
        license: fields.get("license").cloned().unwrap_or_default(),
        depends: fields.get("depend").cloned().unwrap_or_default(),
        provides: fields.get("provides").cloned().unwrap_or_default(),
        control_checksum: checksum,
    })
}

// ===== Pacman parsing =====

/// Pacman package metadata from .PKGINFO.
#[derive(Debug, Default, Clone)]
pub struct PacmanInfo {
    pub pkgname: String,
    pub pkgver: String,
    pub arch: String,
    pub description: String,
    pub url: String,
    pub license: String,
    pub size: u64,
    pub csize: u64,
    pub builddate: u64,
    pub sha256: String,
    pub depends: String,
}

/// Parse a .pkg.tar.zst file's .PKGINFO.
pub fn parse_pacman_pkg(file_path: &str) -> Result<PacmanInfo, anyhow::Error> {
    let file = std::fs::File::open(file_path)?;
    let decoder = zstd::Decoder::new(file)?;
    let mut archive = tar::Archive::new(decoder);

    let mut pkginfo_content = String::new();

    for entry in archive.entries()? {
        let mut entry = entry?;
        let path = entry.path()?.display().to_string();
        let path = path.trim_start_matches("./").to_string();
        if path == ".PKGINFO" {
            entry.read_to_string(&mut pkginfo_content)?;
            break;
        }
    }

    if pkginfo_content.is_empty() {
        anyhow::bail!("No .PKGINFO in .pkg.tar.zst");
    }

    let fields = parse_keyvalue(&pkginfo_content);
    let file_meta = std::fs::metadata(file_path)?;
    let csize = file_meta.len();
    let sha256 = compute_sha256_file(file_path)?;

    Ok(PacmanInfo {
        pkgname: fields.get("pkgname").cloned().unwrap_or_default(),
        pkgver: fields.get("pkgver").cloned().unwrap_or_default(),
        arch: fields.get("arch").cloned().unwrap_or_default(),
        description: fields.get("pkgdesc").cloned().unwrap_or_default(),
        url: fields.get("url").cloned().unwrap_or_default(),
        license: fields.get("license").cloned().unwrap_or_default(),
        size: fields.get("size").and_then(|s| s.parse().ok()).unwrap_or(0),
        csize,
        builddate: fields
            .get("builddate")
            .and_then(|s| s.parse().ok())
            .unwrap_or(0),
        sha256,
        depends: fields.get("depend").cloned().unwrap_or_default(),
    })
}

// ===== APT metadata generation =====

/// Generate apt repository metadata (Packages, Packages.gz, Release,
/// InRelease, Release.gpg) in pure Rust.
///
/// Replaces `reprepro includedeb`.
pub async fn generate_apt_metadata(repo_dir: &str, codename: &str) -> Result<(), anyhow::Error> {
    use crate::gpg;

    let apt_root = format!("{repo_dir}/apt");
    let pool_dir = format!("{apt_root}/pool");
    let dists_dir = format!("{apt_root}/dists/{codename}");
    let binary_dir = format!("{dists_dir}/main/binary-amd64");

    // Ensure directories exist.
    std::fs::create_dir_all(&binary_dir)?;

    // Scan pool for .deb files matching this codename.
    //
    // The agent's .deb assets use filename tokens (`_u2404_`, `_u2204_`,
    // `_u2604_`, `_debian12_`, `_debian13_`) rather than the apt suite
    // codename. Map the codename back to its token(s) so the pool scan
    // includes the file in the correct dists/<codename> index.
    let mut deb_files: Vec<String> = Vec::new();
    let codename_lower = codename.to_ascii_lowercase();
    let static_tokens: &[&str] = match codename_lower.as_str() {
        "noble" => &["_u2404_", "noble"],
        "jammy" => &["_u2204_", "jammy"],
        "resolute" => &["_u2604_", "resolute"],
        "bookworm" => &["_debian12_", "bookworm"],
        "trixie" => &["_debian13_", "trixie"],
        _ => &[],
    };
    if let Ok(entries) = std::fs::read_dir(&pool_dir) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if name.ends_with(".deb") {
                let lower = name.to_ascii_lowercase();
                let matches_token = !static_tokens.is_empty()
                    && static_tokens.iter().any(|t| lower.contains(t));
                let matches_bare = lower.contains(&codename_lower);
                if matches_token || matches_bare {
                    deb_files.push(entry.path().to_string_lossy().to_string());
                }
            }
        }
    }
    deb_files.sort();

    // Build Packages file.
    let mut packages_content = String::new();

    for deb_path in &deb_files {
        match parse_deb_control(deb_path) {
            Ok(control) => {
                let filename = Path::new(deb_path)
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("package.deb");
                let checksums = compute_file_checksums(deb_path)?;

                // Write all control fields from the .deb.
                for (key, val) in &control.fields {
                    packages_content.push_str(&format!("{key}: {val}\n"));
                }

                // Add repo-specific fields.
                packages_content.push_str(&format!("Filename: pool/{filename}\n"));
                packages_content.push_str(&format!("Size: {}\n", checksums.size));
                packages_content.push_str(&format!("MD5sum: {}\n", checksums.md5));
                packages_content.push_str(&format!("SHA1: {}\n", checksums.sha1));
                packages_content.push_str(&format!("SHA256: {}\n", checksums.sha256));
                packages_content.push('\n');
            },
            Err(e) => {
                tracing::warn!(error = %e, file = %deb_path, "Failed to parse .deb control");
            },
        }
    }

    // Write Packages file.
    let packages_path = format!("{binary_dir}/Packages");
    std::fs::write(&packages_path, &packages_content)?;

    // Write Packages.gz (gzip compressed).
    let packages_gz_path = format!("{binary_dir}/Packages.gz");
    let gz_data = gzip_compress(packages_content.as_bytes())?;
    std::fs::write(&packages_gz_path, &gz_data)?;

    // Generate Release file.
    let release_path = format!("{dists_dir}/Release");
    let release_content = generate_apt_release(&binary_dir, codename)?;
    std::fs::write(&release_path, &release_content)?;

    // Sign Release → InRelease (clearsigned) and Release.gpg (detached).
    let inrelease_path = format!("{dists_dir}/InRelease");
    let release_gpg_path = format!("{dists_dir}/Release.gpg");

    if let Err(e) = gpg::sign_file_clearsign(&release_path, &inrelease_path).await {
        tracing::warn!(error = %e, "GPG clearsign InRelease failed (non-fatal but clients will not trust this repo)");
    }
    if let Err(e) = gpg::sign_file_detached(&release_path, &release_gpg_path, true).await {
        tracing::warn!(error = %e, "GPG detached sign Release.gpg failed (non-fatal but clients will not trust this repo)");
    }

    Ok(())
}

/// Generate the apt Release file content.
fn generate_apt_release(binary_dir: &str, codename: &str) -> Result<String, anyhow::Error> {
    let date = chrono::Utc::now()
        .format("%a, %d %b %Y %H:%M:%S +0000")
        .to_string();

    let mut content = String::new();
    content.push_str("Origin: Linux Patch Manager\n");
    content.push_str("Label: Linux Patch Manager\n");
    content.push_str(&format!("Suite: {codename}\n"));
    content.push_str(&format!("Codename: {codename}\n"));
    content.push_str(&format!("Date: {date}\n"));
    content.push_str("Architectures: amd64\n");
    content.push_str("Components: main\n");
    content.push_str("Description: Linux Patch Manager Package Repository\n");

    // Compute checksums of files in the distribution.
    let files_to_hash = [
        (
            "main/binary-amd64/Packages",
            format!("{binary_dir}/Packages"),
        ),
        (
            "main/binary-amd64/Packages.gz",
            format!("{binary_dir}/Packages.gz"),
        ),
    ];

    let mut md5_lines = String::from("MD5Sum:\n");
    let mut sha1_lines = String::from("SHA1:\n");
    let mut sha256_lines = String::from("SHA256:\n");

    for (rel_path, abs_path) in &files_to_hash {
        if let Ok(checksums) = compute_file_checksums(abs_path) {
            md5_lines.push_str(&format!(
                " {} {} {}\n",
                checksums.md5, checksums.size, rel_path
            ));
            sha1_lines.push_str(&format!(
                " {} {} {}\n",
                checksums.sha1, checksums.size, rel_path
            ));
            sha256_lines.push_str(&format!(
                " {} {} {}\n",
                checksums.sha256, checksums.size, rel_path
            ));
        }
    }

    content.push_str(&md5_lines);
    content.push_str(&sha1_lines);
    content.push_str(&sha256_lines);

    Ok(content)
}

// ===== DNF metadata generation =====

/// Generate DNF (RPM) repository metadata (primary.xml.gz, filelists.xml.gz,
/// repomd.xml) in pure Rust.
///
/// Replaces `createrepo_c --update`.
pub async fn generate_dnf_metadata(repo_dir: &str) -> Result<(), anyhow::Error> {
    let repo_root = format!("{repo_dir}/dnf/el9");
    let packages_dir = format!("{repo_root}/Packages");
    let repodata_dir = format!("{repo_root}/repodata");

    std::fs::create_dir_all(&repodata_dir)?;

    // Scan for .rpm files.
    let mut rpm_files: Vec<String> = Vec::new();
    if let Ok(entries) = std::fs::read_dir(&packages_dir) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if name.ends_with(".rpm") {
                rpm_files.push(entry.path().to_string_lossy().to_string());
            }
        }
    }
    rpm_files.sort();

    // Generate primary.xml.
    let mut primary_body = String::new();
    let mut filelists_body = String::new();

    for rpm_path in &rpm_files {
        match parse_rpm(rpm_path) {
            Ok(info) => {
                let filename = Path::new(rpm_path)
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("package.rpm");
                let sha256 = compute_sha256_file(rpm_path)?;
                let file_size = std::fs::metadata(rpm_path)?.len();
                let file_time = std::fs::metadata(rpm_path)?
                    .modified()
                    .ok()
                    .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                    .map(|d| d.as_secs())
                    .unwrap_or(0);

                primary_body.push_str(&format!(
                    "  <package type=\"rpm\">\n\
                     \x20   <name>{name}</name>\n\
                     \x20   <arch>{arch}</arch>\n\
                     \x20   <version epoch=\"{epoch}\" ver=\"{ver}\" rel=\"{rel}\"/>\n\
                     \x20   <summary>{summary}</summary>\n\
                     \x20   <description>{desc}</description>\n\
                     \x20   <url>{url}</url>\n\
                     \x20   <time file=\"{file_time}\" build=\"{build_time}\"/>\n\
                     \x20   <size package=\"{pkg_size}\" installed=\"{inst_size}\" archive=\"{arch_size}\"/>\n\
                     \x20   <location href=\"Packages/{filename}\"/>\n\
                     \x20   <checksum type=\"sha256\" pkgid=\"YES\">{sha256}</checksum>\n\
                     \x20 </package>\n",
                    name = xml_escape(&info.name),
                    arch = xml_escape(&info.arch),
                    epoch = info.epoch,
                    ver = xml_escape(&info.version),
                    rel = xml_escape(&info.release),
                    summary = xml_escape(&info.summary),
                    desc = xml_escape(&info.description),
                    url = xml_escape(&info.url),
                    file_time = file_time,
                    build_time = info.build_time,
                    pkg_size = file_size,
                    inst_size = info.size,
                    arch_size = info.archive_size,
                    filename = filename,
                    sha256 = sha256,
                ));

                filelists_body.push_str(&format!(
                    "  <package pkgid=\"{sha256}\" name=\"{name}\" arch=\"{arch}\">\n\
                     \x20   <version epoch=\"{epoch}\" ver=\"{ver}\" rel=\"{rel}\"/>\n\
                     \x20 </package>\n",
                    sha256 = sha256,
                    name = xml_escape(&info.name),
                    arch = xml_escape(&info.arch),
                    epoch = info.epoch,
                    ver = xml_escape(&info.version),
                    rel = xml_escape(&info.release),
                ));
            },
            Err(e) => {
                tracing::warn!(error = %e, "Failed to parse RPM");
            },
        }
    }

    let pkg_count = rpm_files.len();
    let primary_xml = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <metadata xmlns=\"http://linux.duke.edu/metadata/common\" \
         xmlns:rpm=\"http://linux.duke.edu/metadata/rpm\" \
         packages=\"{pkg_count}\">\n{primary_body}</metadata>\n"
    );
    let filelists_xml = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <filelists xmlns=\"http://linux.duke.edu/metadata/filelists\" \
         packages=\"{pkg_count}\">\n{filelists_body}</filelists>\n"
    );

    // Gzip compress metadata files.
    let primary_gz = gzip_compress(primary_xml.as_bytes())?;
    let filelists_gz = gzip_compress(filelists_xml.as_bytes())?;

    let primary_gz_path = format!("{repodata_dir}/primary.xml.gz");
    let filelists_gz_path = format!("{repodata_dir}/filelists.xml.gz");
    std::fs::write(&primary_gz_path, &primary_gz)?;
    std::fs::write(&filelists_gz_path, &filelists_gz)?;

    // Generate repomd.xml with checksums.
    let timestamp = chrono::Utc::now().timestamp();
    let primary_ck = compute_data_checksums(&primary_gz);
    let primary_open_ck = compute_data_checksums(primary_xml.as_bytes());
    let filelists_ck = compute_data_checksums(&filelists_gz);
    let filelists_open_ck = compute_data_checksums(filelists_xml.as_bytes());

    let repomd_xml = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <repomd xmlns=\"http://linux.duke.edu/metadata/repo\">\n\
         \x20 <revision>{timestamp}</revision>\n\
         \x20 <data type=\"primary\">\n\
         \x20   <checksum type=\"sha256\">{p_ck}</checksum>\n\
         \x20   <open-checksum type=\"sha256\">{p_ok}</open-checksum>\n\
         \x20   <location href=\"repodata/primary.xml.gz\"/>\n\
         \x20   <timestamp>{timestamp}</timestamp>\n\
         \x20   <size>{p_sz}</size>\n\
         \x20   <open-size>{p_osz}</open-size>\n\
         \x20 </data>\n\
         \x20 <data type=\"filelists\">\n\
         \x20   <checksum type=\"sha256\">{f_ck}</checksum>\n\
         \x20   <open-checksum type=\"sha256\">{f_ok}</open-checksum>\n\
         \x20   <location href=\"repodata/filelists.xml.gz\"/>\n\
         \x20   <timestamp>{timestamp}</timestamp>\n\
         \x20   <size>{f_sz}</size>\n\
         \x20   <open-size>{f_osz}</open-size>\n\
         \x20 </data>\n\
         </repomd>\n",
        timestamp = timestamp,
        p_ck = primary_ck.sha256,
        p_ok = primary_open_ck.sha256,
        p_sz = primary_ck.size,
        p_osz = primary_open_ck.size,
        f_ck = filelists_ck.sha256,
        f_ok = filelists_open_ck.sha256,
        f_sz = filelists_ck.size,
        f_osz = filelists_open_ck.size,
    );

    let repomd_path = format!("{repodata_dir}/repomd.xml");
    std::fs::write(&repomd_path, &repomd_xml)?;

    Ok(())
}

// ===== APK metadata generation =====

/// Generate APK repository index (APKINDEX.tar.gz) in pure Rust.
///
/// Replaces `apk index`.
pub async fn generate_apk_metadata(repo_dir: &str) -> Result<(), anyhow::Error> {
    let apk_dir = format!("{repo_dir}/apk/v3.21");

    // Scan for .apk files.
    let mut apk_files: Vec<String> = Vec::new();
    if let Ok(entries) = std::fs::read_dir(&apk_dir) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if name.ends_with(".apk") {
                apk_files.push(entry.path().to_string_lossy().to_string());
            }
        }
    }
    apk_files.sort();

    // Build APKINDEX content.
    let mut apkindex = String::new();

    for apk_path in &apk_files {
        match parse_apk(apk_path) {
            Ok(info) => {
                apkindex.push_str(&format!("C:{}\n", info.control_checksum));
                apkindex.push_str(&format!("P:{}\n", info.pkgname));
                apkindex.push_str(&format!("V:{}\n", info.pkgver));
                apkindex.push_str(&format!("A:{}\n", info.arch));
                apkindex.push_str(&format!("S:{}\n", info.size));
                apkindex.push_str(&format!("I:{}\n", info.installed_size));
                if !info.depends.is_empty() {
                    apkindex.push_str(&format!("T:{}\n", info.depends));
                }
                if !info.provides.is_empty() {
                    apkindex.push_str(&format!("D:{}\n", info.provides));
                }
                if !info.url.is_empty() {
                    apkindex.push_str(&format!("U:{}\n", info.url));
                }
                if !info.license.is_empty() {
                    apkindex.push_str(&format!("F:{}\n", info.license));
                }
                apkindex.push('\n');
            },
            Err(e) => {
                tracing::warn!(error = %e, "Failed to parse APK");
            },
        }
    }

    // Create APKINDEX.tar.gz (tar with APKINDEX_DESCRIPTION and APKINDEX).
    let mut tar_builder = tar::Builder::new(Vec::new());

    // Add APKINDEX_DESCRIPTION.
    let desc = b"Linux Patch Manager Repository\n";
    let mut header = tar::Header::new_gnu();
    header.set_path(Path::new("APKINDEX_DESCRIPTION"))?;
    header.set_size(desc.len() as u64);
    header.set_mode(0o644);
    header.set_entry_type(tar::EntryType::Regular);
    header.set_mtime(0);
    header.set_cksum();
    let mut desc_cursor = std::io::Cursor::new(desc);
    tar_builder.append(&header, &mut desc_cursor)?;

    // Add APKINDEX.
    let mut header2 = tar::Header::new_gnu();
    header2.set_path(Path::new("APKINDEX"))?;
    header2.set_size(apkindex.len() as u64);
    header2.set_mode(0o644);
    header2.set_entry_type(tar::EntryType::Regular);
    header2.set_mtime(0);
    header2.set_cksum();
    let mut index_cursor = std::io::Cursor::new(apkindex.as_bytes());
    tar_builder.append(&header2, &mut index_cursor)?;

    let tar_data = tar_builder.into_inner()?;

    // Gzip compress.
    let gz_data = gzip_compress(&tar_data)?;

    let apkindex_path = format!("{apk_dir}/APKINDEX.tar.gz");
    std::fs::write(&apkindex_path, &gz_data)?;

    Ok(())
}

// ===== Pacman metadata generation =====

/// Generate pacman repo database (.db.tar.zst) in pure Rust.
///
/// Replaces `repo-add`.
pub async fn generate_pacman_metadata(repo_dir: &str) -> Result<(), anyhow::Error> {
    let pacman_dir = format!("{repo_dir}/pacman/x86_64");
    let db_path = format!("{pacman_dir}/lpa-repo.db.tar.zst");

    // Scan for .pkg.tar.zst files (exclude .sig and .db.tar.zst).
    let mut pkg_files: Vec<String> = Vec::new();
    if let Ok(entries) = std::fs::read_dir(&pacman_dir) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if name.ends_with(".pkg.tar.zst")
                && !name.ends_with(".sig")
                && !name.ends_with(".db.tar.zst")
            {
                pkg_files.push(entry.path().to_string_lossy().to_string());
            }
        }
    }
    pkg_files.sort();

    // Build tar archive with package database entries.
    let mut tar_builder = tar::Builder::new(Vec::new());

    for pkg_path in &pkg_files {
        match parse_pacman_pkg(pkg_path) {
            Ok(info) => {
                let dir_name = format!("{}-{}", info.pkgname, info.pkgver);

                // Add directory entry.
                let mut dir_header = tar::Header::new_gnu();
                dir_header.set_path(Path::new(&format!("{dir_name}/")))?;
                dir_header.set_size(0);
                dir_header.set_mode(0o755);
                dir_header.set_entry_type(tar::EntryType::Directory);
                dir_header.set_mtime(info.builddate);
                dir_header.set_cksum();
                let mut empty = std::io::empty();
                tar_builder.append(&dir_header, &mut empty)?;

                // Generate desc file content.
                let mut desc = String::new();
                desc.push_str(&format!("%NAME%\n{}\n\n", info.pkgname));
                desc.push_str(&format!("%VERSION%\n{}\n\n", info.pkgver));
                if !info.description.is_empty() {
                    desc.push_str(&format!("%DESC%\n{}\n\n", info.description));
                }
                desc.push_str(&format!("%ARCH%\n{}\n\n", info.arch));
                if !info.url.is_empty() {
                    desc.push_str(&format!("%URL%\n{}\n\n", info.url));
                }
                if !info.license.is_empty() {
                    desc.push_str(&format!("%LICENSE%\n{}\n\n", info.license));
                }
                desc.push_str(&format!("%BUILDDATE%\n{}\n\n", info.builddate));
                desc.push_str(&format!("%SIZE%\n{}\n\n", info.size));
                desc.push_str(&format!("%CSIZE%\n{}\n\n", info.csize));
                desc.push_str(&format!("%ISIZE%\n{}\n\n", info.size));
                desc.push_str(&format!("%SHA256SUM%\n{}\n\n", info.sha256));
                if !info.depends.is_empty() {
                    desc.push_str(&format!("%DEPENDS%\n{}\n\n", info.depends));
                }

                // Add desc file entry.
                let mut file_header = tar::Header::new_gnu();
                file_header.set_path(Path::new(&format!("{dir_name}/desc")))?;
                file_header.set_size(desc.len() as u64);
                file_header.set_mode(0o644);
                file_header.set_entry_type(tar::EntryType::Regular);
                file_header.set_mtime(info.builddate);
                file_header.set_cksum();
                let mut desc_cursor = std::io::Cursor::new(desc.as_bytes());
                tar_builder.append(&file_header, &mut desc_cursor)?;
            },
            Err(e) => {
                tracing::warn!(error = %e, "Failed to parse pacman package");
            },
        }
    }

    let tar_data = tar_builder.into_inner()?;

    // Compress with zstd (level 19, matching repo-add default).
    let zstd_data = zstd::encode_all(tar_data.as_slice(), 19)?;

    std::fs::write(&db_path, &zstd_data)?;

    Ok(())
}

// ===== Tests =====

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_ar_empty() {
        let entries = parse_ar(b"");
        assert!(entries.is_empty());
    }

    #[test]
    fn test_parse_ar_invalid_magic() {
        let entries = parse_ar(b"NOTANARFILE\nrest of data");
        assert!(entries.is_empty());
    }

    #[test]
    fn test_parse_control_fields_basic() {
        let content =
            "Package: test\nVersion: 1.0\nArchitecture: amd64\nDescription: Test package\n";
        let fields = parse_control_fields(content);
        assert_eq!(fields.get("Package"), Some(&"test".to_string()));
        assert_eq!(fields.get("Version"), Some(&"1.0".to_string()));
        assert_eq!(fields.get("Architecture"), Some(&"amd64".to_string()));
        assert_eq!(fields.get("Description"), Some(&"Test package".to_string()));
    }

    #[test]
    fn test_parse_control_fields_multiline() {
        let content = "Package: test\nDescription: Line one\n Line two\nVersion: 1.0\n";
        let fields = parse_control_fields(content);
        assert_eq!(fields.get("Package"), Some(&"test".to_string()));
        assert!(fields.get("Description").unwrap().contains("Line one"));
        assert!(fields.get("Description").unwrap().contains("Line two"));
        assert_eq!(fields.get("Version"), Some(&"1.0".to_string()));
    }

    #[test]
    fn test_parse_keyvalue_basic() {
        let content = "pkgname = test\npkgver = 1.0.0\narch = x86_64\n";
        let fields = parse_keyvalue(content);
        assert_eq!(fields.get("pkgname"), Some(&"test".to_string()));
        assert_eq!(fields.get("pkgver"), Some(&"1.0.0".to_string()));
        assert_eq!(fields.get("arch"), Some(&"x86_64".to_string()));
    }

    #[test]
    fn test_parse_keyvalue_comments() {
        let content = "# comment\npkgname = test\n# another\npkgver = 1.0\n";
        let fields = parse_keyvalue(content);
        assert_eq!(fields.get("pkgname"), Some(&"test".to_string()));
        assert_eq!(fields.get("pkgver"), Some(&"1.0".to_string()));
    }

    #[test]
    fn test_xml_escape() {
        assert_eq!(xml_escape("test"), "test");
        assert_eq!(xml_escape("a & b"), "a &amp; b");
        assert_eq!(xml_escape("a < b"), "a &lt; b");
        assert_eq!(xml_escape("a > b"), "a &gt; b");
        assert_eq!(xml_escape("\"quoted\""), "&quot;quoted&quot;");
    }

    #[test]
    fn test_compute_data_checksums() {
        let data = b"hello world";
        let checksums = compute_data_checksums(data);
        assert_eq!(checksums.size, 11);
        assert!(!checksums.md5.is_empty());
        assert!(!checksums.sha1.is_empty());
        assert!(!checksums.sha256.is_empty());
    }

    #[test]
    fn test_deb_control_default() {
        let control = DebControl::default();
        assert!(control.package.is_empty());
        assert!(control.version.is_empty());
    }

    #[test]
    fn test_rpm_info_default() {
        let info = RpmInfo::default();
        assert!(info.name.is_empty());
        assert_eq!(info.epoch, 0);
    }

    #[test]
    fn test_apk_info_default() {
        let info = ApkInfo::default();
        assert!(info.pkgname.is_empty());
        assert_eq!(info.size, 0);
    }

    #[test]
    fn test_pacman_info_default() {
        let info = PacmanInfo::default();
        assert!(info.pkgname.is_empty());
        assert_eq!(info.size, 0);
    }

    #[test]
    fn test_gzip_round_trip() {
        let data = b"test data for compression";
        let compressed = gzip_compress(data).unwrap();
        let mut decoder = flate2::read::GzDecoder::new(compressed.as_slice());
        let mut decompressed = Vec::new();
        decoder.read_to_end(&mut decompressed).unwrap();
        assert_eq!(data.as_slice(), decompressed.as_slice());
    }
}
