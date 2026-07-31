//! Semantic version comparison shared across backends.
//!
//! Several code paths need to order package versions to pick the "latest"
//! one (self-upgrade selection, pacman repo metadata, etc.). A plain
//! lexicographic string comparison is wrong once any numeric component
//! reaches double digits: `"2.6.10" < "2.6.9"` byte-wise, so 2.6.9 would be
//! treated as newer than 2.6.10/2.6.11 forever.
//!
//! [`compare_versions`] compares versions semantically: it splits each
//! version into numeric and non-numeric segments and compares them
//! component-by-component, numerically where both sides are numeric and
//! lexicographically otherwise. It tolerates a package-release suffix
//! (`2.6.9-1`) and epoch prefixes (`1:2.6.9-1`) so it works for pacman
//! `pkgver` strings as well as plain dotted semver.

use std::cmp::Ordering;

/// Compare two version strings semantically.
///
/// Returns `Ordering::Greater` when `a` is newer than `b`.
///
/// Examples:
/// - `compare_versions("2.6.10", "2.6.9") == Greater`
/// - `compare_versions("2.6.11-1", "2.6.9-1") == Greater`
/// - `compare_versions("2.6.9", "2.6.9") == Equal`
pub fn compare_versions(a: &str, b: &str) -> Ordering {
    let a_parts = split_version(a);
    let b_parts = split_version(b);

    for i in 0..a_parts.len().max(b_parts.len()) {
        let a_part = a_parts.get(i).map(String::as_str).unwrap_or("0");
        let b_part = b_parts.get(i).map(String::as_str).unwrap_or("0");

        match (a_part.parse::<u64>(), b_part.parse::<u64>()) {
            (Ok(a_num), Ok(b_num)) => match a_num.cmp(&b_num) {
                Ordering::Equal => continue,
                ord => return ord,
            },
            _ => match a_part.cmp(b_part) {
                Ordering::Equal => continue,
                ord => return ord,
            },
        }
    }

    Ordering::Equal
}

/// Split a version string into comparable segments.
///
/// An optional epoch prefix (`N:`) is stripped first. The remainder is split
/// on `.`, `-`, `_`, and `+` so that `2.6.9-1` becomes `["2", "6", "9", "1"]`
/// and `1.0rc1` stays a single trailing segment compared lexicographically.
fn split_version(version: &str) -> Vec<String> {
    // Strip epoch prefix (e.g. "1:2.6.9-1" -> "2.6.9-1").
    let without_epoch = match version.split_once(':') {
        Some((epoch, rest)) if !epoch.is_empty() && epoch.chars().all(|c| c.is_ascii_digit()) => {
            rest
        },
        _ => version,
    };

    without_epoch
        .split(['.', '-', '_', '+'])
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn double_digit_minor_sorts_newer() {
        // The regression: lexicographically "2.6.10" < "2.6.9".
        assert_eq!(compare_versions("2.6.10", "2.6.9"), Ordering::Greater);
        assert_eq!(compare_versions("2.6.11", "2.6.9"), Ordering::Greater);
        assert_eq!(compare_versions("2.6.9", "2.6.10"), Ordering::Less);
    }

    #[test]
    fn pkgrel_suffix_handled() {
        assert_eq!(compare_versions("2.6.10-1", "2.6.9-1"), Ordering::Greater);
        assert_eq!(compare_versions("2.6.11-1", "2.6.10-1"), Ordering::Greater);
        assert_eq!(compare_versions("2.6.9-2", "2.6.9-1"), Ordering::Greater);
    }

    #[test]
    fn equal_versions() {
        assert_eq!(compare_versions("2.6.9", "2.6.9"), Ordering::Equal);
        assert_eq!(compare_versions("2.6.9-1", "2.6.9-1"), Ordering::Equal);
    }

    #[test]
    fn missing_components_treated_as_zero() {
        assert_eq!(compare_versions("2.6", "2.6.0"), Ordering::Equal);
        assert_eq!(compare_versions("2.6.1", "2.6"), Ordering::Greater);
    }

    #[test]
    fn epoch_prefix_stripped() {
        assert_eq!(compare_versions("1:2.6.10-1", "2.6.9-1"), Ordering::Greater);
    }

    #[test]
    fn major_version_bumps() {
        assert_eq!(compare_versions("3.0.0", "2.6.99"), Ordering::Greater);
        assert_eq!(compare_versions("10.0.0", "9.9.9"), Ordering::Greater);
    }
}
