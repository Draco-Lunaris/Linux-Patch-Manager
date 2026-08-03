/**
 * Semantic version comparison — TypeScript port of pm-core's `compare_versions`.
 *
 * Splits each version into numeric and non-numeric segments and compares
 * component-by-component: numerically where both sides are numeric,
 * lexicographically otherwise. Tolerates package-release suffixes (`2.6.9-1`)
 * and epoch prefixes (`1:2.6.9-1`).
 *
 * @returns >0 if `a` is newer, <0 if `b` is newer, 0 if equal.
 */
export function compareVersions(a: string, b: string): number {
  const aParts = splitVersion(a)
  const bParts = splitVersion(b)
  const len = Math.max(aParts.length, bParts.length)

  for (let i = 0; i < len; i++) {
    const aPart = aParts[i] ?? '0'
    const bPart = bParts[i] ?? '0'
    const aNum = Number(aPart)
    const bNum = Number(bPart)
    const aIsNum = aPart !== '' && !Number.isNaN(aNum)
    const bIsNum = bPart !== '' && !Number.isNaN(bNum)

    if (aIsNum && bIsNum) {
      if (aNum !== bNum) return aNum - bNum
    } else {
      if (aPart !== bPart) return aPart < bPart ? -1 : 1
    }
  }

  return 0
}

function splitVersion(version: string): string[] {
  // Strip epoch prefix (e.g. "1:2.6.9-1" -> "2.6.9-1").
  const colonIdx = version.indexOf(':')
  let rest = version
  if (colonIdx > 0) {
    const epoch = version.slice(0, colonIdx)
    if (/^\d+$/.test(epoch)) {
      rest = version.slice(colonIdx + 1)
    }
  }

  // Split on . - _ +
  return rest.split(/[.\-_+]/).filter(s => s !== '')
}