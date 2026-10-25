/** SemVer 2.0.0 parsing and precedence, for `X-KeySeal-Version` against the minimum. */

const SEMVER =
  /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-((?:0|[1-9]\d*|\d*[A-Za-z-][0-9A-Za-z-]*)(?:\.(?:0|[1-9]\d*|\d*[A-Za-z-][0-9A-Za-z-]*))*))?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$/;

interface Version {
  core: [number, number, number];
  prerelease: string[];
}

export function parseSemver(value: string): Version | null {
  const match = SEMVER.exec(value);
  if (!match) {
    return null;
  }
  return {
    core: [Number(match[1]), Number(match[2]), Number(match[3])],
    prerelease: match[4] ? match[4].split(".") : [],
  };
}

function compareIdentifiers(a: string, b: string): number {
  const aNumeric = /^\d+$/.test(a);
  const bNumeric = /^\d+$/.test(b);
  if (aNumeric && bNumeric) {
    return Math.sign(Number(a) - Number(b));
  }
  if (aNumeric !== bNumeric) {
    return aNumeric ? -1 : 1;
  }
  if (a === b) {
    return 0;
  }
  return a < b ? -1 : 1;
}

/** Negative, zero or positive as `a` has lower, equal or higher precedence than `b`. */
export function compareSemver(a: Version, b: Version): number {
  for (let index = 0; index < 3; index += 1) {
    const difference = a.core[index]! - b.core[index]!;
    if (difference !== 0) {
      return Math.sign(difference);
    }
  }
  // A pre-release has lower precedence than its release.
  if (a.prerelease.length === 0 || b.prerelease.length === 0) {
    return Math.sign(b.prerelease.length - a.prerelease.length);
  }
  const length = Math.min(a.prerelease.length, b.prerelease.length);
  for (let index = 0; index < length; index += 1) {
    const difference = compareIdentifiers(
      a.prerelease[index]!,
      b.prerelease[index]!
    );
    if (difference !== 0) {
      return difference;
    }
  }
  return Math.sign(a.prerelease.length - b.prerelease.length);
}
