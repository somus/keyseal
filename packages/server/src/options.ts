import { characters } from "./job-input.js";
import type { KeySealOptions } from "./keyseal.js";
import { parseSemver } from "./semver.js";

const ACCENT_COLOR = /^#[0-9A-Fa-f]{6}$/;
// Unreserved characters only: the helper compares the document URL with
// the job URL it parsed, which re-encodes anything else and resolves . and
// .. segments.
const BASE_PATH = /^(?:\/(?!\.\.?(?:\/|$))[A-Za-z0-9._~-]+)*$/;

/** WHATWG URL serialises every IP host as dotted decimal or bracketed IPv6. */
function isIpLiteral(hostname: string): boolean {
  return hostname.startsWith("[") || /^[0-9.]+$/.test(hostname);
}

function isLocalhost(hostname: string): boolean {
  return hostname === "localhost" || hostname.endsWith(".localhost");
}

/** Throws a TypeError for invalid options; returns the parsed `minHelperVersion`. */
export function checkOptions(
  options: KeySealOptions,
  basePath: string
): ReturnType<typeof parseSemver> {
  // Protocol section 4: the helper refuses any other origin.
  const origin = new URL(options.origin);
  const { hostname } = origin;
  const insecure =
    options.allowInsecureOrigin === true &&
    origin.protocol === "http:" &&
    (hostname === "localhost" || hostname === "127.0.0.1");
  if (
    origin.origin !== options.origin ||
    !(
      insecure ||
      (origin.protocol === "https:" &&
        !isIpLiteral(hostname) &&
        !isLocalhost(hostname))
    )
  ) {
    throw new TypeError(
      "origin must be a bare https origin on a domain name, such as https://example.org"
    );
  }
  if (!BASE_PATH.test(basePath)) {
    throw new TypeError(
      "basePath must be empty or /-separated segments of letters, digits, . _ ~ and -, other than . and .."
    );
  }
  const minVersion =
    options.minHelperVersion === undefined
      ? null
      : parseSemver(options.minHelperVersion);
  if (options.minHelperVersion !== undefined && !minVersion) {
    throw new TypeError("minHelperVersion must be a SemVer version");
  }
  const { branding } = options;
  if (branding) {
    const length =
      typeof branding.name === "string" ? characters(branding.name) : 0;
    if (length < 1 || length > 64) {
      throw new TypeError("branding.name must be 1 to 64 characters");
    }
    if (
      branding.icon !== undefined &&
      new URL(branding.icon).origin !== options.origin
    ) {
      throw new TypeError(
        "branding.icon must be an absolute URL on the origin"
      );
    }
    if (
      branding.accentColor !== undefined &&
      !ACCENT_COLOR.test(branding.accentColor)
    ) {
      throw new TypeError("branding.accentColor must be #rrggbb");
    }
    if (
      branding.translucent !== undefined &&
      typeof branding.translucent !== "boolean"
    ) {
      throw new TypeError("branding.translucent must be a boolean");
    }
  }
  return minVersion;
}
