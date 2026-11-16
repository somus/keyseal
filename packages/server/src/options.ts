import type { CertificateInspector } from "./certificates.js";
import { parseSemver, type Version } from "./semver.js";
import type { SigningService } from "./service.js";
import type { Adapter } from "./types.js";
import { characters } from "./values.js";

export interface KeySealOptions {
  adapter: Adapter;
  service: SigningService;
  /** Scheme, host and port of the job URLs, such as `https://dash.example.org`. */
  origin: string;
  /** Path the job endpoint is mounted under, such as `/api/keyseal`; empty by default. */
  basePath?: string;
  /** Accept `http://localhost` and `http://127.0.0.1` origins, for development and CI. */
  allowInsecureOrigin?: boolean;
  /** Lowest `X-KeySeal-Version` served (SemVer); older helpers get 426. */
  minHelperVersion?: string;
  /** Returns false to answer a job endpoint request with 429. */
  rateLimit?: (request: Request) => boolean | Promise<boolean>;
  now?: () => Date;
  /**
   * Served as `/.well-known/keyseal.json`; without it the manifest is 404.
   * `translucent: false` asks the helper for opaque job windows.
   */
  branding?: {
    name: string;
    icon?: string;
    accentColor?: string;
    translucent?: boolean;
  };
  certificateInspector?: CertificateInspector;
}

/** `minHelperVersion` as given and parsed. */
export interface MinHelperVersion {
  text: string;
  version: Version;
}

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

/** Throws a TypeError for invalid options; returns `minHelperVersion`, if set. */
export function checkOptions(
  options: KeySealOptions,
  basePath: string
): MinHelperVersion | null {
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
  let minVersion: MinHelperVersion | null = null;
  if (options.minHelperVersion !== undefined) {
    const version = parseSemver(options.minHelperVersion);
    if (!version) {
      throw new TypeError("minHelperVersion must be a SemVer version");
    }
    minVersion = { text: options.minHelperVersion, version };
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
