/**
 * ECDSA verification on the brainpool curves (RFC 5639), which BoringSSL, and
 * so `node:crypto` in Bun and Workers, does not support. Only public values
 * are involved, so nothing here needs to run in constant time.
 */

interface Curve {
  p: bigint;
  a: bigint;
  b: bigint;
  /** The generator. */
  g: [bigint, bigint];
  /** The generator's order. */
  n: bigint;
}

export type BrainpoolCurve = "brainpoolP256r1" | "brainpoolP384r1";

const CURVES: Record<BrainpoolCurve, Curve> = {
  brainpoolP256r1: {
    a: 0x7d5a0975fc2c3057eef67530417affe7fb8055c126dc5c6ce94a4b44f330b5d9n,
    b: 0x26dc5c6ce94a4b44f330b5d9bbd77cbf958416295cf7e1ce6bccdc18ff8c07b6n,
    g: [
      0x8bd2aeb9cb7e57cb2c4b482ffc81b7afb9de27e1e3bd23c23a4453bd9ace3262n,
      0x547ef835c3dac4fd97f8461a14611dc9c27745132ded8e545c1d54c72f046997n,
    ],
    n: 0xa9fb57dba1eea9bc3e660a909d838d718c397aa3b561a6f7901e0e82974856a7n,
    p: 0xa9fb57dba1eea9bc3e660a909d838d726e3bf623d52620282013481d1f6e5377n,
  },
  brainpoolP384r1: {
    a: 0x7bc382c63d8c150c3c72080ace05afa0c2bea28e4fb22787139165efba91f90f8aa5814a503ad4eb04a8c7dd22ce2826n,
    b: 0x04a8c7dd22ce28268b39b55416f0447c2fb77de107dcd2a62e880ea53eeb62d57cb4390295dbc9943ab78696fa504c11n,
    g: [
      0x1d1c64f068cf45ffa2a63a81b7c13f6b8847a3e77ef14fe3db7fcafe0cbd10e8e826e03436d646aaef87b2e247d4af1en,
      0x8abe1d7520f9c2a45cb1eb8e95cfd55262b70b29feec5864e19c054ff99129280e4646217791811142820341263c5315n,
    ],
    n: 0x8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b31f166e6cac0425a7cf3ab6af6b7fc3103b883202e9046565n,
    p: 0x8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b412b1da197fb71123acd3a729901d1a71874700133107ec53n,
  },
};

/** Jacobian coordinates; Z = 0 is the point at infinity. */
type Point = [bigint, bigint, bigint];

const INFINITY: Point = [1n, 1n, 0n];

function mod(value: bigint, m: bigint): bigint {
  const result = value % m;
  return result < 0n ? result + m : result;
}

/** `value` to the power `exponent`, modulo `m`. */
function power(value: bigint, exponent: bigint, m: bigint): bigint {
  let result = 1n;
  let base = mod(value, m);
  for (let e = exponent; e > 0n; e >>= 1n) {
    if (e & 1n) {
      result = (result * base) % m;
    }
    base = (base * base) % m;
  }
  return result;
}

/** The inverse modulo a prime. */
function inverse(value: bigint, m: bigint): bigint {
  return power(value, m - 2n, m);
}

function double(curve: Curve, [x, y, z]: Point): Point {
  const { p, a } = curve;
  if (z === 0n || y === 0n) {
    return INFINITY;
  }
  const yy = mod(y * y, p);
  const s = mod(4n * x * yy, p);
  const zz = mod(z * z, p);
  const m = mod(3n * x * x + a * zz * zz, p);
  const x3 = mod(m * m - 2n * s, p);
  return [x3, mod(m * (s - x3) - 8n * yy * yy, p), mod(2n * y * z, p)];
}

function add(curve: Curve, one: Point, two: Point): Point {
  const { p } = curve;
  const [x1, y1, z1] = one;
  const [x2, y2, z2] = two;
  if (z1 === 0n) {
    return two;
  }
  if (z2 === 0n) {
    return one;
  }
  const z1z1 = mod(z1 * z1, p);
  const z2z2 = mod(z2 * z2, p);
  const u1 = mod(x1 * z2z2, p);
  const u2 = mod(x2 * z1z1, p);
  const s1 = mod(y1 * z2 * z2z2, p);
  const s2 = mod(y2 * z1 * z1z1, p);
  if (u1 === u2) {
    return s1 === s2 ? double(curve, one) : INFINITY;
  }
  const h = mod(u2 - u1, p);
  const r = mod(s2 - s1, p);
  const hh = mod(h * h, p);
  const hhh = mod(h * hh, p);
  const x3 = mod(r * r - hhh - 2n * u1 * hh, p);
  return [x3, mod(r * (u1 * hh - x3) - s1 * hhh, p), mod(h * z1 * z2, p)];
}

function multiply(curve: Curve, point: Point, scalar: bigint): Point {
  let result = INFINITY;
  for (let bit = BigInt(scalar.toString(2).length) - 1n; bit >= 0n; bit -= 1n) {
    result = double(curve, result);
    if ((scalar >> bit) & 1n) {
      result = add(curve, result, point);
    }
  }
  return result;
}

function toBigInt(bytes: Uint8Array): bigint {
  let value = 0n;
  for (const byte of bytes) {
    value = (value << 8n) | BigInt(byte);
  }
  return value;
}

/**
 * Whether `r` and `s`, the contents of an ECDSA-Sig-Value's INTEGERs, are a
 * signature by the uncompressed public point `point` over `hash` (SEC 1
 * section 4.1.4).
 */
export function verifyBrainpool(
  name: BrainpoolCurve,
  point: Uint8Array,
  hash: Uint8Array,
  rBytes: Uint8Array,
  sBytes: Uint8Array
): boolean {
  // A negative INTEGER is never a valid r or s.
  if ((rBytes[0] ?? 0x80) >= 0x80 || (sBytes[0] ?? 0x80) >= 0x80) {
    return false;
  }
  const r = toBigInt(rBytes);
  const s = toBigInt(sBytes);
  const curve = CURVES[name];
  const { p, a, b, n } = curve;
  const size = (p.toString(16).length + 1) >> 1;
  if (point.length !== 1 + 2 * size || point[0] !== 0x04) {
    return false;
  }
  const x = toBigInt(point.subarray(1, 1 + size));
  const y = toBigInt(point.subarray(1 + size));
  if (
    x >= p ||
    y >= p ||
    mod(y * y - (x * x * x + a * x + b), p) !== 0n ||
    r < 1n ||
    r >= n ||
    s < 1n ||
    s >= n
  ) {
    return false;
  }
  // The leftmost bits of the hash, as many as the order has.
  const bits = n.toString(2).length;
  let e = toBigInt(hash);
  if (hash.length * 8 > bits) {
    e >>= BigInt(hash.length * 8 - bits);
  }
  const w = inverse(s, n);
  const sum = add(
    curve,
    multiply(curve, [curve.g[0], curve.g[1], 1n], mod(e * w, n)),
    multiply(curve, [x, y, 1n], mod(r * w, n))
  );
  if (sum[2] === 0n) {
    return false;
  }
  const affineX = mod(sum[0] * inverse(sum[2] * sum[2], p), p);
  return mod(affineX, n) === r;
}
