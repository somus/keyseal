/** Protocol section 1: lengths in characters count Unicode code points. */
export function characters(value: string): number {
  return [...value].length;
}

export function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
