const RFC9562_UUID_RE =
  /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/;

/**
 * Validate and normalize a strict 36-character hyphenated RFC 9562 UUID.
 * Returns the lowercase canonical UUID string, or null if invalid.
 */
export function parseCanonicalUuid(raw: string): string | null {
  if (!RFC9562_UUID_RE.test(raw)) {
    return null;
  }
  return raw.toLowerCase();
}
