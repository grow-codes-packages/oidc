// Service-owned: roles extraction shared by the verifier and the framework adapters.

/** Keys tried, in order, when a roles claim holds objects (Casdoor `roles: [{name: …}]`). */
const ROLE_OBJECT_KEYS = ["name", "code", "role", "value"] as const;

/**
 * Reads the value at a claim path. A path is a claim name (`roles`) or a dotted path into nested
 * objects (`realm_access.roles`). An exact top-level match wins over the dotted interpretation, so
 * claims whose names contain dots (`https://example.com/roles`) keep working.
 */
export function claimAt(claims: Readonly<Record<string, unknown>>, path: string): unknown {
  if (Object.hasOwn(claims, path)) return claims[path];
  let current: unknown = claims;
  for (const part of path.split(".")) {
    if (current === null || typeof current !== "object" || Array.isArray(current)) return undefined;
    const record = current as Record<string, unknown>;
    if (!Object.hasOwn(record, part)) return undefined;
    current = record[part];
  }
  return current;
}

/** One role entry: a string, or an object with `name`/`code`/`role`/`value`. */
function roleName(entry: unknown): string | undefined {
  if (typeof entry === "string") return entry.trim() === "" ? undefined : entry.trim();
  if (entry !== null && typeof entry === "object" && !Array.isArray(entry)) {
    const record = entry as Record<string, unknown>;
    for (const key of ROLE_OBJECT_KEYS) {
      const value = record[key];
      if (typeof value === "string" && value.trim() !== "") return value.trim();
    }
  }
  return undefined;
}

/**
 * Extracts role names from the claim at `rolesClaim` (default `roles`).
 *
 * - a string → split on commas and whitespace (`"admin editor"`, `"admin,editor"`);
 * - an array of strings and/or objects → each string, or the object's `name` (Casdoor), `code`,
 *   `role` or `value`;
 * - anything else (missing, number, object) → `[]`.
 *
 * Duplicates are removed; order is kept.
 */
export function extractRoles(
  claims: Readonly<Record<string, unknown>>,
  rolesClaim = "roles",
): string[] {
  const raw = claimAt(claims, rolesClaim);
  let names: (string | undefined)[] = [];
  if (typeof raw === "string") {
    names = raw.split(/[\s,]+/u);
  } else if (Array.isArray(raw)) {
    names = raw.map(roleName);
  }
  const out: string[] = [];
  for (const name of names) {
    if (name !== undefined && name !== "" && !out.includes(name)) out.push(name);
  }
  return out;
}

/**
 * True when `userRoles` contains at least one of `required` (case-insensitive). An empty
 * `required` list means "any authenticated user".
 */
export function hasAnyRole(userRoles: readonly string[], required: readonly string[]): boolean {
  if (required.length === 0) return true;
  const have = new Set(userRoles.map((role) => role.toLowerCase()));
  return required.some((role) => have.has(role.toLowerCase()));
}
