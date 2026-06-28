import { splitArnParts } from '@cloud-copilot/iam-utils'

/** IAM principal type keys supported in Principal and NotPrincipal policy elements. */
export type PermissionPrincipalType = 'AWS' | 'Service' | 'Federated' | 'CanonicalUser'

/** Principal values grouped by IAM principal type for Permission algebra and policy output. */
export type PermissionPrincipals = Partial<Record<PermissionPrincipalType, string[]>> & {
  /** True when the policy used Principal: "*" rather than a typed principal map. */
  wildcard?: true
}

/** Internal normalized representation of a Principal or NotPrincipal dimension. */
export type PrincipalConstraint =
  | { kind: 'any'; explicit: boolean }
  | { kind: 'principal'; principals: PermissionPrincipals }
  | { kind: 'notPrincipal'; principals: PermissionPrincipals }

/** A normalized principal entry with semantic scope metadata used for comparisons. */
export interface NormalizedPrincipalEntry {
  /** The IAM principal type or Any for Principal: "*". */
  type: PermissionPrincipalType | 'Any'
  /** The normalized string value retained for round-tripping and debugging. */
  value: string
  /** The semantic category used for containment and overlap comparisons. */
  semanticKind:
    | 'wildcard'
    | 'account'
    | 'arn'
    | 'service'
    | 'federated'
    | 'canonicalUser'
    | 'organization'
    | 'network'
  /** Account IDs covered by this principal or derived principal-related condition scope. */
  accountIds?: string[]
  /** Organization IDs covered by this principal-related condition scope. */
  organizationIds?: string[]
  /** AWS service principal names covered by this entry. */
  servicePrincipals?: string[]
  /** VPC IDs covered by this principal-related condition scope. */
  vpcIds?: string[]
  /** CIDR blocks covered by this principal-related condition scope. */
  cidrBlocks?: string[]
}

/** The relationship between two normalized principal sets. */
export type PrincipalSetRelation =
  'equal' | 'subset' | 'superset' | 'overlap' | 'disjoint' | 'unknown'

const principalTypes: PermissionPrincipalType[] = ['AWS', 'Service', 'Federated', 'CanonicalUser']

/**
 * Build an unconstrained principal dimension.
 *
 * @param explicit - True when the source policy explicitly used Principal: "*".
 * @returns The unconstrained principal constraint.
 */
export function anyPrincipalConstraint(explicit: boolean): PrincipalConstraint {
  return { kind: 'any', explicit }
}

/**
 * Build a positive principal constraint.
 *
 * @param principals - The positive principal values.
 * @returns A normalized principal constraint.
 */
export function principalConstraint(
  principals: PermissionPrincipals | undefined
): PrincipalConstraint {
  return normalizePrincipalConstraint(principals, undefined)
}

/**
 * Build a negative principal constraint.
 *
 * @param notPrincipals - The excluded principal values.
 * @returns A normalized not-principal constraint.
 */
export function notPrincipalConstraint(
  notPrincipals: PermissionPrincipals | undefined
): PrincipalConstraint {
  return normalizePrincipalConstraint(undefined, notPrincipals)
}

/**
 * Normalize optional Principal and NotPrincipal values into an internal constraint.
 *
 * @param principal - Positive principals, if present.
 * @param notPrincipal - Negative principals, if present.
 * @returns The normalized principal constraint.
 */
export function normalizePrincipalConstraint(
  principal: PermissionPrincipals | undefined,
  notPrincipal: PermissionPrincipals | undefined
): PrincipalConstraint {
  if (principal && notPrincipal) {
    throw new Error('Permission must have a principal or notPrincipal, not both.')
  }
  if (principal) {
    const normalized = normalizePermissionPrincipals(principal)
    if (normalized.wildcard) return { kind: 'any', explicit: true }
    return { kind: 'principal', principals: normalized }
  }
  if (notPrincipal) {
    const normalized = normalizePermissionPrincipals(notPrincipal)
    if (normalized.wildcard) return { kind: 'notPrincipal', principals: normalized }
    return { kind: 'notPrincipal', principals: normalized }
  }
  return { kind: 'any', explicit: false }
}

/**
 * Normalize principal values by validating wildcard usage, de-duplicating values, and normalizing STS sessions.
 *
 * @param principals - Principal values to normalize.
 * @returns Normalized principal values.
 */
export function normalizePermissionPrincipals(
  principals: PermissionPrincipals
): PermissionPrincipals {
  const hasTypedValues = principalTypes.some((type) => (principals[type]?.length ?? 0) > 0)
  if (principals.wildcard && hasTypedValues) {
    throw new Error(
      'Permission principals cannot combine wildcard: true with typed principal values'
    )
  }

  const normalized: PermissionPrincipals = {}
  if (principals.wildcard) {
    normalized.wildcard = true
  }
  for (const type of principalTypes) {
    const values = principals[type]
    if (values && values.length > 0) {
      normalized[type] = Array.from(
        new Set(values.map((value) => normalizePrincipalValue(type, value)))
      )
    }
  }
  if (!normalized.wildcard && principalEntries(normalized).length === 0) {
    throw new Error('Permission principals must contain at least one principal value')
  }
  return normalized
}

/**
 * Determine whether one principal constraint fully includes another.
 *
 * @param a - Candidate including constraint.
 * @param b - Candidate included constraint.
 * @returns True when every principal in b is also in a.
 */
export function principalIncludes(a: PrincipalConstraint, b: PrincipalConstraint): boolean {
  if (a.kind === 'any') return true
  if (b.kind === 'any') return constraintIsUniversal(a)

  if (a.kind === 'principal' && b.kind === 'principal') {
    return entriesIncludeAll(principalEntries(a.principals), principalEntries(b.principals))
  }

  if (a.kind === 'notPrincipal' && b.kind === 'principal') {
    return principalEntries(b.principals).every(
      (entry) => !principalEntries(a.principals).some((excluded) => entriesOverlap(excluded, entry))
    )
  }

  if (a.kind === 'notPrincipal' && b.kind === 'notPrincipal') {
    return entriesIncludeAll(principalEntries(b.principals), principalEntries(a.principals))
  }

  if (a.kind === 'principal' && b.kind === 'notPrincipal') {
    return constraintIsUniversal(a)
  }

  return false
}

/**
 * Determine whether two principal constraints have any possible overlap.
 *
 * @param a - First principal constraint.
 * @param b - Second principal constraint.
 * @returns True when at least one principal can satisfy both constraints.
 */
export function principalConstraintsOverlap(
  a: PrincipalConstraint,
  b: PrincipalConstraint
): boolean {
  return intersectPrincipalConstraints(a, b).length > 0
}

/**
 * Return compact principal constraints representing a union.
 *
 * @param a - First principal constraint.
 * @param b - Second principal constraint.
 * @returns One or more constraints representing the union.
 */
export function unionPrincipalConstraints(
  a: PrincipalConstraint,
  b: PrincipalConstraint
): PrincipalConstraint[] {
  if (principalIncludes(a, b)) return [a]
  if (principalIncludes(b, a)) return [b]
  if (a.kind === 'any') return [{ kind: 'any', explicit: a.explicit }]
  if (b.kind === 'any') return [{ kind: 'any', explicit: b.explicit }]

  if (a.kind === 'principal' && b.kind === 'principal') {
    return [{ kind: 'principal', principals: mergePrincipals(a.principals, b.principals) }]
  }

  if (a.kind === 'notPrincipal' && b.kind === 'notPrincipal') {
    const intersection = intersectPrincipalMaps(a.principals, b.principals)
    return intersection
      ? [{ kind: 'notPrincipal', principals: intersection }]
      : [{ kind: 'any', explicit: true }]
  }

  const positive = a.kind === 'principal' ? a : b.kind === 'principal' ? b : undefined
  const negative = a.kind === 'notPrincipal' ? a : b.kind === 'notPrincipal' ? b : undefined
  if (positive && negative) {
    const remainingExclusions = subtractPrincipalMap(negative.principals, positive.principals)
    return remainingExclusions
      ? [{ kind: 'notPrincipal', principals: remainingExclusions }]
      : [{ kind: 'any', explicit: true }]
  }

  return [a, b]
}

/**
 * Return constraints representing the intersection of two principal constraints.
 *
 * @param a - First principal constraint.
 * @param b - Second principal constraint.
 * @returns Constraints for the overlap, or an empty array when disjoint.
 */
export function intersectPrincipalConstraints(
  a: PrincipalConstraint,
  b: PrincipalConstraint
): PrincipalConstraint[] {
  if (a.kind === 'any') return [b]
  if (b.kind === 'any') return [a]

  if (a.kind === 'principal' && b.kind === 'principal') {
    const intersection = intersectPrincipalMaps(a.principals, b.principals)
    return intersection ? [{ kind: 'principal', principals: intersection }] : []
  }

  if (a.kind === 'notPrincipal' && b.kind === 'notPrincipal') {
    return [{ kind: 'notPrincipal', principals: mergePrincipals(a.principals, b.principals) }]
  }

  const positive = a.kind === 'principal' ? a : b.kind === 'principal' ? b : undefined
  const negative = a.kind === 'notPrincipal' ? a : b.kind === 'notPrincipal' ? b : undefined
  if (positive && negative) {
    const remaining = subtractPrincipalMap(positive.principals, negative.principals)
    return remaining ? [{ kind: 'principal', principals: remaining }] : []
  }

  return []
}

/**
 * Return constraints for allow minus deny on the principal dimension.
 *
 * @param allow - Allow principal constraint.
 * @param deny - Deny principal constraint.
 * @returns Principal constraints that remain allowed.
 */
export function subtractPrincipalConstraint(
  allow: PrincipalConstraint,
  deny: PrincipalConstraint
): PrincipalConstraint[] {
  if (!principalConstraintsOverlap(allow, deny)) return [allow]
  if (principalIncludes(deny, allow)) return []

  if (constraintIsUniversal(allow) && deny.kind === 'principal') {
    return [{ kind: 'notPrincipal', principals: deny.principals }]
  }
  if (constraintIsUniversal(allow) && deny.kind === 'notPrincipal') {
    return [{ kind: 'principal', principals: deny.principals }]
  }
  if (allow.kind === 'principal' && deny.kind === 'principal') {
    const remaining = subtractPrincipalMap(allow.principals, deny.principals)
    return remaining ? [{ kind: 'principal', principals: remaining }] : []
  }
  if (allow.kind === 'notPrincipal' && deny.kind === 'principal') {
    return [
      { kind: 'notPrincipal', principals: mergePrincipals(allow.principals, deny.principals) }
    ]
  }
  if (allow.kind === 'notPrincipal' && deny.kind === 'notPrincipal') {
    const remaining = subtractPrincipalMap(deny.principals, allow.principals)
    return remaining ? [{ kind: 'principal', principals: remaining }] : []
  }

  return [allow]
}

/**
 * Convert a constraint into Permission constructor principal arguments.
 *
 * @param constraint - The principal constraint to convert.
 * @returns Principal and NotPrincipal fields for a Permission.
 */
export function principalArgsForConstraint(constraint: PrincipalConstraint): {
  principal: PermissionPrincipals | undefined
  notPrincipal: PermissionPrincipals | undefined
} {
  if (constraint.kind === 'any') {
    return {
      principal: constraint.explicit ? { wildcard: true } : undefined,
      notPrincipal: undefined
    }
  }
  if (constraint.kind === 'principal') {
    return { principal: constraint.principals, notPrincipal: undefined }
  }
  return { principal: undefined, notPrincipal: constraint.principals }
}

/**
 * Convert principal values to a stable JSON value for bucketing policy statements.
 *
 * @param principal - Principal values to canonicalize.
 * @returns A JSON-compatible canonical representation.
 */
export function canonicalPrincipal(principal: PermissionPrincipals | undefined): unknown {
  if (!principal) return null
  const normalized = normalizePermissionPrincipals(principal)
  const out: Record<string, string[] | true> = {}
  if (normalized.wildcard) out.wildcard = true
  for (const type of principalTypes) {
    if (normalized[type]) out[type] = [...normalized[type]].sort()
  }
  return out
}

/**
 * Convert a Principal/NotPrincipal raw policy value into PermissionPrincipals.
 *
 * @param value - The raw Principal or NotPrincipal value.
 * @returns Permission principal values.
 */
export function principalsFromRawPolicyValue(value: unknown): PermissionPrincipals | undefined {
  if (value === undefined) return undefined
  if (value === '*') return { wildcard: true }
  if (!value || typeof value !== 'object' || Array.isArray(value)) return undefined

  const result: PermissionPrincipals = {}
  const record = value as Record<string, string | string[]>
  for (const type of principalTypes) {
    const rawValues = record[type]
    if (rawValues === undefined) continue
    result[type] = Array.isArray(rawValues) ? [...rawValues] : [rawValues]
  }
  return normalizePermissionPrincipals(result)
}

/**
 * Convert PermissionPrincipals into a raw policy Principal or NotPrincipal value.
 *
 * @param principals - Principal values to convert.
 * @returns A raw policy value.
 */
export function principalsToPolicyValue(principals: PermissionPrincipals): unknown {
  const normalized = normalizePermissionPrincipals(principals)
  if (normalized.wildcard) return '*'

  const out: Record<string, string | string[]> = {}
  for (const type of principalTypes) {
    const values = normalized[type]
    if (values) out[type] = values.length === 1 ? values[0] : [...values]
  }
  return out
}

function constraintIsUniversal(constraint: PrincipalConstraint): boolean {
  return (
    constraint.kind === 'any' ||
    (constraint.kind === 'principal' && isWildcardPrincipals(constraint.principals))
  )
}

function isWildcardPrincipals(principals: PermissionPrincipals): boolean {
  return principals.wildcard === true || principals.AWS?.includes('*') === true
}

function principalEntries(principals: PermissionPrincipals): NormalizedPrincipalEntry[] {
  if (principals.wildcard) return [{ type: 'Any', value: '*', semanticKind: 'wildcard' }]
  return principalTypes.flatMap((type) =>
    (principals[type] ?? []).map((value) => entryForValue(type, value))
  )
}

function entriesIncludeAll(a: NormalizedPrincipalEntry[], b: NormalizedPrincipalEntry[]): boolean {
  return b.every((bEntry) => a.some((aEntry) => entryIncludes(aEntry, bEntry)))
}

function entryIncludes(a: NormalizedPrincipalEntry, b: NormalizedPrincipalEntry): boolean {
  if (a.semanticKind === 'wildcard') return true
  if (a.type === 'AWS' && a.value === '*') return true
  if (a.type !== b.type) return false
  if (a.value === b.value) return true
  if (
    a.semanticKind === 'account' &&
    b.accountIds?.some((accountId) => a.accountIds?.includes(accountId))
  ) {
    return true
  }
  return false
}

function entriesOverlap(a: NormalizedPrincipalEntry, b: NormalizedPrincipalEntry): boolean {
  return entryIncludes(a, b) || entryIncludes(b, a)
}

function mergePrincipals(a: PermissionPrincipals, b: PermissionPrincipals): PermissionPrincipals {
  if (isWildcardPrincipals(a) || isWildcardPrincipals(b))
    return a.wildcard || b.wildcard ? { wildcard: true } : { AWS: ['*'] }
  const merged: PermissionPrincipals = {}
  for (const type of principalTypes) {
    const values = [...(a[type] ?? []), ...(b[type] ?? [])]
    if (values.length > 0)
      merged[type] = Array.from(new Set(values.map((v) => normalizePrincipalValue(type, v))))
  }
  return normalizePermissionPrincipals(merged)
}

function intersectPrincipalMaps(
  a: PermissionPrincipals,
  b: PermissionPrincipals
): PermissionPrincipals | undefined {
  if (isWildcardPrincipals(a)) return b
  if (isWildcardPrincipals(b)) return a
  const entriesA = principalEntries(a)
  const entriesB = principalEntries(b)
  const kept: NormalizedPrincipalEntry[] = []
  for (const aEntry of entriesA) {
    for (const bEntry of entriesB) {
      const intersection = intersectEntries(aEntry, bEntry)
      if (intersection) kept.push(intersection)
    }
  }
  return principalsFromEntries(kept)
}

function subtractPrincipalMap(
  source: PermissionPrincipals,
  remove: PermissionPrincipals
): PermissionPrincipals | undefined {
  if (isWildcardPrincipals(remove)) return undefined
  // Universal-source subtraction that needs a NotPrincipal residual is handled by
  // subtractPrincipalConstraint before this positive-map helper is called.
  if (isWildcardPrincipals(source)) return source
  const removeEntries = principalEntries(remove)
  const kept = principalEntries(source).filter(
    (entry) => !removeEntries.some((removeEntry) => entryIncludes(removeEntry, entry))
  )
  return principalsFromEntries(kept)
}

function intersectEntries(
  a: NormalizedPrincipalEntry,
  b: NormalizedPrincipalEntry
): NormalizedPrincipalEntry | undefined {
  if (!entriesOverlap(a, b)) return undefined
  if (entryIncludes(a, b)) return b
  if (entryIncludes(b, a)) return a
  return undefined
}

function principalsFromEntries(
  entries: NormalizedPrincipalEntry[]
): PermissionPrincipals | undefined {
  const out: PermissionPrincipals = {}
  for (const entry of entries) {
    if (entry.semanticKind === 'wildcard') return { wildcard: true }
    if (entry.type === 'Any') return { wildcard: true }
    const type = entry.type
    out[type] = [...(out[type] ?? []), entry.value]
  }
  for (const type of principalTypes) {
    if (out[type]) out[type] = Array.from(new Set(out[type]))
  }
  return principalEntries(out).length > 0 ? normalizePermissionPrincipals(out) : undefined
}

function entryForValue(type: PermissionPrincipalType, value: string): NormalizedPrincipalEntry {
  const normalizedValue = normalizePrincipalValue(type, value)
  if (normalizedValue === '*') return { type, value: normalizedValue, semanticKind: 'wildcard' }
  if (type === 'AWS') {
    const accountId = accountIdForAwsPrincipal(normalizedValue)
    if (/^\d{12}$/.test(normalizedValue) || normalizedValue.endsWith(':root')) {
      return {
        type,
        value: normalizedValue,
        semanticKind: 'account',
        accountIds: accountId ? [accountId] : undefined
      }
    }
    return {
      type,
      value: normalizedValue,
      semanticKind: 'arn',
      accountIds: accountId ? [accountId] : undefined
    }
  }
  if (type === 'Service') {
    return {
      type,
      value: normalizedValue,
      semanticKind: 'service',
      servicePrincipals: [normalizedValue]
    }
  }
  if (type === 'Federated') return { type, value: normalizedValue, semanticKind: 'federated' }
  return { type, value: normalizedValue, semanticKind: 'canonicalUser' }
}

function normalizePrincipalValue(type: PermissionPrincipalType, value: string): string {
  if (type !== 'AWS') return value
  return normalizeStsAssumedRoleArn(value)
}

function accountIdForAwsPrincipal(value: string): string | undefined {
  if (/^\d{12}$/.test(value)) return value
  if (!value.startsWith('arn:')) return undefined
  try {
    return splitArnParts(value).accountId
  } catch (_err) {
    return undefined
  }
}

function normalizeStsAssumedRoleArn(value: string): string {
  if (!value.startsWith('arn:')) return value
  let parts: ReturnType<typeof splitArnParts>
  try {
    parts = splitArnParts(value)
  } catch (_err) {
    return value
  }
  const resource = parts.resource ?? ''
  if (parts.service !== 'sts' || !resource.startsWith('assumed-role/')) return value
  const assumedRoleParts = resource.slice('assumed-role/'.length).split('/')
  if (assumedRoleParts.length < 2) return value
  const rolePathAndName = assumedRoleParts.slice(0, -1).join('/')
  return `arn:${parts.partition}:iam::${parts.accountId}:role/${rolePathAndName}`
}
