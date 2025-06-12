export type PermissionEffect = 'Allow' | 'Deny'

export type PermissionConditions = Record<string, Record<string, string[]>>

/**
 * Convert an AWS wildcard ARN pattern (e.g. "arn:aws:s3:::bucket/*") into a RegExp.
 */
function wildcardToRegex(pattern: string): RegExp {
  const parts = pattern.split('*').map((s) => s.replace(/[-/\\^$+?.()|[\]{}]/g, '\\$&'))
  return new RegExp('^' + parts.join('.*') + '$')
}

/**
 * An immutable representation of a single permission for a specific action.
 *
 * This will eventually have methods like "merge with another permission",
 * "check if overlaps with another permission", "subtract a deny permission",
 * etc and those will all return a new Permission instance.
 */
export class Permission {
  constructor(
    public readonly effect: PermissionEffect,
    public readonly service: string,
    public readonly action: string,
    public readonly resource: string[] | undefined,
    public readonly notResource: string[] | undefined,
    public readonly conditions: Record<string, Record<string, string[]>> | undefined
  ) {
    if (resource !== undefined && notResource !== undefined) {
      throw new Error('Permission must have a resource or notResource, not both.')
    } else if (resource === undefined && notResource === undefined) {
      throw new Error('Permission must have a resource or notResource, one must be defined.')
    }
  }

  /**
   * Returns true if this Permission completely includes the other Permission.
   * Only supports merging of "Allow" permissions (same effect, service, action).
   */
  public includes(other: Permission): boolean {
    // 1. Effects, service, and action must match
    if (
      this.effect !== other.effect ||
      this.service !== other.service ||
      this.action !== other.action
    ) {
      return false
    }

    // 2. Conditions: every condition in this must be implied by the other permission’s conditions
    //    That is, for each operator and context key in this.conditions, other.conditions must have it,
    //    and the values must satisfy inclusion logic per operator.
    const condsA = normalizeConditionKeys(this.conditions || {})
    const condsB = normalizeConditionKeys(other.conditions || {})
    for (const op of Object.keys(condsA)) {
      if (!(op in condsB)) return false
      const keysA = Object.keys(condsA[op])
      const keysB = Object.keys(condsB[op])
      // Every key in A must appear in B
      for (const key of keysA) {
        if (!keysB.includes(key)) return false
        const valsA = condsA[op][key]
        const valsB = condsB[op][key]
        const baseOp = conditionBaseOperator(op)
        switch (baseOp) {
          case 'stringequals':
          case 'stringlike':
          case 'arnequals':
          case 'arnlike':
            // other must be at least as restrictive: B_vals ⊆ A_vals
            if (!valsB.every((v) => valsA.includes(v))) return false
            break
          case 'stringnotequals':
          case 'stringnotlike':
          case 'arnnotequals':
          case 'arnnotlike':
            // other must exclude at least what A excludes: A_vals ⊆ B_vals
            if (!valsA.every((v) => valsB.includes(v))) return false
            break
          case 'numericlessthan':
          case 'numericlessthanequals':
            // other boundary <= this boundary
            const numA = Number(valsA[0])
            const numB = Number(valsB[0])
            if (isNaN(numA) || isNaN(numB)) return false
            if (numB > numA) return false
            break
          case 'numericgreaterthan':
          case 'numericgreaterthanequals':
            // other boundary >= this boundary
            const ngA = Number(valsA[0])
            const ngB = Number(valsB[0])
            if (isNaN(ngA) || isNaN(ngB)) return false
            if (ngB < ngA) return false
            break
          case 'bool':
            // other must have the same boolean value
            if (valsA[0] !== valsB[0]) return false
            break
          case 'ipaddress':
          case 'notipaddress':
            // every CIDR in B must be contained in some CIDR in A
            for (const cidrB of valsB) {
              if (!valsA.some((cidrA) => cidrA === cidrB)) {
                return false
              }
            }
            break
          case 'datelessthan':
          case 'datelessthanequals':
            // other date <= this date lexically (ISO)
            const dA = valsA[0]
            const dB = valsB[0]
            if (dB > dA) return false
            break
          case 'dategreaterthan':
          case 'dategreaterthanequals':
            // other date >= this date
            const dgA = valsA[0]
            const dgB = valsB[0]
            if (dgB < dgA) return false
            break
          default:
            return false
        }
      }
    }

    // 3. Resources / NotResources

    const thisResource = this.resource
    const thisNotResource = this.notResource
    const otherResource = other.resource
    const otherNotResource = other.notResource

    // 3a. If both have resource[]
    if (thisResource !== undefined && otherResource !== undefined) {
      return otherResource.every((r2) => thisResource.some((r1) => wildcardToRegex(r1).test(r2)))
    }
    // 3b. Both have notResource[]
    if (thisNotResource !== undefined && otherNotResource !== undefined) {
      return thisNotResource.every((n1) =>
        otherNotResource.some((n2) => wildcardToRegex(n1).test(n2))
      )
    }

    // 3c. A.resource & B.notResource -> B allows almost all, A allows only R1 -> true iff every N2 is matched by some R1
    if (thisResource !== undefined && otherNotResource !== undefined) {
      return otherNotResource.every((n2) => thisResource.some((r1) => wildcardToRegex(r1).test(n2)))
    }

    // 3d. A.notResource & B.resource -> every r2 ∉ N1
    if (thisNotResource !== undefined && otherResource !== undefined) {
      return otherResource.every(
        (r2) => !thisNotResource.some((n1) => wildcardToRegex(n1).test(r2))
      )
    }
    return false
  }

  /**
   * Returns the union of this Permission with another.
   * If one includes the other, return the including Permission.
   * Otherwise, attempt to merge conditions and resource/notResource.
   * If merge yields a single Permission, return it; else return both.
   */
  public union(other: Permission): Permission[] {
    // 1. Ensure same effect, service, and action
    if (
      this.effect !== other.effect ||
      this.service !== other.service ||
      this.action !== other.action
    ) {
      return [this, other]
    }

    // 2. If one includes the other, return the including one
    if (this.includes(other)) {
      return [this]
    }
    if (other.includes(this)) {
      return [other]
    }

    // 3. Attempt to combine conditions
    const condsA = this.conditions || {}
    const condsB = other.conditions || {}
    const mergedConds = mergeConditions(condsA, condsB)
    if (mergedConds === null) {
      return [this, other]
    }

    // 4. Combine resource/notResource (constructor enforces exclusivity)
    const thisResource = this.resource
    const thisNotResource = this.notResource
    const otherResource = other.resource
    const otherNotResource = other.notResource
    const eff = this.effect
    const svc = this.service
    const act = this.action
    const conds = Object.keys(mergedConds).length > 0 ? mergedConds : undefined

    // Both have resource[]
    if (thisResource !== undefined && otherResource !== undefined) {
      const union = Array.from(new Set([...thisResource, ...otherResource]))
      return [new Permission(eff, svc, act, union, undefined, conds)]
    }
    // Both have notResource[]
    if (thisNotResource !== undefined && otherNotResource !== undefined) {
      // Intersection of both notResource arrays
      const intersection = thisNotResource.filter((n) => otherNotResource.includes(n))
      return [new Permission(eff, svc, act, undefined, intersection, conds)]
    }
    // One has resource, other has notResource
    if (thisResource !== undefined && otherNotResource !== undefined) {
      return [
        new Permission(eff, svc, act, thisResource, undefined, conds),
        new Permission(eff, svc, act, undefined, otherNotResource, conds)
      ]
    }
    if (otherResource !== undefined && thisNotResource !== undefined) {
      return [
        new Permission(eff, svc, act, otherResource, undefined, conds),
        new Permission(eff, svc, act, undefined, thisNotResource, conds)
      ]
    }

    // Otherwise cannot combine, return both
    return [this, other]
  }

  /**
   * Returns the intersection of this Permission with another.
   * Always returns exactly one Permission. If there is no overlap,
   * returns undefined.
   */
  public intersection(other: Permission): Permission | undefined {
    // 1. Must match effect, service, and action
    if (
      this.effect !== other.effect ||
      this.service !== other.service ||
      this.action !== other.action
    ) {
      // No overlap at all—return a "zero-resource" permission
      return undefined
    }

    if (this.resource != undefined && other.resource != undefined) {
      // 2. If one includes the other, return the narrower one unless both are NotResource
      if (this.includes(other)) {
        return other
      }
      if (other.includes(this)) {
        return this
      }
    }

    // 3. Attempt to intersect/merge conditions
    const a = normalizeConditionKeys(this.conditions || {})
    const b = normalizeConditionKeys(other.conditions || {})
    const allOps = Array.from(new Set([...Object.keys(a), ...Object.keys(b)]))
    const intersectedConds: PermissionConditions = {}

    for (const op of allOps) {
      const condA = a[op] || {}
      const condB = b[op] || {}
      const allKeys = Array.from(new Set([...Object.keys(condA), ...Object.keys(condB)]))
      intersectedConds[op] = {}

      for (const key of allKeys) {
        const valsA = condA[key] || []
        const valsB = condB[key] || []

        // If key appears in both, intersect or combine based on operator
        if (key in condA && key in condB) {
          switch (conditionBaseOperator(op)) {
            case 'stringequals':
            case 'stringlike':
            case 'arnequals':
            case 'arnlike': {
              // Intersection of string lists
              const common = valsA.filter((v) => valsB.includes(v))
              if (common.length === 0) {
                return undefined
              }
              intersectedConds[op][key] = common
              break
            }
            case 'stringnotequals':
            case 'stringnotlike':
            case 'arnnotequals':
            case 'arnnotlike': {
              // Union of exclusions
              intersectedConds[op][key] = Array.from(new Set([...valsA, ...valsB]))
              break
            }
            case 'numericlessthan':
            case 'numericlessthanequals': {
              const numA = Number(valsA[0])
              const numB = Number(valsB[0])
              if (isNaN(numA) || isNaN(numB)) {
                return undefined
              }
              const boundary = Math.min(numA, numB)
              intersectedConds[op][key] = [String(boundary)]
              break
            }
            case 'numericgreaterthan':
            case 'numericgreaterthanequals': {
              const ngA = Number(valsA[0])
              const ngB = Number(valsB[0])
              if (isNaN(ngA) || isNaN(ngB)) {
                return undefined
              }
              const boundary = Math.max(ngA, ngB)
              intersectedConds[op][key] = [String(boundary)]
              break
            }
            case 'bool': {
              if (valsA[0] !== valsB[0]) {
                return undefined
              }
              intersectedConds[op][key] = [valsA[0]]
              break
            }
            case 'ipaddress':
            case 'notipaddress': {
              const common = valsA.filter((cidr) => valsB.includes(cidr))
              if (common.length === 0) {
                return undefined
              }
              intersectedConds[op][key] = common
              break
            }
            case 'datelessthan':
            case 'datelessthanequals': {
              const dA = valsA[0]
              const dB = valsB[0]
              intersectedConds[op][key] = [dA < dB ? dA : dB]
              break
            }
            case 'dategreaterthan':
            case 'dategreaterthanequals': {
              const dgA = valsA[0]
              const dgB = valsB[0]
              intersectedConds[op][key] = [dgA > dgB ? dgA : dgB]
              break
            }
            default:
              return undefined
          }
        } else {
          // Key only in one side: carry it through
          intersectedConds[op][key] = key in condA ? Array.from(valsA) : Array.from(valsB)
        }
      }
    }

    // 4. Combine resource/notResource:
    const thisResource = this.resource
    const thisNotResource = this.notResource
    const otherResource = other.resource
    const otherNotResource = other.notResource
    const eff = this.effect
    const svc = this.service
    const act = this.action
    const conds = Object.keys(intersectedConds).length > 0 ? intersectedConds : undefined

    // Both have resource[] => intersect patterns
    if (thisResource !== undefined && otherResource !== undefined) {
      // Keep any R1 that matches something in R2, and any R2 that matches something in R1
      const part1 = thisResource.filter((r1) =>
        otherResource.some((r2) => wildcardToRegex(r1).test(r2))
      )
      const part2 = otherResource.filter((r2) =>
        thisResource.some((r1) => wildcardToRegex(r2).test(r1))
      )
      const intersectR = Array.from(new Set([...part1, ...part2]))
      if (intersectR.length === 0) {
        return undefined
      }
      return new Permission(eff, svc, act, intersectR, undefined, conds)
    }

    // Both have notResource[] => union of exclusions (more restrictive), but remove subsumed patterns
    if (thisNotResource !== undefined && otherNotResource !== undefined) {
      // Compute union of both exclusion lists
      const combined = Array.from(new Set([...thisNotResource, ...otherNotResource]))
      // Remove any pattern that is subsumed by a more general pattern
      const filtered = combined.filter(
        (pat) =>
          !combined.some((otherPat) => otherPat !== pat && wildcardToRegex(otherPat).test(pat))
      )
      return new Permission(eff, svc, act, undefined, filtered, conds)
    }

    // One has resource, other has notResource

    const resource = thisResource || otherResource
    const notResource = thisNotResource || otherNotResource
    if (resource !== undefined || notResource !== undefined) {
      const filtered = resource!.filter(
        (r1) => !notResource!.some((n2) => wildcardToRegex(n2).test(r1))
      )
      if (filtered.length === 0) {
        return undefined
      }
      return new Permission(eff, svc, act, filtered, undefined, conds)
    }

    // This should never happen
    return undefined
  }

  /**
   * Subtract a Deny permission from this Allow permission.
   * Returns an array of resulting Allow permissions (may be empty if fully denied).
   */
  public subtract(other: Permission): Permission[] {
    // Only subtract Deny from Allow for the same service/action
    if (
      this.effect !== 'Allow' ||
      other.effect !== 'Deny' ||
      this.service !== other.service ||
      this.action !== other.action
    ) {
      // No subtraction applies
      return [this]
    }

    // Early exit: identical conditions and deny covers allow resources => fully denied
    const allowCondsNorm = normalizeConditionKeys(this.conditions || {})
    const denyCondsNorm = normalizeConditionKeys(other.conditions || {})
    if (JSON.stringify(allowCondsNorm) === JSON.stringify(denyCondsNorm)) {
      // If both have resource[] and deny resources include all allow resources
      if (this.resource && other.resource) {
        if (this.resource.every((a) => other.resource!.some((d) => wildcardToRegex(d).test(a)))) {
          return []
        }
      }
      // If both have notResource[] and deny.notResource excludes superset of allow.notResource
      if (this.notResource && other.notResource) {
        // Deny excludes everything allow excludes or more, so allow has no effective resources
        if (this.notResource.every((n) => other.notResource!.includes(n))) {
          return []
        }
      }
    }
    // 1. Invert Deny conditions
    const inverted = invertConditions(other.conditions || {})

    // 2. Merge conditions: original Allow ∧ inverted Deny
    const allowConds = normalizeConditionKeys(this.conditions || {})
    const mergedConds = mergeComplementaryConditions(
      mergeConditions(allowConds, inverted) || {
        ...allowConds,
        ...inverted
      }
    )

    const allowResource = this.resource
    const allowNotResource = this.notResource
    const denyResource = other.resource
    const denyNotResource = other.notResource

    const eff = this.effect
    const svc = this.service
    const act = this.action
    const conds = Object.keys(mergedConds).length ? mergedConds : undefined

    // Case: Allow.resource & Deny.resource
    if (allowResource !== undefined && denyResource !== undefined) {
      // If Deny has no conditions, subtract resources normally
      if (!other.conditions || Object.keys(other.conditions).length === 0) {
        const remaining = allowResource.filter(
          (a) => !denyResource.some((d) => wildcardToRegex(d).test(a))
        )

        // we cannot express the subtraction in a single statement → keep both.
        const denyIsSubset = denyResource.every((d) =>
          allowResource.some((a) => wildcardToRegex(a).test(d))
        )
        if (denyIsSubset && remaining.length === allowResource.length) {
          return [this, other]
        }

        if (remaining.length === 0) return []
        return [new Permission(eff, svc, act, remaining, undefined, conds)]
      }
      // Deny is conditional: do not remove resources, let condition inversion handle exclusion
      return [new Permission(eff, svc, act, allowResource, undefined, conds)]
    }

    // Case: Allow.resource & Deny.notResource --> remaining = A ∩ DNR
    if (allowResource !== undefined && denyNotResource !== undefined) {
      // If Deny has conditions, skip list-based subtraction and rely on conditions only
      if (other.conditions && Object.keys(other.conditions).length > 0) {
        return [new Permission(eff, svc, act, allowResource, undefined, conds)]
      }
      const remaining = allowResource.filter((a) =>
        denyNotResource.some((dnr) => wildcardToRegex(dnr).test(a))
      )
      if (remaining.length === 0) return []
      return [new Permission(eff, svc, act, remaining, undefined, conds)]
    }

    // Case: Allow.notResource & Deny.resource
    if (allowNotResource !== undefined && denyResource !== undefined) {
      // If Deny is conditional, let conditions handle; keep original notResource
      if (other.conditions && Object.keys(other.conditions).length > 0) {
        return [new Permission(eff, svc, act, undefined, allowNotResource, conds)]
      }

      // Check if every Deny resource is already excluded by allowNotResource
      const denyCovered = denyResource.every((dr) =>
        allowNotResource.some((anr) => wildcardToRegex(anr).test(dr))
      )
      if (denyCovered) {
        // Deny adds no new exclusions; keep original
        return [new Permission(eff, svc, act, undefined, allowNotResource, conds)]
      }

      // Otherwise union the exclusions
      const newNot = Array.from(new Set([...allowNotResource, ...denyResource]))
      return [new Permission(eff, svc, act, undefined, newNot, conds)]
    }

    // Case: Allow.notResource & Deny.notResource --> newNot = ANR \ DNR
    if (allowNotResource !== undefined && denyNotResource !== undefined) {
      // If Deny has conditions, skip list-based subtraction and rely on conditions only
      if (other.conditions && Object.keys(other.conditions).length > 0) {
        return [new Permission(eff, svc, act, undefined, allowNotResource, conds)]
      }
      const remainingNot = allowNotResource.filter(
        (n) => !denyNotResource.some((dnr) => wildcardToRegex(dnr).test(n))
      )
      if (remainingNot.length === 0) return []
      return [new Permission(eff, svc, act, undefined, remainingNot, conds)]
    }

    // This should never happen
    throw new Error('Permission.subtract: This should never happen—invalid state.')
  }
}

/**
 * Attempt to merge two condition‐maps. If they can be expressed as a single IAM condition block,
 * return that merged block. Otherwise, return null (indicating no single‐block merger is possible).
 */
function mergeConditions(
  a: Record<string, Record<string, string[]>>,
  b: Record<string, Record<string, string[]>>
): Record<string, Record<string, string[]>> | null {
  // 1. If the set of operators in 'a' differs from the set in 'b', return null.
  a = normalizeConditionKeys(a)
  b = normalizeConditionKeys(b)
  const opsA = Object.keys(a).sort()
  const opsB = Object.keys(b).sort()
  if (JSON.stringify(opsA) !== JSON.stringify(opsB)) {
    return null
  }

  const merged: PermissionConditions = {}

  // 2. For each operator op that appears in both:
  for (const op of opsA) {
    const keysA = Object.keys(a[op]).sort()
    const keysB = Object.keys(b[op]).sort()
    // If the set of context‐keys under this operator differs, we can't merge as one block
    if (JSON.stringify(keysA) !== JSON.stringify(keysB)) {
      return null
    }

    // Now we know op and its context keys align. Build the merged set for this operator:
    merged[op] = {}
    for (const key of keysA) {
      const valsA = a[op][key]
      const valsB = b[op][key]

      // How we combine depends on operator semantics:
      switch (conditionBaseOperator(op)) {
        case 'stringequals':
        case 'stringlike':
        case 'stringnotequals':
        case 'stringnotlike':
        case 'arnequals':
        case 'arnlike':
        case 'arnnotequals':
        case 'arnnotlike':
          // String‐based operators: just union the value arrays
          merged[op][key] = Array.from(new Set([...valsA, ...valsB]))
          break

        case 'numericlessthan':
        case 'numericlessthanequals':
        case 'numericgreaterthan':
        case 'numericgreaterthanequals':
        case 'numericequals':
        case 'numericnotequals':
          // Numeric operators: pick the “widest” comparison that still covers both sets
          // For simplicity, convert all valsA/valsB to numbers; find the min or max
          const numsA = valsA.map((v) => Number(v))
          const numsB = valsB.map((v) => Number(v))
          if (numsA.some(isNaN) || numsB.some(isNaN)) {
            // Malformed number—cannot merge
            return null
          }
          if (op === 'numericlessthan' || op === 'numericlessthanequals') {
            // We want the largest boundary
            const candidate = Math.max(...numsA, ...numsB)
            merged[op][key] = [String(candidate)]
          } else if (op === 'numericgreaterthan' || op === 'numericgreaterthanequals') {
            // We want the smallest boundary
            const candidate = Math.min(...numsA, ...numsB)
            merged[op][key] = [String(candidate)]
          } else if (op === 'numericequals' || op === 'numericnotequals') {
            // Union the sets of allowed/not‐allowed numbers
            merged[op][key] = Array.from(new Set([...valsA.map(String), ...valsB.map(String)]))
          }
          break

        case 'datelessthan':
        case 'datelessthanequals':
        case 'dategreaterthan':
        case 'dategreaterthanequals':
          // Similar idea: choose the “widest” date limit
          // Assume ISO‐8601 strings so lex‐compare works
          if (op === 'datelessthan' || op === 'datelessthanequals') {
            // pick the LARGEST date (latest) because “< latest” covers “< earlier”
            const candidate = [...valsA, ...valsB].sort().reverse()[0]
            merged[op][key] = [candidate]
          } else {
            // "DateGreaterThan"/"DateGreaterThanEquals": pick the EARLIEST date
            const candidate = [...valsA, ...valsB].sort()[0]
            merged[op][key] = [candidate]
          }
          break

        case 'bool':
          // Typically valsA and valsB are ["true"] or ["false"].
          // If either contains "true", then the union is ["true","false"]? No—
          // Bool doesn't make sense with an array. In IAM, Bool only works with a single value.
          // If values differ (one says ["true"], the other says ["false"]), you cannot
          // express (Bool==true OR Bool==false) as a single Bool. You’d need two separate
          // statements. So bail out.
          if (valsA[0] === valsB[0]) {
            merged[op][key] = [valsA[0]]
          } else {
            return null
          }
          break

        case 'ipaddress':
        case 'notipaddress':
          // You can pass multiple CIDR blocks under a single IpAddress. So union them.
          merged[op][key] = Array.from(new Set([...valsA, ...valsB]))
          break

        // Any other operators (e.g., “ArnNotLike” etc.) behave similarly to their base type
        default:
          // If we don’t explicitly handle the operator, reject merging
          return null
      }
    }
  }

  return merged
}

/**
 * Checks if an IAM condition operator ends with "IfExists".
 *
 * @param op the IAM condition operator, e.g., "StringEqualsIfExists"
 * @returns true if the operator ends with "IfExists", false otherwise.
 */
function isIfExists(op: string): boolean {
  // Check if the operator ends with "IfExists"
  return op.toLowerCase().endsWith('ifexists')
}

/**
 * Get the set operator from an IAM condition operator such as "ForAllValues" or "ForAnyValue".
 *
 * @param op the IAM condition operator, e.g., "ForAllValues:StringEquals"
 * @returns the set operator, e.g., "forallvalues" or "foranyvalue", or undefined if no set operator is present.
 */
function conditionSetOperator(op: string): string | undefined {
  return op.includes(':') ? op.split(':')[0].toLowerCase() : undefined
}

/**
 * Gets the base operator name from an IAM condition operator. Removes any set operator prefix or
 * "IfExists" suffix.
 *
 * @param op the IAM condition operator, e.g., "ForAllValues:StringEqualsIfExists"
 * @returns the base operator name, e.g., "stringequals" or "arnequals".
 */
function conditionBaseOperator(op: string): string {
  // Return the base operator name for IAM condition operators
  return op
    .split(':')
    .at(-1)!
    .toLowerCase()
    .replace(/ifexists$/, '')
}

/**
 * Returns a new PermissionConditions object with all operator and context keys lowercased.
 */
export function normalizeConditionKeys(conds: PermissionConditions): PermissionConditions {
  const result: PermissionConditions = {}
  for (const [op, keyMap] of Object.entries(conds)) {
    const lowerOp = op.toLowerCase()
    result[lowerOp] = {}
    for (const [contextKey, values] of Object.entries(keyMap)) {
      const lowerContextKey = contextKey.toLowerCase()
      result[lowerOp][lowerContextKey] = Array.from(values)
    }
  }
  return result
}

const invertOperatorMap: Record<string, string> = {
  stringequals: 'StringNotEquals',
  stringlike: 'StringNotLike',
  arnequals: 'ArnNotEquals',
  arnlike: 'ArnNotLike',
  stringnotequals: 'StringEquals',
  stringnotlike: 'StringLike',
  arnnotequals: 'ArnEquals',
  arnnotlike: 'ArnLike',
  numericlessthan: 'NumericGreaterThanEquals',
  numericlessthanequals: 'NumericGreaterThan',
  numericgreaterthan: 'NumericLessThanEquals',
  numericgreaterthanequals: 'NumericLessThan',
  numericequals: 'NumericNotEquals',
  numericnotequals: 'NumericEquals',
  datelessthan: 'DateGreaterThanEquals',
  datelessthanequals: 'DateGreaterThan',
  dategreaterthan: 'DateLessThanEquals',
  dategreaterthanequals: 'DateLessThan',
  bool: 'Bool',
  ipaddress: 'NotIpAddress',
  notipaddress: 'IpAddress'
}

const invertedSetOperatorMap: Record<string, string> = {
  forallvalues: 'ForAnyValue',
  foranyvalue: 'ForAllValues'
}

/**
 * Invert a set of IAM condition clauses for Deny → allow inversion.
 * Preserves ForAllValues:/ForAnyValue: prefixes and IfExists suffixes.
 *
 * @param conds the condition clauses to invert
 * @return a new set of inverted conditions
 */
export function invertConditions(
  conds: Record<string, Record<string, string[]>>
): Record<string, Record<string, string[]>> {
  const normalized = normalizeConditionKeys(conds)
  const inverted: Record<string, Record<string, string[]>> = {}
  for (const [op, keyMap] of Object.entries(normalized)) {
    const setOperator = conditionSetOperator(op) || undefined
    const setOperatorPrefix = setOperator ? invertedSetOperatorMap[setOperator] + ':' : ''
    const hasIfExists = isIfExists(op)
    const coreOp = conditionBaseOperator(op)
    const invertedCore = invertOperatorMap[coreOp] || coreOp
    const invertedOp =
      `${setOperatorPrefix}${invertedCore}${hasIfExists ? 'IfExists' : ''}`.toLowerCase()
    inverted[invertedOp] = {}
    for (const [key, vals] of Object.entries(keyMap)) {
      if (coreOp === 'bool' || coreOp === 'null') {
        inverted[invertedOp][key] = vals.map((v) => (v.toLowerCase() === 'true' ? 'false' : 'true'))
      } else {
        inverted[invertedOp][key] = Array.from(vals)
      }
    }
  }
  return inverted
}

function mergeComplementaryConditions(c: PermissionConditions): PermissionConditions {
  const complement: Record<string, string> = {
    stringequals: 'stringnotequals',
    stringlike: 'stringnotlike',
    arnequals: 'arnnotequals',
    arnlike: 'arnnotlike',
    numericequals: 'numericnotequals',
    numericnotequals: 'numericequals',
    numericlessthan: 'numericgreaterthanequals',
    numericgreaterthanequals: 'numericlessthan',
    numericlessthanequals: 'numericgreaterthan',
    numericgreaterthan: 'numericlessthanequals',
    datelessthan: 'dategreaterthanequals',
    dategreaterthanequals: 'datelessthan',
    datelessthanequals: 'dategreaterthan',
    dategreaterthan: 'datelessthanequals',
    ipaddress: 'notipaddress',
    notipaddress: 'ipaddress',
    bool: 'bool'
  }
  const out = JSON.parse(JSON.stringify(c)) as PermissionConditions
  for (const [base, comp] of Object.entries(complement)) {
    if (out[base] && out[comp]) {
      for (const key of Object.keys(out[base])) {
        if (key in out[comp]) {
          out[base][key] = out[base][key].filter((v) => !out[comp][key].includes(v))
          delete out[comp][key]
        }
      }
      if (out[comp] && Object.keys(out[comp]).length === 0) delete out[comp]
    }
  }
  return out
}
