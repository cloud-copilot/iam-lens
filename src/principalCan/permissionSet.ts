import { expandIamActions, invertIamActions } from '@cloud-copilot/iam-expand'
import { Policy, Statement } from '@cloud-copilot/iam-policy'
import { Permission, PermissionEffect } from './permission.js'

/**
 * A permission set will be a collection of permissions for a specific effect (Allow or Deny).
 * So this will be used to represent things like "all the allowed permissions in a set of SCPs"
 * and "all the deny's that apply to a principal"
 */
export class PermissionSet {
  private permissions: Record<string, Record<string, Permission[]>> = {}

  constructor(public readonly effect: PermissionEffect) {}

  /**
   * Add a new permission to the set.  If the new permission overlaps with an existing one,
   * they will be unioned together to avoid redundancy.
   *
   * @param newPermission the permission to add
   */
  public addPermission(newPermission: Permission): void {
    if (newPermission.effect !== this.effect) {
      throw new Error(
        `Permission effect ${newPermission.effect} does not match PermissionSet effect ${this.effect}`
      )
    }

    const service = newPermission.service
    const action = newPermission.action
    if (!this.permissions[service]) {
      this.permissions[service] = {}
    }
    if (!this.permissions[service][action]) {
      this.permissions[service][action] = []
    }
    const existingPermissions = this.permissions[service][action]
    if (existingPermissions.length === 0) {
      existingPermissions.push(newPermission)
      return
    }

    let replacesExisting = false
    let mergedWithExisting = false
    let first: Permission | undefined = existingPermissions[0]
    let rest = existingPermissions.slice(1)
    const newPermissions: Permission[] = []
    while (first) {
      const unionResult = first.union(newPermission)
      if (unionResult.length === 1) {
        const unionedPermission = unionResult[0]
        if (unionedPermission == first) {
          // The new permission is included in the existing permission, so we don't need to add it
          return
        }
        if (unionedPermission == newPermission) {
          replacesExisting = true
          // The existing permission is included in the new permission, so we can replace it
        } else {
          // The unioned permission is a net new permission, so we can add it
          newPermissions.push(unionedPermission)
          mergedWithExisting = true
        }
      } else {
        newPermissions.push(first)
      }
      first = rest.shift()
    }

    if (replacesExisting && !mergedWithExisting) {
      // If we didn't replace or merge with any existing permissions, just add the new permission
      newPermissions.push(newPermission)
    } else if (!replacesExisting && !mergedWithExisting) {
      // If we didn't replace or merge with any existing permissions, just add the new permission
      newPermissions.push(newPermission)
    }
    this.permissions[service][action] = newPermissions
  }

  /**
   * Get the permissions for a specific service and action.
   *
   * @param service the service to get permissions for
   * @param action the action to get permissions for
   * @returns the permissions that match the service and action
   */
  public getPermissions(service: string, action: string): Permission[] {
    if (!this.permissions[service] || !this.permissions[service][action]) {
      return []
    }
    return this.permissions[service][action]
  }

  /**
   * Check if the permission set has any permissions for a specific service
   *
   * @param service the service to check permissions for
   * @returns true if the permission set has permissions for the service, false otherwise
   */
  public hasService(service: string): boolean {
    return !!this.permissions[service]
  }

  /**
   * Check if the permission set has any permissions for a specific action
   *
   * @param service the service the action belongs to
   * @param action the action to check permissions for
   * @returns true if the permission set has permissions for the action, false otherwise
   */
  public hasAction(service: string, action: string): boolean {
    return !!(this.permissions[service] && this.permissions[service][action])
  }

  /**
   * Check if the permission set is empty (has no permissions)
   * @returns true if the permission set is empty, false otherwise
   */
  public isEmpty(): boolean {
    return Object.keys(this.permissions).length === 0
  }

  /**
   * Get all the permissions in the permission set
   *
   * @returns a copy of all the permissions in the permission set
   */
  public getAllPermissions(): Permission[] {
    const allPermissions: Permission[] = []
    for (const service in this.permissions) {
      for (const action in this.permissions[service]) {
        allPermissions.push(...this.permissions[service][action])
      }
    }
    return allPermissions
  }

  /**
   * Return a new PermissionSet containing the intersection of this set and another.
   * Only permissions that overlap (same effect, service, action, and intersecting resources/conditions)
   * will be included.
   *
   * @param other The other PermissionSet to intersect with.
   * @returns A new PermissionSet containing the intersecting permissions.
   * @throws Error if the effects of the two PermissionSets do not match.
   */
  public intersection(other: PermissionSet): PermissionSet {
    if (this.effect !== other.effect) {
      throw new Error('Cannot intersect PermissionSets with different effects')
    }

    const result = new PermissionSet(this.effect)

    for (const service of Object.keys(this.permissions)) {
      if (!other.hasService(service)) continue

      for (const action of Object.keys(this.permissions[service])) {
        if (!other.hasAction(service, action)) continue

        const thisPermissions = this.getPermissions(service, action)
        const otherPermissions = other.getPermissions(service, action)

        for (const thisPermission of thisPermissions) {
          for (const otherPermission of otherPermissions) {
            const ix = thisPermission.intersection(otherPermission)
            if (ix) {
              result.addPermission(ix)
            }
          }
        }
      }
    }

    return result
  }

  /**
   * Subtract a Deny PermissionSet from this Allow PermissionSet.
   *
   * Returns two PermissionSets: one with the remaining Allow permissions,
   * and one with any Deny permissions that were created as a result of the subtraction.
   *
   * @param deny the Deny PermissionSet to subtract
   * @returns an object containing the resulting Allow and Deny PermissionSets
   */
  public subtract(deny: PermissionSet): { allow: PermissionSet; deny: PermissionSet } {
    if (this.effect !== 'Allow' || deny.effect !== 'Deny') {
      throw new Error('Can only subtract a Deny PermissionSet from an Allow PermissionSet')
    }

    const allowSet = new PermissionSet('Allow')
    const denySet = new PermissionSet('Deny')

    for (const service of Object.keys(this.permissions)) {
      if (!deny.hasService(service)) {
        // allowSet.permissions[service] = this.permissions[service]
        // If the other set doesn't have this service, we can keep all permissions
        allowSet.permissions[service] = allowSet.permissions[service] || {}
        for (const action of Object.keys(this.permissions[service])) {
          allowSet.permissions[service][action] = [...this.getPermissions(service, action)]
        }
        continue
      }

      for (const action of Object.keys(this.permissions[service])) {
        if (!deny.hasAction(service, action)) {
          if (!allowSet.permissions[service]) {
            allowSet.permissions[service] = {}
          }
          // If the other set doesn't have this action, we can keep all permissions
          // allowSet.permissions[service] = allowSet.permissions[service] || {}
          allowSet.permissions[service][action] = [...this.getPermissions(service, action)]
          continue
        }

        let thisPermissions = this.getPermissions(service, action)
        const denyPermissions = deny.getPermissions(service, action)

        // We need to iteratively from each set of permissions, taking the result of each subtraction and feeding it into the next one.
        for (const denyPermission of denyPermissions) {
          const newPermissions: Permission[] = []
          for (const thisPermission of thisPermissions) {
            const difference = thisPermission.subtract(denyPermission)
            for (const diff of difference) {
              if (diff.effect === 'Allow') {
                newPermissions.push(diff)
              } else {
                denySet.addPermission(diff)
              }
            }
          }
          thisPermissions = newPermissions
        }
        for (const perm of thisPermissions) {
          allowSet.addPermission(perm)
        }
      }
    }

    return { allow: allowSet, deny: denySet }
  }

  /**
   * Add all permissions from another PermissionSet to this one.
   *
   * @param others the other PermissionSet (or array of PermissionSets) to add permissions from
   * @throws Error if the effects of the two PermissionSets do not match
   */
  public addAll(others: PermissionSet[] | PermissionSet): void {
    if (!Array.isArray(others)) {
      others = [others]
    }

    for (const other of others) {
      if (other.effect !== this.effect) {
        throw new Error('Cannot add PermissionSets with different effects')
      }
    }

    for (const other of others) {
      for (const perm of other.getAllPermissions()) {
        this.addPermission(perm)
      }
    }
  }

  /**
   * Deep clones the PermissionSet.
   *
   * @returns a new PermissionSet instance with the same permissions.
   */
  clone(): PermissionSet {
    const clone = new PermissionSet(this.effect)
    for (const service in this.permissions) {
      clone.permissions[service] = {}
      for (const action in this.permissions[service]) {
        clone.permissions[service][action] = [...this.permissions[service][action]]
      }
    }
    return clone
  }
}

/**
 * Given an array of IAM Policy objects, extract every "Allow" statement
 * and load it into a PermissionSet.  Each AWS action is split into its
 * service ("s3", "ec2", etc.) and the individual action name ("GetObject", "StartInstances", etc.).
 *
 * Assumptions:
 * 1. The Policy type comes from `@cloud-copilot/iam-policy`.  Each Policy has a `.statements` array.
 * 2. Each Statement has at least these fields (per AWS IAM JSON):
 *      - Effect: "Allow" | "Deny"
 *      - Action: string | string[]
 *      - Resource?: string | string[]
 *      - NotResource?: string | string[]
 *      - Condition?: Record<string, Record<string, string | string[]>>
 *
 * 3. We ignore any statements whose Effect ≠ "Allow".
 * 4. We do not expand wildcards here—if a statement’s Action is "s3:*",
 *    we leave it as the pattern "s3:*".  (If you want to expand all wildcards,
 *    run these policies through iam-expand first, then call this function.)
 *
 * Returns a PermissionSet containing one Permission object for each (service, action, resource, notResource, condition)
 * triple where Effect == "Allow".
 */
export async function buildPermissionSetFromPolicies(
  effect: PermissionEffect,
  policies: Policy[]
): Promise<PermissionSet> {
  // We'll collect all "Allow" statements across all policies
  const permissionSet = new PermissionSet(effect)
  await addPoliciesToPermissionSet(permissionSet, effect, policies)
  return permissionSet
}

export async function addPoliciesToPermissionSet(
  permissionSet: PermissionSet,
  effect: PermissionEffect,
  policies: Policy[]
): Promise<void> {
  for (const policy of policies) {
    // Each Policy object has a `.statements` array of raw Statement JSON
    for (const stmt of policy.statements()) {
      if (effect === 'Allow' && !stmt.isAllow()) {
        continue // skip Deny or any other non-Allow effect
      } else if (effect === 'Deny' && !stmt.isDeny()) {
        continue // skip Allow statements if we're building a Deny set
      }
      await addStatementToPermissionSet(stmt, permissionSet)
    }
  }
}

/**
 * Add a single Statement to a PermissionSet, expanding it into one or more Permissions as needed.
 *
 * @param statement the IAM policy statement to add
 * @param permissionSet the PermissionSet to add the statement to
 * @returns nothing; the PermissionSet is modified in place
 */
export async function addStatementToPermissionSet(
  statement: Statement,
  permissionSet: PermissionSet
) {
  const effect = statement.effect() as PermissionEffect
  let statementActions: string[]
  if (statement.isActionStatement()) {
    const allActions = statement.actions().map((a) => a.value())
    statementActions = await expandIamActions(allActions, { expandAsterisk: true })
  } else if (statement.isNotActionStatement()) {
    statementActions = await invertIamActions(statement.notActions().map((a) => a.value()))
  } else {
    return
  }

  for (const fullAction of statementActions) {
    const [service, actionName] = fullAction.split(':')
    if (!service || !actionName) continue

    let resource: string[] | undefined = undefined
    let notResource: string[] | undefined = undefined
    if (statement.isResourceStatement()) {
      resource = statement.resources().map((r) => r.value())
    } else if (statement.isNotResourceStatement()) {
      notResource = statement.notResources().map((r) => r.value())
    }

    permissionSet.addPermission(
      new Permission(effect, service, actionName, resource, notResource, statement.conditionMap())
    )
  }
}

/**
 * Create a consistent key for any permission
 *
 * @param p the permission to create a key for
 * @returns a string key that uniquely identifies the permission's resources and conditions
 */
function canonicalKey(p: Permission): string {
  // Sort resource arrays so ["B","A"] == ["A","B"]
  const resources = p.resource?.slice().sort() ?? null
  const notResource = p.notResource?.slice().sort() ?? null

  // Canonicalize the condition map (lower-case keys already).
  // We stringify with sorted keys so structurally-equal maps hash the same.
  const canonicalCond = p.conditions
    ? JSON.stringify(
        Object.fromEntries(
          Object.entries(p.conditions)
            .sort(([a], [b]) => a.localeCompare(b))
            .map(([op, kv]) => [
              op,
              Object.fromEntries(
                Object.entries(kv)
                  .sort(([a], [b]) => a.localeCompare(b))
                  .map(([k, v]) => [k, [...v].sort()])
              )
            ])
        )
      )
    : null

  // Effect is fixed for the whole PermissionSet, so not needed in the key.
  return JSON.stringify({ resources, notResource, canonicalCond })
}

/**
 * Convert a PermissionSet into an array of IAM policy statements.
 *
 * @param set the PermissionSet to convert
 * @returns an array of IAM policy statements
 */
export function toPolicyStatements(set: PermissionSet): any {
  const buckets = new Map<
    string,
    { res?: string[]; notRes?: string[]; cond?: any; actions: string[] }
  >()

  for (const perm of set.getAllPermissions()) {
    const key = canonicalKey(perm)
    const bucket = buckets.get(key) ?? {
      res: perm.resource ? [...perm.resource!] : undefined,
      notRes: perm.notResource ? [...perm.notResource!] : undefined,
      cond: perm.conditions ? perm.conditions : undefined,
      actions: []
    }
    bucket.actions.push(`${perm.service}:${perm.action}`)
    buckets.set(key, bucket)
  }

  // De-duplicate and sort Actions inside each bucket
  const statements = [...buckets.values()].map((b) => {
    const value: any = {
      Effect: set.effect,
      Action: b.actions.length === 1 ? b.actions[0] : [...new Set(b.actions)].sort()
    }

    if (b.cond) {
      value['Condition'] = b.cond
    }

    if (b.res && b.notRes) {
      throw new Error('Permission cannot have both Resource and NotResource defined')
    }

    if (b.res) {
      value['Resource'] = b.res
    } else if (b.notRes) {
      value['NotResource'] = b.notRes
    }

    return value
  })

  return statements
}
