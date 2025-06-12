import { expandIamActions, invertIamActions } from '@cloud-copilot/iam-expand'
import { Policy } from '@cloud-copilot/iam-policy'
import { Permission, PermissionEffect } from './permission.js'

/**
 * A permission set will be a collection of permissions for a specific effect (Allow or Deny).
 * So this will be used to represent things like "all the allowed permissions in a set of SCPs"
 * and "all the deny's that apply to a principal"
 */
export class PermissionSet {
  private permissions: Record<string, Record<string, Permission[]>> = {}

  constructor(public readonly effect: PermissionEffect) {}

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

  public getPermissions(service: string, action: string): Permission[] {
    if (!this.permissions[service] || !this.permissions[service][action]) {
      return []
    }
    return this.permissions[service][action]
  }

  public hasService(service: string): boolean {
    return !!this.permissions[service]
  }

  public hasAction(service: string, action: string): boolean {
    return !!(this.permissions[service] && this.permissions[service][action])
  }

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

        const thisPermissions = this.getPermissions(service, action)
        const denyPermissions = deny.getPermissions(service, action)

        for (const thisPermission of thisPermissions) {
          for (const denyPermission of denyPermissions) {
            const difference = thisPermission.subtract(denyPermission)
            for (const diff of difference) {
              if (diff.effect === 'Allow') {
                allowSet.addPermission(diff)
              } else {
                denySet.addPermission(diff)
              }
            }
          }
        }
      }
    }

    return { allow: allowSet, deny: denySet }
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
      } else if (effect === 'Deny' && stmt.isAllow()) {
        continue // skip Allow statements if we're building a Deny set
      }

      let statementActions: string[]
      if (stmt.isActionStatement()) {
        const allActions = stmt.actions().map((a) => a.value())
        statementActions = await expandIamActions(allActions, { expandAsterisk: true })
      } else if (stmt.isNotActionStatement()) {
        statementActions = await invertIamActions(stmt.notActions().map((a) => a.value()))
      } else {
        continue
      }

      for (const fullAction of statementActions) {
        const [service, actionName] = fullAction.split(':')
        if (!service || !actionName) continue

        let resource: string[] | undefined = undefined
        let notResource: string[] | undefined = undefined
        if (stmt.isResourceStatement()) {
          resource = stmt.resources().map((r) => r.value())
        } else if (stmt.isNotResourceStatement()) {
          notResource = stmt.notResources().map((r) => r.value())
        }

        permissionSet.addPermission(
          new Permission(effect, service, actionName, resource, notResource, stmt.conditionMap())
        )
      }
    }
  }
}

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
  const statements = [...buckets.values()].map((b) => ({
    Effect: set.effect,
    Action: b.actions.length === 1 ? b.actions[0] : [...new Set(b.actions)].sort(),
    Resource: b.res,
    NotResource: b.notRes,
    Condition: b.cond
  }))
  return statements
}
