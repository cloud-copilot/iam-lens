import { assert, expect } from 'vitest'
import { PermissionConditions } from './permission.js'
import { PermissionSet } from './permissionSet.js'

export interface TestPermission {
  effect: 'Allow' | 'Deny'
  action: string
  resource?: string[]
  notResource?: string[]
  conditions?: PermissionConditions
}

/**
 * Verifies that the given permission set matches the expected permissions.
 *
 * @param permissionSet
 * @param expectedPermissions
 */
export function expectPermissionSetToMatch(
  permissionSet: PermissionSet,
  expectedPermissions: TestPermission[]
): void {
  const expectationsByAction: Record<string, TestPermission[]> = {}
  for (const expected of expectedPermissions) {
    if (!expectationsByAction[expected.action]) {
      expectationsByAction[expected.action] = []
    }
    expectationsByAction[expected.action].push(expected)
  }

  for (const action of Object.keys(expectationsByAction)) {
    const expectedPermissions = expectationsByAction[action]
    const [service, serviceAction] = expectedPermissions[0].action.split(':')
    const actualPermissions = permissionSet.getPermissions(service, serviceAction)
    // Check if the actual permissions match the expected permissions
    if (actualPermissions.length !== expectedPermissions.length) {
      assert.fail(
        `Expected ${expectedPermissions.length} permissions for action ${action}, but got ${actualPermissions.length}`
      )
    }
    expect(actualPermissions, JSON.stringify(actualPermissions)).toHaveLength(
      expectedPermissions.length
    )
    for (let i = 0; i < expectedPermissions.length; i++) {
      const expectedPerm = expectedPermissions[i]
      const actualPerm = actualPermissions[i]

      expect(actualPerm.effect).toBe(expectedPerm.effect)
      expect(actualPerm.service).toBe(service)
      expect(actualPerm.action).toBe(serviceAction)
      expect(actualPerm.resource).toEqual(expectedPerm.resource)
      expect(actualPerm.notResource).toEqual(expectedPerm.notResource)
      expect(lowerCaseConditionKeys(actualPerm.conditions)).toEqual(
        lowerCaseConditionKeys(expectedPerm.conditions)
      )
    }
  }
}

/**
 * Convert condition operators and keys to lower case to ensure consistent comparisons.
 *
 * @param conditions the conditions to convert
 * @returns the conditions with lower-cased operators and keys
 */
export function lowerCaseConditionKeys(
  conditions: PermissionConditions | undefined
): PermissionConditions | undefined {
  if (!conditions) {
    return undefined
  }
  const lowerCased: PermissionConditions = {}
  for (const [key, value] of Object.entries(conditions)) {
    lowerCased[key.toLowerCase()] = {}
    for (const [conditionKey, conditionValue] of Object.entries(value)) {
      lowerCased[key.toLowerCase()][conditionKey.toLowerCase()] = conditionValue
    }
  }
  return lowerCased
}
