import { describe, expect, it } from 'vitest'
import { Permission, PermissionConditions } from './permission.js'
import { PermissionSet } from './permissionSet.js'

interface TestPermission {
  effect: 'Allow' | 'Deny'
  action: string
  resource?: string[]
  notResource?: string[]
  conditions?: PermissionConditions
}

const addPermissionTests: {
  only?: true
  name: string
  permissions: TestPermission[]
  expected: TestPermission[]
}[] = [
  {
    name: 'Add single permission',
    permissions: [{ action: 's3:ListBucket', effect: 'Allow', resource: ['*'] }],
    expected: [{ action: 's3:ListBucket', effect: 'Allow', resource: ['*'] }]
  },
  {
    name: 'Add non overlapping permissions',
    permissions: [
      {
        action: 's3:ListBucket',
        effect: 'Allow',
        resource: ['*'],
        conditions: { StringEquals: { 'aws:RequestTag/Project': ['Test'] } }
      },
      {
        action: 's3:ListBucket',
        effect: 'Allow',
        resource: ['*'],
        conditions: { StringEquals: { 'aws:RequestTag/Department': ['Test'] } }
      }
    ],
    expected: [
      {
        action: 's3:ListBucket',
        effect: 'Allow',
        resource: ['*'],
        conditions: { StringEquals: { 'aws:RequestTag/Project': ['Test'] } }
      },
      {
        action: 's3:ListBucket',
        effect: 'Allow',
        resource: ['*'],
        conditions: { StringEquals: { 'aws:RequestTag/Department': ['Test'] } }
      }
    ]
  },
  {
    name: 'Add non overlapping then wildcard',
    permissions: [
      {
        action: 's3:ListBucket',
        effect: 'Allow',
        resource: ['*'],
        conditions: { StringEquals: { 'aws:RequestTag/Project': ['Test'] } }
      },
      {
        action: 's3:ListBucket',
        effect: 'Allow',
        resource: ['*'],
        conditions: { StringEquals: { 'aws:RequestTag/Department': ['Test'] } }
      },
      {
        action: 's3:ListBucket',
        effect: 'Allow',
        resource: ['*'],
        conditions: { StringEquals: { 'aws:RequestTag/Area': ['Test'] } }
      },
      {
        action: 's3:ListBucket',
        effect: 'Allow',
        resource: ['*']
      }
    ],
    expected: [
      {
        action: 's3:ListBucket',
        effect: 'Allow',
        resource: ['*']
      }
    ]
  },
  {
    name: 'Add wildcard then others',
    permissions: [
      {
        action: 's3:ListBucket',
        effect: 'Allow',
        resource: ['*']
      },
      {
        action: 's3:ListBucket',
        effect: 'Allow',
        resource: ['*'],
        conditions: { StringEquals: { 'aws:RequestTag/Project': ['Test'] } }
      },
      {
        action: 's3:ListBucket',
        effect: 'Allow',
        resource: ['*'],
        conditions: { StringEquals: { 'aws:RequestTag/Department': ['Test'] } }
      },
      {
        action: 's3:ListBucket',
        effect: 'Allow',
        resource: ['*'],
        conditions: { StringEquals: { 'aws:RequestTag/Area': ['Test'] } }
      }
    ],
    expected: [
      {
        action: 's3:ListBucket',
        effect: 'Allow',
        resource: ['*']
      }
    ]
  },
  {
    name: 'Merge Permissions',
    permissions: [
      {
        action: 's3:ListBucket',
        effect: 'Allow',
        resource: ['*'],
        conditions: { StringEquals: { 'aws:RequestTag/Project': ['Test1'] } }
      },
      {
        action: 's3:ListBucket',
        effect: 'Allow',
        resource: ['*'],
        conditions: { StringEquals: { 'aws:RequestTag/Project': ['Test2'] } }
      }
    ],
    expected: [
      {
        action: 's3:ListBucket',
        effect: 'Allow',
        resource: ['*'],
        conditions: { stringequals: { 'aws:requesttag/project': ['Test1', 'Test2'] } }
      }
    ]
  }
]

describe('PermissionSet#addPermission', () => {
  for (const test of addPermissionTests) {
    const func = test.only ? it.only : it
    func(test.name, () => {
      //Given a permission set with the given permissions
      const permissionSet = new PermissionSet('Allow')

      //When the permissions are added
      for (const perm of test.permissions) {
        const [service, action] = perm.action.split(':')
        permissionSet.addPermission(
          new Permission(
            perm.effect,
            service,
            action,
            perm.resource,
            perm.notResource,
            perm.conditions
          )
        )
      }

      //Then the permission set should contain the expected permissions
      expectPermissionSetToMatch(permissionSet, test.expected)
    })
  }
})

const intersectionTests: {
  only?: true
  name: string
  permissions1: TestPermission[]
  permissions2: TestPermission[]
  expected: TestPermission[]
}[] = [
  {
    name: 'Intersecting permissions with same effect',
    permissions1: [
      { action: 's3:ListBucket', effect: 'Allow', resource: ['*'] },
      { action: 's3:GetObject', effect: 'Allow', resource: ['arn:aws:s3:::example-bucket/*'] }
    ],
    permissions2: [
      { action: 's3:ListBucket', effect: 'Allow', resource: ['*'] },
      { action: 's3:GetObject', effect: 'Allow', resource: ['arn:aws:s3:::example-bucket/*'] }
    ],
    expected: [
      { action: 's3:ListBucket', effect: 'Allow', resource: ['*'] },
      { action: 's3:GetObject', effect: 'Allow', resource: ['arn:aws:s3:::example-bucket/*'] }
    ]
  },
  {
    name: 'Non-intersecting permissions',
    permissions1: [
      { action: 's3:GetObject', effect: 'Allow', resource: ['arn:aws:s3:::example-bucket/*'] }
    ],
    permissions2: [
      { action: 's3:GetObject', effect: 'Allow', resource: ['arn:aws:s3:::another-bucket/*'] }
    ],
    expected: []
  },
  {
    name: 'Intersecting permissions with different conditions',
    permissions1: [
      {
        action: 's3:GetObject',
        effect: 'Allow',
        resource: ['arn:aws:s3:::example-bucket/*'],
        conditions: { StringEqualsIgnoreCaseIfExists: { 'aws:userAgent': ['TestAgent'] } }
      }
    ],
    permissions2: [
      {
        action: 's3:GetObject',
        effect: 'Allow',
        resource: ['arn:aws:s3:::example-bucket/*'],
        conditions: { StringEqualsIgnoreCaseIfExists: { 'aws:userAgent': ['TestAgent'] } }
      }
    ],
    expected: []
  },
  {
    name: 'Intersection with a subset of resources',
    permissions1: [{ action: 's3:ListBucket', effect: 'Allow', resource: ['*'] }],
    permissions2: [
      {
        action: 's3:ListBucket',
        effect: 'Allow',
        resource: ['arn:aws:s3:::bucket1', 'arn:aws:s3:::bucket2']
      },
      {
        action: 's3:ListBucket',
        effect: 'Allow',
        resource: ['arn:aws:s3:::bucket3', 'arn:aws:s3:::bucket4']
      }
    ],
    expected: [
      {
        action: 's3:ListBucket',
        effect: 'Allow',
        resource: [
          'arn:aws:s3:::bucket1',
          'arn:aws:s3:::bucket2',
          'arn:aws:s3:::bucket3',
          'arn:aws:s3:::bucket4'
        ]
      }
    ]
  }
]

for (const test of intersectionTests) {
  const func = test.only ? it.only : it
  func(test.name, () => {
    // Given two permission sets with the given permissions
    const permissionSet1 = new PermissionSet('Allow')
    for (const perm of test.permissions1) {
      const [service, action] = perm.action.split(':')
      permissionSet1.addPermission(
        new Permission(
          perm.effect,
          service,
          action,
          perm.resource,
          perm.notResource,
          perm.conditions
        )
      )
    }

    const permissionSet2 = new PermissionSet('Allow')
    for (const perm of test.permissions2) {
      const [service, action] = perm.action.split(':')
      permissionSet2.addPermission(
        new Permission(
          perm.effect,
          service,
          action,
          perm.resource,
          perm.notResource,
          perm.conditions
        )
      )
    }

    // When the intersection is calculated
    const intersection = permissionSet1.intersection(permissionSet2)

    // Then the intersection should contain the expected permissions
    expectPermissionSetToMatch(intersection, test.expected)
  })
}

const subtractTests: {
  only?: true
  name: string
  allowPermissions: TestPermission[]
  denyPermissions: TestPermission[]
  expectedAllow: TestPermission[]
  expectedDeny: TestPermission[]
}[] = [
  {
    name: 'Simple subtraction of allow and deny permissions',
    allowPermissions: [
      { action: 's3:ListBucket', effect: 'Allow', resource: ['*'] },
      { action: 's3:GetObject', effect: 'Allow', resource: ['arn:aws:s3:::example-bucket/*'] }
    ],
    denyPermissions: [{ action: 's3:ListBucket', effect: 'Deny', resource: ['*'] }],
    expectedAllow: [
      { action: 's3:GetObject', effect: 'Allow', resource: ['arn:aws:s3:::example-bucket/*'] }
    ],
    expectedDeny: []
  },
  {
    name: 'Subtract with final deny permissions',
    allowPermissions: [
      { action: 's3:ListBucket', effect: 'Allow', resource: ['*'] },
      { action: 's3:GetObject', effect: 'Allow', resource: ['arn:aws:s3:::example-bucket/*'] }
    ],
    denyPermissions: [
      { action: 's3:ListBucket', effect: 'Deny', resource: ['*'] },
      {
        action: 's3:GetObject',
        effect: 'Deny',
        resource: ['arn:aws:s3:::example-bucket/private/*']
      }
    ],
    expectedAllow: [
      { action: 's3:GetObject', effect: 'Allow', resource: ['arn:aws:s3:::example-bucket/*'] }
    ],
    expectedDeny: [
      {
        action: 's3:GetObject',
        effect: 'Deny',
        resource: ['arn:aws:s3:::example-bucket/private/*']
      }
    ]
  },
  {
    name: 'Subtract with no overlapping services',
    allowPermissions: [{ action: 's3:ListBucket', effect: 'Allow', resource: ['*'] }],
    denyPermissions: [{ action: 'ec2:StartInstances', effect: 'Deny', resource: ['*'] }],
    expectedAllow: [{ action: 's3:ListBucket', effect: 'Allow', resource: ['*'] }],
    expectedDeny: []
  }
]

for (const test of subtractTests) {
  const func = test.only ? it.only : it
  func(test.name, () => {
    // Given a permission set with the given allow and deny permissions
    const allowPermissionSet = new PermissionSet('Allow')
    for (const perm of test.allowPermissions) {
      const [service, action] = perm.action.split(':')
      allowPermissionSet.addPermission(
        new Permission(
          perm.effect,
          service,
          action,
          perm.resource,
          perm.notResource,
          perm.conditions
        )
      )
    }

    const denyPermissionSet = new PermissionSet('Deny')
    for (const perm of test.denyPermissions) {
      const [service, action] = perm.action.split(':')
      denyPermissionSet.addPermission(
        new Permission(
          perm.effect,
          service,
          action,
          perm.resource,
          perm.notResource,
          perm.conditions
        )
      )
    }

    // When the subtraction is performed
    const result = allowPermissionSet.subtract(denyPermissionSet)

    // Then the result should contain the expected allow and deny permissions
    expectPermissionSetToMatch(result.allow, test.expectedAllow)
    expectPermissionSetToMatch(result.deny, test.expectedDeny)
  })
}

/**
 * Verifies that the given permission set matches the expected permissions.
 *
 * @param permissionSet
 * @param expectedPermissions
 */
function expectPermissionSetToMatch(
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
    expect(actualPermissions).toHaveLength(expectedPermissions.length)
    for (let i = 0; i < expectedPermissions.length; i++) {
      const expectedPerm = expectedPermissions[i]
      const actualPerm = actualPermissions[i]

      expect(actualPerm.effect).toBe(expectedPerm.effect)
      expect(actualPerm.service).toBe(service)
      expect(actualPerm.action).toBe(serviceAction)
      expect(actualPerm.resource).toEqual(expectedPerm.resource)
      expect(actualPerm.notResource).toEqual(expectedPerm.notResource)
      expect(actualPerm.conditions).toEqual(expectedPerm.conditions)
    }
  }
}
