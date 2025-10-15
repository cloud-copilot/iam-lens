import { describe, expect, it } from 'vitest'
import { Permission } from './permission.js'
import { PermissionSet, toPolicyStatements } from './permissionSet.js'
import { expectPermissionSetToMatch, TestPermission } from './permissionSetTestUtils.js'

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

const addAllTests: {
  only?: true
  name: string
  basePermissions: TestPermission[]
  permissionSetsToAdd: TestPermission[][]
  expected: TestPermission[]
}[] = [
  {
    name: 'Add single permission set',
    basePermissions: [{ action: 's3:ListBucket', effect: 'Allow', resource: ['*'] }],
    permissionSetsToAdd: [
      [{ action: 's3:GetObject', effect: 'Allow', resource: ['arn:aws:s3:::example-bucket/*'] }]
    ],
    expected: [
      { action: 's3:ListBucket', effect: 'Allow', resource: ['*'] },
      { action: 's3:GetObject', effect: 'Allow', resource: ['arn:aws:s3:::example-bucket/*'] }
    ]
  },
  {
    name: 'Add multiple permission sets',
    basePermissions: [{ action: 's3:ListBucket', effect: 'Allow', resource: ['*'] }],
    permissionSetsToAdd: [
      [{ action: 's3:GetObject', effect: 'Allow', resource: ['arn:aws:s3:::bucket1/*'] }],
      [{ action: 's3:PutObject', effect: 'Allow', resource: ['arn:aws:s3:::bucket2/*'] }]
    ],
    expected: [
      { action: 's3:ListBucket', effect: 'Allow', resource: ['*'] },
      { action: 's3:GetObject', effect: 'Allow', resource: ['arn:aws:s3:::bucket1/*'] },
      { action: 's3:PutObject', effect: 'Allow', resource: ['arn:aws:s3:::bucket2/*'] }
    ]
  },
  {
    name: 'Add empty permission set',
    basePermissions: [{ action: 's3:ListBucket', effect: 'Allow', resource: ['*'] }],
    permissionSetsToAdd: [[]],
    expected: [{ action: 's3:ListBucket', effect: 'Allow', resource: ['*'] }]
  },
  {
    name: 'Add overlapping permissions that should merge',
    basePermissions: [
      { action: 's3:GetObject', effect: 'Allow', resource: ['arn:aws:s3:::bucket1/*'] }
    ],
    permissionSetsToAdd: [
      [{ action: 's3:GetObject', effect: 'Allow', resource: ['arn:aws:s3:::bucket2/*'] }]
    ],
    expected: [
      {
        action: 's3:GetObject',
        effect: 'Allow',
        resource: ['arn:aws:s3:::bucket1/*', 'arn:aws:s3:::bucket2/*']
      }
    ]
  },
  {
    name: 'Add permissions with conditions',
    basePermissions: [
      {
        action: 's3:GetObject',
        effect: 'Allow',
        resource: ['*'],
        conditions: { StringEquals: { 'aws:RequestTag/Environment': ['Production'] } }
      }
    ],
    permissionSetsToAdd: [
      [
        {
          action: 's3:GetObject',
          effect: 'Allow',
          resource: ['*'],
          conditions: { StringEquals: { 'aws:RequestTag/Team': ['DevOps'] } }
        }
      ]
    ],
    expected: [
      {
        action: 's3:GetObject',
        effect: 'Allow',
        resource: ['*'],
        conditions: { StringEquals: { 'aws:RequestTag/Environment': ['Production'] } }
      },
      {
        action: 's3:GetObject',
        effect: 'Allow',
        resource: ['*'],
        conditions: { StringEquals: { 'aws:RequestTag/Team': ['DevOps'] } }
      }
    ]
  },
  {
    name: 'Add multiple sets with duplicate permissions',
    basePermissions: [{ action: 's3:ListBucket', effect: 'Allow', resource: ['*'] }],
    permissionSetsToAdd: [
      [{ action: 's3:GetObject', effect: 'Allow', resource: ['arn:aws:s3:::bucket/*'] }],
      [{ action: 's3:GetObject', effect: 'Allow', resource: ['arn:aws:s3:::bucket/*'] }]
    ],
    expected: [
      { action: 's3:ListBucket', effect: 'Allow', resource: ['*'] },
      { action: 's3:GetObject', effect: 'Allow', resource: ['arn:aws:s3:::bucket/*'] }
    ]
  }
]

describe('PermissionSet#addAll', () => {
  for (const test of addAllTests) {
    const func = test.only ? it.only : it
    func(test.name, () => {
      // Given a permission set with base permissions
      const permissionSet = new PermissionSet('Allow')
      for (const perm of test.basePermissions) {
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

      // When adding all permissions from multiple permission sets
      const permissionSetsToAdd = test.permissionSetsToAdd.map((permissions) => {
        const otherSet = new PermissionSet('Allow')
        for (const perm of permissions) {
          const [service, action] = perm.action.split(':')
          otherSet.addPermission(
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
        return otherSet
      })

      permissionSet.addAll(permissionSetsToAdd)

      // Then the permission set should contain all expected permissions
      expectPermissionSetToMatch(permissionSet, test.expected)
    })
  }

  it('should throw error when adding permission set with different effect', () => {
    // Given an Allow permission set
    const allowSet = new PermissionSet('Allow')
    allowSet.addPermission(new Permission('Allow', 's3', 'ListBucket', ['*'], undefined, undefined))

    // And a Deny permission set
    const denySet = new PermissionSet('Deny')
    denySet.addPermission(new Permission('Deny', 's3', 'GetObject', ['*'], undefined, undefined))

    // When trying to add the Deny set to the Allow set
    // Then it should throw an error
    expect(() => {
      allowSet.addAll(denySet)
    }).toThrow('Cannot add PermissionSets with different effects')
  })

  it('should handle adding single permission set (not array)', () => {
    // Given a base permission set
    const baseSet = new PermissionSet('Allow')
    baseSet.addPermission(new Permission('Allow', 's3', 'ListBucket', ['*'], undefined, undefined))

    // And another permission set to add
    const otherSet = new PermissionSet('Allow')
    otherSet.addPermission(
      new Permission('Allow', 's3', 'GetObject', ['arn:aws:s3:::bucket/*'], undefined, undefined)
    )

    // When adding the single permission set (not in array)
    baseSet.addAll(otherSet)

    // Then both permissions should be present
    expectPermissionSetToMatch(baseSet, [
      { action: 's3:ListBucket', effect: 'Allow', resource: ['*'] },
      { action: 's3:GetObject', effect: 'Allow', resource: ['arn:aws:s3:::bucket/*'] }
    ])
  })
})

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
  },
  {
    name: 'Subtract a wildcard deny with permissions',
    allowPermissions: [{ action: 's3:ListBucket', effect: 'Allow', resource: ['*'] }],
    denyPermissions: [
      {
        action: 's3:ListBucket',
        effect: 'Deny',
        resource: ['*'],
        conditions: { StringEquals: { 'aws:RequestTag/Project': ['Test'] } }
      }
    ],
    expectedAllow: [
      {
        action: 's3:ListBucket',
        effect: 'Allow',
        resource: ['*'],
        conditions: { StringNotEquals: { 'aws:RequestTag/Project': ['Test'] } }
      }
    ],
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

describe('PermissionSet#clone', () => {
  it('should create a deep copy of an empty permission set', () => {
    // Given an empty permission set
    const original = new PermissionSet('Allow')

    // When cloning the permission set
    const cloned = original.clone()

    // Then the cloned permission set should have the same effect and be empty
    expect(cloned.effect).toBe('Allow')
    expect(cloned.isEmpty()).toBe(true)
    expect(cloned).not.toBe(original) // Different objects
  })

  it('should create a deep copy of a permission set with permissions', () => {
    // Given a permission set with various permissions
    const original = new PermissionSet('Allow')
    original.addPermission(new Permission('Allow', 's3', 'ListBucket', ['*'], undefined, undefined))
    original.addPermission(
      new Permission('Allow', 's3', 'GetObject', ['arn:aws:s3:::bucket/*'], undefined, undefined)
    )
    original.addPermission(
      new Permission('Allow', 'ec2', 'DescribeInstances', ['*'], undefined, {
        StringEquals: { 'aws:RequestedRegion': ['us-east-1'] }
      })
    )

    // When cloning the permission set
    const cloned = original.clone()

    // Then the cloned permission set should have the same permissions
    expect(cloned.effect).toBe(original.effect)
    expect(cloned.isEmpty()).toBe(false)
    expect(cloned.getAllPermissions()).toHaveLength(3)

    // And should have the same permissions content
    const originalPermissions = original.getAllPermissions()
    const clonedPermissions = cloned.getAllPermissions()
    expect(clonedPermissions).toHaveLength(originalPermissions.length)

    for (let i = 0; i < originalPermissions.length; i++) {
      const orig = originalPermissions[i]
      const clone = clonedPermissions[i]
      expect(clone.effect).toBe(orig.effect)
      expect(clone.service).toBe(orig.service)
      expect(clone.action).toBe(orig.action)
      expect(clone.resource).toEqual(orig.resource)
      expect(clone.notResource).toEqual(orig.notResource)
      expect(clone.conditions).toEqual(orig.conditions)
    }
  })

  it('should create independent copies that do not affect each other', () => {
    // Given a permission set with some permissions
    const original = new PermissionSet('Deny')
    original.addPermission(
      new Permission('Deny', 's3', 'DeleteObject', ['arn:aws:s3:::bucket/*'], undefined, undefined)
    )

    // When cloning the permission set and modifying the clone
    const cloned = original.clone()
    cloned.addPermission(
      new Permission('Deny', 'ec2', 'TerminateInstances', ['*'], undefined, undefined)
    )

    // Then the original should be unchanged
    expect(original.getAllPermissions()).toHaveLength(1)
    expect(original.hasService('ec2')).toBe(false)

    // And the clone should have the additional permission
    expect(cloned.getAllPermissions()).toHaveLength(2)
    expect(cloned.hasService('ec2')).toBe(true)
    expect(cloned.hasAction('ec2', 'TerminateInstances')).toBe(true)
  })

  it('should preserve effect type in cloned permission set', () => {
    // Given a Deny permission set
    const denySet = new PermissionSet('Deny')
    denySet.addPermission(new Permission('Deny', 's3', 'DeleteBucket', ['*'], undefined, undefined))

    // When cloning the permission set
    const clonedDenySet = denySet.clone()

    // Then the cloned set should maintain the Deny effect
    expect(clonedDenySet.effect).toBe('Deny')
    expect(clonedDenySet.getAllPermissions()[0].effect).toBe('Deny')
  })

  it('should clone complex permissions with conditions and notResource', () => {
    // Given a permission set with complex permissions
    const original = new PermissionSet('Allow')
    original.addPermission(
      new Permission('Allow', 's3', 'GetObject', undefined, ['arn:aws:s3:::sensitive-bucket/*'], {
        StringEquals: { 'aws:PrincipalTag/Department': ['Engineering'] },
        DateGreaterThan: { 'aws:CurrentTime': ['2023-01-01T00:00:00Z'] }
      })
    )

    // When cloning the permission set
    const cloned = original.clone()

    // Then the cloned permission should have the same complex attributes
    const originalPerm = original.getAllPermissions()[0]
    const clonedPerm = cloned.getAllPermissions()[0]

    expect(clonedPerm.notResource).toEqual(originalPerm.notResource)
    expect(clonedPerm.conditions).toEqual(originalPerm.conditions)
    expect(clonedPerm.resource).toEqual(originalPerm.resource)
  })
})

const toPolicyStatementsTests: {
  name: string
  only?: true
  permissions: TestPermission[]
  expectedStatements: any[]
}[] = [
  {
    name: 'Single permission',
    permissions: [{ action: 's3:ListBucket', effect: 'Allow', resource: ['*'] }],
    expectedStatements: [
      {
        Effect: 'Allow',
        Action: 's3:ListBucket',
        Resource: ['*']
      }
    ]
  },
  {
    name: 'Multiple permissions with merging',
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
    expectedStatements: [
      {
        Effect: 'Allow',
        Action: 's3:ListBucket',
        Resource: ['*'],
        Condition: { stringequals: { 'aws:requesttag/project': ['Test1', 'Test2'] } }
      }
    ]
  },
  // Test of multiple actions that should be merged to an array
  {
    name: 'Multiple actions with merging',
    permissions: [
      { action: 's3:ListBucket', effect: 'Allow', resource: ['*'] },
      { action: 's3:GetObject', effect: 'Allow', resource: ['*'] }
    ],
    expectedStatements: [
      {
        Effect: 'Allow',
        Action: ['s3:GetObject', 's3:ListBucket'],
        Resource: ['*']
      }
    ]
  },
  // Test with a NotResource
  {
    name: 'Permission with NotResource',
    permissions: [
      {
        action: 's3:DeleteObject',
        effect: 'Allow',
        notResource: ['arn:aws:s3:::sensitive-bucket/*']
      }
    ],
    expectedStatements: [
      {
        Effect: 'Allow',
        Action: 's3:DeleteObject',
        NotResource: ['arn:aws:s3:::sensitive-bucket/*']
      }
    ]
  }
]

describe('toPolicyStatements', () => {
  for (const test of toPolicyStatementsTests) {
    const func = test.only ? it.only : it
    func(test.name, () => {
      // Given a permission set with the given permissions
      const permissionSet = new PermissionSet('Allow')
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

      // When converting to policy statements
      const statements = toPolicyStatements(permissionSet)

      // Then the generated statements should match the expected statements
      expect(statements).toEqual(test.expectedStatements)
    })
  }
})
