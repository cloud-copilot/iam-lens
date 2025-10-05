import { describe, expect, it } from 'vitest'
import { invertConditions, Permission, PermissionConditions } from './permission.js'

interface TestPermission {
  effect: 'Allow' | 'Deny'
  action: string
  resource?: string[]
  notResource?: string[]
  conditions?: PermissionConditions
}

const permissionIncludesTests: {
  only?: true
  name: string
  permission: TestPermission
  otherPermission: TestPermission
  included: boolean
}[] = [
  {
    name: 'Wildcard resource matches specific resource',
    permission: {
      effect: 'Allow',
      action: 's3:GetObject',
      resource: ['*']
    },
    otherPermission: {
      effect: 'Allow',
      action: 's3:GetObject',
      resource: ['arn:aws:s3:::mybucket/file']
    },
    included: true
  },
  {
    name: 'Specific resource does not include wildcard resource',
    permission: {
      effect: 'Allow',
      action: 's3:GetObject',
      resource: ['arn:aws:s3:::mybucket/file']
    },
    otherPermission: {
      effect: 'Allow',
      action: 's3:GetObject',
      resource: ['*']
    },
    included: false
  },
  {
    name: 'Resource array with multiple patterns includes specific resource',
    permission: {
      effect: 'Allow',
      action: 's3:GetObject',
      resource: ['arn:aws:s3:::mybucket/*', 'arn:aws:s3:::otherbucket/*']
    },
    otherPermission: {
      effect: 'Allow',
      action: 's3:GetObject',
      resource: ['arn:aws:s3:::otherbucket/somefile']
    },
    included: true
  },
  {
    name: 'Resource array with multiple patterns does not include non-matching resource',
    permission: {
      effect: 'Allow',
      action: 's3:GetObject',
      resource: ['arn:aws:s3:::mybucket/*', 'arn:aws:s3:::otherbucket/*']
    },
    otherPermission: {
      effect: 'Allow',
      action: 's3:GetObject',
      resource: ['arn:aws:s3:::thirdbucket/file']
    },
    included: false
  },
  {
    name: 'Permission with resource wildcard includes other permission with notResource',
    permission: {
      effect: 'Allow',
      action: 's3:GetObject',
      resource: ['*']
    },
    otherPermission: {
      effect: 'Allow',
      action: 's3:GetObject',
      notResource: ['arn:aws:s3:::mybucket/file']
    },
    included: true
  },
  {
    name: 'Permission with notResource includes other permission with resource',
    permission: {
      effect: 'Allow',
      action: 's3:GetObject',
      notResource: ['arn:aws:s3:::mybucket/file']
    },
    otherPermission: {
      effect: 'Allow',
      action: 's3:GetObject',
      resource: ['arn:aws:s3:::otherbucket/file']
    },
    included: true
  },
  {
    name: 'Both permissions using notResource',
    permission: {
      effect: 'Allow',
      action: 's3:GetObject',
      notResource: ['arn:aws:s3:::mybucket/file']
    },
    otherPermission: {
      effect: 'Allow',
      action: 's3:GetObject',
      notResource: ['arn:aws:s3:::mybucket/file', 'arn:aws:s3:::otherbucket/file']
    },
    included: true
  },
  {
    name: 'NotResource with wildcard includes specific not resource',
    permission: {
      effect: 'Allow',
      action: 's3:GetObject',
      notResource: ['arn:aws:s3:::mybucket/file*']
    },
    otherPermission: {
      effect: 'Allow',
      action: 's3:GetObject',
      notResource: ['arn:aws:s3:::mybucket/file2']
    },
    included: true
  },
  {
    name: 'Conditions: StringEquals superset includes subset (true)',
    permission: {
      effect: 'Allow',
      action: 's3:GetObject',
      resource: ['*'],
      conditions: {
        StringEquals: {
          'aws:username': ['alice', 'bob', 'carol']
        }
      }
    },
    otherPermission: {
      effect: 'Allow',
      action: 's3:GetObject',
      resource: ['*'],
      conditions: {
        StringEquals: {
          'aws:username': ['alice', 'bob']
        }
      }
    },
    included: true
  },
  {
    name: 'Conditions: StringEquals with disjoint values (false)',
    permission: {
      effect: 'Allow',
      action: 's3:GetObject',
      resource: ['*'],
      conditions: {
        StringEquals: {
          'aws:username': ['alice']
        }
      }
    },
    otherPermission: {
      effect: 'Allow',
      action: 's3:GetObject',
      resource: ['*'],
      conditions: {
        StringEquals: {
          'aws:username': ['bob']
        }
      }
    },
    included: false
  },
  {
    name: 'Conditions: Different operators (false)',
    permission: {
      effect: 'Allow',
      action: 's3:GetObject',
      resource: ['*'],
      conditions: {
        StringEquals: {
          'aws:username': ['alice']
        }
      }
    },
    otherPermission: {
      effect: 'Allow',
      action: 's3:GetObject',
      resource: ['*'],
      conditions: {
        StringLike: {
          'aws:username': ['alice*']
        }
      }
    },
    included: false
  },
  {
    name: 'Conditions: NumericLessThan superset includes subset (true)',
    permission: {
      effect: 'Allow',
      action: 's3:GetObject',
      resource: ['*'],
      conditions: {
        NumericLessThan: {
          's3:max-keys': ['100']
        }
      }
    },
    otherPermission: {
      effect: 'Allow',
      action: 's3:GetObject',
      resource: ['*'],
      conditions: {
        NumericLessThan: {
          's3:max-keys': ['50']
        }
      }
    },
    included: true
  },
  {
    name: 'Conditions: NumericGreaterThan superset includes subset (true)',
    permission: {
      effect: 'Allow',
      action: 's3:GetObject',
      resource: ['*'],
      conditions: {
        NumericGreaterThan: {
          's3:min-keys': ['10']
        }
      }
    },
    otherPermission: {
      effect: 'Allow',
      action: 's3:GetObject',
      resource: ['*'],
      conditions: {
        NumericGreaterThan: {
          's3:min-keys': ['20']
        }
      }
    },
    included: true
  },
  {
    name: 'Conditions: DateLessThan superset includes subset (true)',
    permission: {
      effect: 'Allow',
      action: 's3:GetObject',
      resource: ['*'],
      conditions: {
        DateLessThan: {
          'aws:CurrentTime': ['2024-12-31T23:59:59Z']
        }
      }
    },
    otherPermission: {
      effect: 'Allow',
      action: 's3:GetObject',
      resource: ['*'],
      conditions: {
        DateLessThan: {
          'aws:CurrentTime': ['2024-06-30T23:59:59Z']
        }
      }
    },
    included: true
  },
  {
    name: 'Conditions: DateGreaterThan superset includes subset (true)',
    permission: {
      effect: 'Allow',
      action: 's3:GetObject',
      resource: ['*'],
      conditions: {
        DateGreaterThan: {
          'aws:CurrentTime': ['2024-01-01T00:00:00Z']
        }
      }
    },
    otherPermission: {
      effect: 'Allow',
      action: 's3:GetObject',
      resource: ['*'],
      conditions: {
        DateGreaterThan: {
          'aws:CurrentTime': ['2024-06-01T00:00:00Z']
        }
      }
    },
    included: true
  },
  {
    name: 'Conditions: Bool equals (true)',
    permission: {
      effect: 'Allow',
      action: 's3:GetObject',
      resource: ['*'],
      conditions: {
        Bool: {
          'aws:SecureTransport': ['true']
        }
      }
    },
    otherPermission: {
      effect: 'Allow',
      action: 's3:GetObject',
      resource: ['*'],
      conditions: {
        Bool: {
          'aws:SecureTransport': ['true']
        }
      }
    },
    included: true
  },
  {
    name: 'Conditions: Bool not equal (false)',
    permission: {
      effect: 'Allow',
      action: 's3:GetObject',
      resource: ['*'],
      conditions: {
        Bool: {
          'aws:SecureTransport': ['true']
        }
      }
    },
    otherPermission: {
      effect: 'Allow',
      action: 's3:GetObject',
      resource: ['*'],
      conditions: {
        Bool: {
          'aws:SecureTransport': ['false']
        }
      }
    },
    included: false
  },
  {
    //TODO: Eventually would like to support CIDR overlap checking
    name: 'Conditions: IpAddress superset includes subset (false)',
    permission: {
      effect: 'Allow',
      action: 's3:GetObject',
      resource: ['*'],
      conditions: {
        IpAddress: {
          'aws:SourceIp': ['192.168.0.0/16']
        }
      }
    },
    otherPermission: {
      effect: 'Allow',
      action: 's3:GetObject',
      resource: ['*'],
      conditions: {
        IpAddress: {
          'aws:SourceIp': ['192.168.1.1/32']
        }
      }
    },
    included: false
  },
  {
    name: 'Conditions: ForAllValues:StringEquals superset includes subset (true)',
    permission: {
      effect: 'Allow',
      action: 's3:GetObject',
      resource: ['*'],
      conditions: {
        'ForAllValues:StringEquals': {
          'aws:username': ['alice', 'bob', 'carol']
        }
      }
    },
    otherPermission: {
      effect: 'Allow',
      action: 's3:GetObject',
      resource: ['*'],
      conditions: {
        'ForAllValues:StringEquals': {
          'aws:username': ['alice', 'bob']
        }
      }
    },
    included: true
  },
  {
    name: 'Conditions: ForAnyValue:StringEquals superset includes subset (true)',
    permission: {
      effect: 'Allow',
      action: 's3:GetObject',
      resource: ['*'],
      conditions: {
        'ForAnyValue:StringEquals': {
          'aws:username': ['alice', 'bob', 'carol']
        }
      }
    },
    otherPermission: {
      effect: 'Allow',
      action: 's3:GetObject',
      resource: ['*'],
      conditions: {
        'ForAnyValue:StringEquals': {
          'aws:username': ['alice', 'bob']
        }
      }
    },
    included: true
  },
  {
    name: 'Conditions: StringEqualsIfExists superset includes subset (true)',
    permission: {
      effect: 'Allow',
      action: 's3:GetObject',
      resource: ['*'],
      conditions: {
        StringEqualsIfExists: {
          'aws:username': ['alice', 'bob', 'carol']
        }
      }
    },
    otherPermission: {
      effect: 'Allow',
      action: 's3:GetObject',
      resource: ['*'],
      conditions: {
        StringEqualsIfExists: {
          'aws:username': ['alice', 'bob']
        }
      }
    },
    included: true
  },
  {
    name: 'Conditions: StringEqualsIfExists with disjoint values (false)',
    permission: {
      effect: 'Allow',
      action: 's3:GetObject',
      resource: ['*'],
      conditions: {
        StringEqualsIfExists: {
          'aws:username': ['alice']
        }
      }
    },
    otherPermission: {
      effect: 'Allow',
      action: 's3:GetObject',
      resource: ['*'],
      conditions: {
        StringEqualsIfExists: {
          'aws:username': ['bob']
        }
      }
    },
    included: false
  },
  {
    name: 'Conditions: NumericLessThanIfExists superset includes subset (true)',
    permission: {
      effect: 'Allow',
      action: 's3:GetObject',
      resource: ['*'],
      conditions: {
        NumericLessThanIfExists: {
          's3:max-keys': ['100']
        }
      }
    },
    otherPermission: {
      effect: 'Allow',
      action: 's3:GetObject',
      resource: ['*'],
      conditions: {
        NumericLessThanIfExists: {
          's3:max-keys': ['50']
        }
      }
    },
    included: true
  },
  {
    name: 'Conditions: NumericLessThanIfExists with disjoint boundary (false)',
    permission: {
      effect: 'Allow',
      action: 's3:GetObject',
      resource: ['*'],
      conditions: {
        NumericLessThanIfExists: {
          's3:max-keys': ['50']
        }
      }
    },
    otherPermission: {
      effect: 'Allow',
      action: 's3:GetObject',
      resource: ['*'],
      conditions: {
        NumericLessThanIfExists: {
          's3:max-keys': ['100']
        }
      }
    },
    included: false
  },
  {
    name: 'both notresource permissions',
    permission: {
      effect: 'Allow',
      action: 's3:PutObject',
      notResource: ['arn:aws:s3:::data/*', 'arn:aws:s3:::config/*']
    },
    otherPermission: {
      effect: 'Allow',
      action: 's3:PutObject',
      notResource: ['arn:aws:s3:::data/private*', 'arn:aws:s3:::config/*']
    },
    // intersection of notResource => ['arn:aws:s3:::config/*']
    included: true
  }
]

describe('Permission#includes', () => {
  for (const test of permissionIncludesTests) {
    const func = test.only ? it.only : it

    func(test.name, () => {
      //Given a permission and another permission
      const [thisService, thisAction] = test.permission.action.split(':')
      const permission = new Permission(
        test.permission.effect,
        thisService,
        thisAction,
        test.permission.resource,
        test.permission.notResource,
        test.permission.conditions
      )

      const [otherService, otherAction] = test.otherPermission.action.split(':')
      const otherPermission = new Permission(
        test.otherPermission.effect,
        thisService,
        thisAction,
        test.otherPermission.resource,
        test.otherPermission.notResource,
        test.otherPermission.conditions
      )

      //When we check if the permission includes the other permission
      const result = permission.includes(otherPermission)

      //Then the result should match the expected value
      expect(result).toBe(test.included)
    })
  }
})

const permissionUnionTests: {
  only?: true
  name: string

  first: TestPermission
  second: TestPermission
  merged?: boolean | TestPermission
}[] = [
  {
    name: 'merge two with similar resources',
    first: {
      effect: 'Allow',
      action: 's3:GetObject',
      resource: ['arn:aws:s3:::mybucket/file1', 'arn:aws:s3:::mybucket/file2']
    },
    second: {
      effect: 'Allow',
      action: 's3:GetObject',
      resource: ['arn:aws:s3:::mybucket/file2', 'arn:aws:s3:::mybucket/file3']
    },

    merged: {
      effect: 'Allow',
      action: 's3:GetObject',
      resource: [
        'arn:aws:s3:::mybucket/file1',
        'arn:aws:s3:::mybucket/file2',
        'arn:aws:s3:::mybucket/file3'
      ]
    }
  },
  {
    name: 'merge two notResource permissions',
    first: {
      effect: 'Allow',
      action: 's3:GetObject',
      notResource: ['arn:aws:s3:::mybucket/file1', 'arn:aws:s3:::mybucket/file2']
    },
    second: {
      effect: 'Allow',
      action: 's3:GetObject',
      notResource: ['arn:aws:s3:::mybucket/file2', 'arn:aws:s3:::mybucket/file3']
    },
    // union of notResource is intersection of arrays => ['arn:aws:s3:::mybucket/file2']
    merged: {
      effect: 'Allow',
      action: 's3:GetObject',
      notResource: ['arn:aws:s3:::mybucket/file2']
    }
  },
  {
    name: 'resource and notResource cannot merge, return both',
    first: {
      effect: 'Allow',
      action: 's3:GetObject',
      resource: ['arn:aws:s3:::mybucket/file1']
    },
    second: {
      effect: 'Allow',
      action: 's3:GetObject',
      notResource: ['arn:aws:s3:::mybucket/file2']
    },
    merged: {
      effect: 'Allow',
      action: 's3:GetObject',
      notResource: ['arn:aws:s3:::mybucket/file2']
    }
  },
  {
    name: 'conditions merge for StringEquals',
    first: {
      effect: 'Allow',
      action: 's3:GetObject',
      resource: ['*'],
      conditions: {
        StringEquals: { 'aws:username': ['alice'] }
      }
    },
    second: {
      effect: 'Allow',
      action: 's3:GetObject',
      resource: ['*'],
      conditions: {
        StringEquals: { 'aws:username': ['bob'] }
      }
    },
    merged: {
      effect: 'Allow',
      action: 's3:GetObject',
      resource: ['*'],
      conditions: {
        stringequals: { 'aws:username': ['alice', 'bob'] }
      }
    }
  },
  {
    name: 'conditions cannot merge different operators',
    first: {
      effect: 'Allow',
      action: 's3:GetObject',
      resource: ['*'],
      conditions: {
        StringEquals: { 'aws:username': ['alice'] }
      }
    },
    second: {
      effect: 'Allow',
      action: 's3:GetObject',
      resource: ['*'],
      conditions: {
        NumericLessThan: { 's3:max-keys': ['50'] }
      }
    },
    merged: false
  },
  {
    name: 'merge wildcard and specific resources',
    first: {
      effect: 'Allow',
      action: 's3:GetObject',
      resource: ['arn:aws:s3:::mybucket/*']
    },
    second: {
      effect: 'Allow',
      action: 's3:GetObject',
      resource: ['arn:aws:s3:::mybucket/file1', 'arn:aws:s3:::mybucket/file2']
    },
    merged: {
      effect: 'Allow',
      action: 's3:GetObject',
      resource: ['arn:aws:s3:::mybucket/*']
    }
  },
  {
    name: 'merge notResource wildcards intersection',
    first: {
      effect: 'Allow',
      action: 's3:PutObject',
      notResource: ['arn:aws:s3:::data/*', 'arn:aws:s3:::config/*']
    },
    second: {
      effect: 'Allow',
      action: 's3:PutObject',
      notResource: ['arn:aws:s3:::stuff/*', 'arn:aws:s3:::config/*']
    },
    // intersection of notResource => ['arn:aws:s3:::config/*']
    merged: {
      effect: 'Allow',
      action: 's3:PutObject',
      notResource: ['arn:aws:s3:::config/*']
    }
  },
  {
    name: 'merge multiple condition operators',
    first: {
      effect: 'Allow',
      action: 'ec2:StartInstances',
      resource: ['*'],
      conditions: {
        StringEquals: { 'aws:PrincipalOrgId': ['o-123'] },
        Bool: { 'aws:multifactorauthpresent': ['true'] }
      }
    },
    second: {
      effect: 'Allow',
      action: 'ec2:StartInstances',
      resource: ['*'],
      conditions: {
        StringEquals: { 'aws:PrincipalOrgId': ['o-456'] },
        Bool: { 'aws:multifactorauthpresent': ['true'] }
      }
    },
    merged: {
      effect: 'Allow',
      action: 'ec2:StartInstances',
      resource: ['*'],
      conditions: {
        stringequals: { 'aws:principalorgid': ['o-123', 'o-456'] },
        bool: { 'aws:multifactorauthpresent': ['true'] }
      }
    }
  },
  {
    name: 'cannot merge condition if values disjoint under different keys',
    first: {
      effect: 'Allow',
      action: 'ec2:StopInstances',
      resource: ['*'],
      conditions: {
        stringequals: { 'aws:principalorgid': ['o-123'] }
      }
    },
    second: {
      effect: 'Allow',
      action: 'ec2:StopInstances',
      resource: ['*'],
      conditions: {
        stringequals: { 'aws:sourcevpce': ['vpce-1a2b'] }
      }
    },
    merged: false
  },
  {
    name: 'merge ForAllValues and ForAnyValue conditions',
    first: {
      effect: 'Allow',
      action: 'lambda:InvokeFunction',
      resource: ['*'],
      conditions: {
        'forallvalues:stringequals': { 'aws:lambdaexecpolicies': ['PolicyA', 'PolicyB'] }
      }
    },
    second: {
      effect: 'Allow',
      action: 'lambda:InvokeFunction',
      resource: ['*'],
      conditions: {
        'forallvalues:stringequals': { 'aws:lambdaexecpolicies': ['PolicyC'] }
      }
    },
    merged: {
      effect: 'Allow',
      action: 'lambda:InvokeFunction',
      resource: ['*'],
      conditions: {
        'forallvalues:stringequals': { 'aws:lambdaexecpolicies': ['PolicyA', 'PolicyB', 'PolicyC'] }
      }
    }
  },
  {
    name: 'non overlapping',
    first: {
      action: 's3:ListBucket',
      effect: 'Allow',
      resource: ['*'],
      conditions: { StringEquals: { 'aws:RequestTag/Project': ['Test'] } }
    },
    second: {
      action: 's3:ListBucket',
      effect: 'Allow',
      resource: ['*'],
      conditions: { StringEquals: { 'aws:RequestTag/Department': ['Test'] } }
    },
    merged: false
  }
]

describe('Permission#union', () => {
  for (const test of permissionIncludesTests.filter((t) => t.included)) {
    const func = test.only ? it.only : it
    func(`includes test for: ${test.name}`, () => {
      //Given a permission and another permission that includes it
      const [thisService, thisAction] = test.permission.action.split(':')
      const firstPermission = new Permission(
        test.permission.effect,
        thisService,
        thisAction,
        test.permission.resource,
        test.permission.notResource,
        test.permission.conditions
      )

      const [secondService, secondAction] = test.otherPermission.action.split(':')
      const secondPermission = new Permission(
        test.otherPermission.effect,
        secondService,
        secondAction,
        test.otherPermission.resource,
        test.otherPermission.notResource,
        test.otherPermission.conditions
      )

      //When we check if the permission includes the other permission
      const result = firstPermission.union(secondPermission)

      //Then they should be merged
      expect(result.length).toEqual(1)
      const mergedPermission = result[0]
      expect(mergedPermission.effect).toBe(firstPermission.effect)
      expect(mergedPermission.action).toBe(firstPermission.action)
      expect(mergedPermission.resource).toEqual(firstPermission.resource)
      expect(mergedPermission.notResource).toEqual(firstPermission.notResource)
      expect(mergedPermission.conditions).toEqual(firstPermission.conditions)
    })
  }

  for (const test of permissionUnionTests) {
    const func = test.only ? it.only : it

    func(test.name, () => {
      //Given two permissions
      const [firstService, firstAction] = test.first.action.split(':')
      const firstPermission = new Permission(
        test.first.effect,
        firstService,
        firstAction,
        test.first.resource,
        test.first.notResource,
        test.first.conditions
      )

      const [secondService, secondAction] = test.second.action.split(':')
      const secondPermission = new Permission(
        test.second.effect,
        secondService,
        secondAction,
        test.second.resource,
        test.second.notResource,
        test.second.conditions
      )

      //When we merge the permissions
      let result: Permission[] | null = null
      result = firstPermission.union(secondPermission)

      //Then the result should match the expected value
      if (test.merged === false) {
        expect(result.length).toEqual(2)
      } else if (test.merged) {
        expect(result.length).toEqual(1)
        const expectedMerge = test.merged as TestPermission
        const [expectedService, expectedAction] = expectedMerge.action.split(':')
        const actualMerge = result[0]
        expect(actualMerge.effect).toBe(expectedMerge.effect)
        expect(actualMerge.service).toBe(expectedService)
        expect(actualMerge.action).toBe(expectedAction)
        expect(actualMerge.resource).toEqual(expectedMerge.resource)
        expect(actualMerge.notResource).toEqual(expectedMerge.notResource)
        expect(actualMerge.conditions).toEqual(expectedMerge.conditions)
      } else {
        expect(true, 'This should never happen').toBe(false)
      }
    })
  }
})

const intersectionTests: {
  only?: true
  name: string
  permission: TestPermission
  otherPermission: TestPermission
  intersection: TestPermission | false
}[] = [
  {
    name: 'one includes the other (wildcard)',
    permission: {
      effect: 'Allow',
      action: 's3:GetObject',
      resource: ['*']
    },
    otherPermission: {
      effect: 'Allow',
      action: 's3:GetObject',
      resource: ['arn:aws:s3:::mybucket/file']
    },
    intersection: {
      effect: 'Allow',
      action: 's3:GetObject',
      resource: ['arn:aws:s3:::mybucket/file']
    }
  },
  {
    name: 'intersection of two specific resource lists',
    permission: {
      effect: 'Allow',
      action: 's3:GetObject',
      resource: ['arn:aws:s3:::mybucket/file1', 'arn:aws:s3:::mybucket/file2']
    },
    otherPermission: {
      effect: 'Allow',
      action: 's3:GetObject',
      resource: ['arn:aws:s3:::mybucket/file2', 'arn:aws:s3:::mybucket/file3']
    },
    intersection: {
      effect: 'Allow',
      action: 's3:GetObject',
      resource: ['arn:aws:s3:::mybucket/file2']
    }
  },
  {
    name: 'intersection of two notResource lists with overlap',
    permission: {
      effect: 'Allow',
      action: 's3:PutObject',
      notResource: ['arn:aws:s3:::data/*', 'arn:aws:s3:::config/*']
    },
    otherPermission: {
      effect: 'Allow',
      action: 's3:PutObject',
      notResource: ['arn:aws:s3:::data/private*', 'arn:aws:s3:::config/*']
    },
    intersection: {
      effect: 'Allow',
      action: 's3:PutObject',
      notResource: ['arn:aws:s3:::data/*', 'arn:aws:s3:::config/*']
    }
  },

  {
    name: 'intersection of two notResource lists without overlap',
    permission: {
      effect: 'Allow',
      action: 's3:PutObject',
      notResource: ['arn:aws:s3:::data/*', 'arn:aws:s3:::config/*']
    },
    otherPermission: {
      effect: 'Allow',
      action: 's3:PutObject',
      notResource: ['arn:aws:s3:::logs/*', 'arn:aws:s3:::config/*']
    },
    intersection: {
      effect: 'Allow',
      action: 's3:PutObject',
      notResource: ['arn:aws:s3:::data/*', 'arn:aws:s3:::config/*', 'arn:aws:s3:::logs/*']
    }
  },
  {
    name: 'intersection with matching conditions',
    permission: {
      effect: 'Allow',
      action: 'ec2:StartInstances',
      resource: ['*'],
      conditions: {
        StringEquals: { 'aws:PrincipalOrgId': ['o-123'] }
      }
    },
    otherPermission: {
      effect: 'Allow',
      action: 'ec2:StartInstances',
      resource: ['*'],
      conditions: {
        StringEquals: { 'aws:PrincipalOrgId': ['o-123', 'o-456'] }
      }
    },
    intersection: {
      effect: 'Allow',
      action: 'ec2:StartInstances',
      resource: ['*'],
      conditions: {
        StringEquals: { 'aws:PrincipalOrgId': ['o-123'] }
      }
    }
  },
  {
    name: 'intersection with different conditions merges conditions',
    permission: {
      effect: 'Allow',
      action: 'ec2:StopInstances',
      resource: ['*'],
      conditions: {
        StringEquals: { 'aws:PrincipalOrgId': ['o-123'] }
      }
    },
    otherPermission: {
      effect: 'Allow',
      action: 'ec2:StopInstances',
      resource: ['*'],
      conditions: {
        StringEquals: { 'aws:SourceVpc': ['vpc-abc'] }
      }
    },
    intersection: {
      effect: 'Allow',
      action: 'ec2:StopInstances',
      resource: ['*'],
      conditions: {
        stringequals: { 'aws:principalorgid': ['o-123'], 'aws:sourcevpc': ['vpc-abc'] }
      }
    }
  },
  {
    name: 'intersection of wildcard resource patterns',
    permission: {
      effect: 'Allow',
      action: 's3:GetObject',
      resource: ['arn:aws:s3:::mybucket/*']
    },
    otherPermission: {
      effect: 'Allow',
      action: 's3:GetObject',
      resource: ['arn:aws:s3:::mybucket/file*']
    },
    intersection: {
      effect: 'Allow',
      action: 's3:GetObject',
      resource: ['arn:aws:s3:::mybucket/file*']
    }
  },
  {
    name: 'intersection of disjoint wildcard resources (false)',
    permission: {
      effect: 'Allow',
      action: 's3:GetObject',
      resource: ['arn:aws:s3:::mybucket/*']
    },
    otherPermission: {
      effect: 'Allow',
      action: 's3:GetObject',
      resource: ['arn:aws:s3:::otherbucket/*']
    },
    intersection: false
  },
  {
    name: 'intersection carries through distinct condition keys',
    permission: {
      effect: 'Allow',
      action: 'ec2:StartInstances',
      resource: ['*'],
      conditions: {
        StringEquals: { 'aws:PrincipalOrgId': ['o-123'] }
      }
    },
    otherPermission: {
      effect: 'Allow',
      action: 'ec2:StartInstances',
      resource: ['*'],
      conditions: {
        Bool: { 'aws:MultiFactorAuthPresent': ['true'] }
      }
    },
    intersection: {
      effect: 'Allow',
      action: 'ec2:StartInstances',
      resource: ['*'],
      conditions: {
        stringequals: { 'aws:principalorgid': ['o-123'] },
        bool: { 'aws:multifactorauthpresent': ['true'] }
      }
    }
  },
  {
    name: 'intersection of numeric and date conditions',
    permission: {
      effect: 'Allow',
      action: 'lambda:InvokeFunction',
      resource: ['*'],
      conditions: {
        NumericLessThan: { 'lambda:timeout': ['300'] },
        DateGreaterThanEquals: { 'aws:CurrentTime': ['2024-01-01T00:00:00Z'] }
      }
    },
    otherPermission: {
      effect: 'Allow',
      action: 'lambda:InvokeFunction',
      resource: ['*'],
      conditions: {
        NumericLessThan: { 'lambda:timeout': ['200'] },
        DateGreaterThanEquals: { 'aws:CurrentTime': ['2024-06-01T00:00:00Z'] }
      }
    },
    intersection: {
      effect: 'Allow',
      action: 'lambda:InvokeFunction',
      resource: ['*'],
      conditions: {
        NumericLessThan: { 'lambda:timeout': ['200'] },
        DateGreaterThanEquals: { 'aws:CurrentTime': ['2024-06-01T00:00:00Z'] }
      }
    }
  },
  {
    name: 'intersection of notResource with wildcard and specific',
    permission: {
      effect: 'Allow',
      action: 'sqs:SendMessage',
      notResource: ['arn:aws:sqs:us-east-1:123456789012:queue/*']
    },
    otherPermission: {
      effect: 'Allow',
      action: 'sqs:SendMessage',
      notResource: ['arn:aws:sqs:us-east-1:123456789012:queue/secure-*']
    },
    intersection: {
      effect: 'Allow',
      action: 'sqs:SendMessage',
      notResource: ['arn:aws:sqs:us-east-1:123456789012:queue/*']
    }
  },
  {
    name: 'intersection with no overlapping notResource (union exclusions)',
    permission: {
      effect: 'Allow',
      action: 'sqs:ReceiveMessage',
      notResource: ['arn:aws:sqs:us-east-1:123456789012:queue/alpha']
    },
    otherPermission: {
      effect: 'Allow',
      action: 'sqs:ReceiveMessage',
      notResource: ['arn:aws:sqs:us-east-1:123456789012:queue/beta']
    },
    intersection: {
      effect: 'Allow',
      action: 'sqs:ReceiveMessage',
      notResource: [
        'arn:aws:sqs:us-east-1:123456789012:queue/alpha',
        'arn:aws:sqs:us-east-1:123456789012:queue/beta'
      ]
    }
  },
  {
    name: 'intersection of two StringEquals with overlap',
    permission: {
      effect: 'Allow',
      action: 'iam:PassRole',
      resource: ['*'],
      conditions: {
        StringEquals: { 'aws:principalaccountid': ['111111111111', '222222222222'] }
      }
    },
    otherPermission: {
      effect: 'Allow',
      action: 'iam:PassRole',
      resource: ['*'],
      conditions: {
        StringEquals: { 'aws:principalaccountid': ['222222222222', '333333333333'] }
      }
    },
    intersection: {
      effect: 'Allow',
      action: 'iam:PassRole',
      resource: ['*'],
      conditions: {
        stringequals: { 'aws:principalaccountid': ['222222222222'] }
      }
    }
  },
  {
    name: 'intersection of two StringEquals with no overlap (false)',
    permission: {
      effect: 'Allow',
      action: 'iam:PassRole',
      resource: ['*'],
      conditions: {
        StringEquals: { 'aws:principalaccountid': ['111111111111'] }
      }
    },
    otherPermission: {
      effect: 'Allow',
      action: 'iam:PassRole',
      resource: ['*'],
      conditions: {
        StringEquals: { 'aws:principalaccountid': ['222222222222'] }
      }
    },
    intersection: false
  },
  {
    name: 'intersection of two StringNotEquals',
    permission: {
      effect: 'Allow',
      action: 'iam:CreateUser',
      resource: ['*'],
      conditions: {
        StringNotEquals: { 'aws:username': ['alice'] }
      }
    },
    otherPermission: {
      effect: 'Allow',
      action: 'iam:CreateUser',
      resource: ['*'],
      conditions: {
        StringNotEquals: { 'aws:username': ['bob'] }
      }
    },
    intersection: {
      effect: 'Allow',
      action: 'iam:CreateUser',
      resource: ['*'],
      conditions: {
        stringnotequals: { 'aws:username': ['alice', 'bob'] }
      }
    }
  },
  {
    name: 'intersection of StringEquals and StringNotEquals on same key',
    permission: {
      effect: 'Allow',
      action: 'sts:AssumeRole',
      resource: ['*'],
      conditions: {
        StringEquals: { 'aws:principalaccountid': ['111111111111', '222222222222'] }
      }
    },
    otherPermission: {
      effect: 'Allow',
      action: 'sts:AssumeRole',
      resource: ['*'],
      conditions: {
        StringNotEquals: { 'aws:principalaccountid': ['222222222222'] }
      }
    },
    intersection: {
      effect: 'Allow',
      action: 'sts:AssumeRole',
      resource: ['*'],
      conditions: {
        stringequals: { 'aws:principalaccountid': ['111111111111', '222222222222'] },
        stringnotequals: { 'aws:principalaccountid': ['222222222222'] }
      }
    }
  },
  {
    name: 'intersection of resource and notResource',
    permission: {
      effect: 'Allow',
      action: 's3:GetObject',
      resource: ['arn:aws:s3:::bucket1/file1', 'arn:aws:s3:::bucket1/file2']
    },
    otherPermission: {
      effect: 'Allow',
      action: 's3:GetObject',
      notResource: ['arn:aws:s3:::bucket1/file2']
    },
    intersection: {
      effect: 'Allow',
      action: 's3:GetObject',
      resource: ['arn:aws:s3:::bucket1/file1']
    }
  },
  {
    name: 'intersection of notResource and resource reversed',
    permission: {
      effect: 'Allow',
      action: 's3:GetObject',
      resource: ['arn:aws:s3:::bucket1/file1', 'arn:aws:s3:::bucket1/file2']
    },
    otherPermission: {
      effect: 'Allow',
      action: 's3:GetObject',
      notResource: ['arn:aws:s3:::bucket1/file2']
    },
    intersection: {
      effect: 'Allow',
      action: 's3:GetObject',
      resource: ['arn:aws:s3:::bucket1/file1']
    }
  },
  {
    name: 'intersection of resource list and notResource exclusion',
    permission: {
      effect: 'Allow',
      action: 's3:DeleteObject',
      resource: ['arn:aws:s3:::mybucket/logs/*', 'arn:aws:s3:::mybucket/data/*']
    },
    otherPermission: {
      effect: 'Allow',
      action: 's3:DeleteObject',
      notResource: ['arn:aws:s3:::mybucket/data/private/*']
    },
    intersection: {
      effect: 'Allow',
      action: 's3:DeleteObject',
      resource: ['arn:aws:s3:::mybucket/logs/*', 'arn:aws:s3:::mybucket/data/*']
    }
  },
  {
    name: 'intersection of notResource exclusion and resource list',
    permission: {
      effect: 'Allow',
      action: 'dynamodb:PutItem',
      notResource: ['arn:aws:dynamodb:us-west-2:123456789012:table/private-*']
    },
    otherPermission: {
      effect: 'Allow',
      action: 'dynamodb:PutItem',
      resource: [
        'arn:aws:dynamodb:us-west-2:123456789012:table/public-users',
        'arn:aws:dynamodb:us-west-2:123456789012:table/private-data'
      ]
    },
    intersection: {
      effect: 'Allow',
      action: 'dynamodb:PutItem',
      resource: ['arn:aws:dynamodb:us-west-2:123456789012:table/public-users']
    }
  },

  {
    name: 'intersection resource fully excluded by notResource yields undefined',
    permission: {
      effect: 'Allow',
      action: 's3:GetObject',
      resource: ['arn:aws:s3:::bucket1/file2']
    },
    otherPermission: {
      effect: 'Allow',
      action: 's3:GetObject',
      notResource: ['arn:aws:s3:::bucket1/file2']
    },
    intersection: false
  }
]

describe('Permission#intersection', () => {
  for (const test of intersectionTests) {
    const func = test.only ? it.only : it

    func(test.name, () => {
      //Given two permissions
      const [firstService, firstAction] = test.permission.action.split(':')
      const firstPermission = new Permission(
        test.permission.effect,
        firstService,
        firstAction,
        test.permission.resource,
        test.permission.notResource,
        test.permission.conditions
      )

      const [secondService, secondAction] = test.otherPermission.action.split(':')
      const secondPermission = new Permission(
        test.otherPermission.effect,
        secondService,
        secondAction,
        test.otherPermission.resource,
        test.otherPermission.notResource,
        test.otherPermission.conditions
      )

      //When we get the intersection of the permissions
      const result = firstPermission.intersection(secondPermission)

      //Then the result should match the expected value
      if (test.intersection === false) {
        expect(result).toBeUndefined()
      } else {
        expect(result).toBeDefined()
        const actualResult = result as Permission
        const expectedIntersection = test.intersection as TestPermission
        const [expectedService, expectedAction] = expectedIntersection.action.split(':')
        expect(actualResult.effect).toBe(expectedIntersection.effect)
        expect(actualResult.service).toBe(expectedService)
        expect(actualResult.action).toBe(expectedAction)
        expect(actualResult.resource).toEqual(expectedIntersection.resource)
        expect(actualResult.notResource).toEqual(expectedIntersection.notResource)
        expect(actualResult.conditions).toEqual(expectedIntersection.conditions)
      }
    })
  }
})

const subtractTests: {
  only?: true
  name: string
  allow: TestPermission
  deny: TestPermission
  expected: TestPermission[]
}[] = [
  {
    name: 'Simple Resource Subtraction',
    allow: {
      effect: 'Allow',
      action: 's3:GetObject',
      resource: ['arn:aws:s3:::mybucket/file1', 'arn:aws:s3:::mybucket/file2']
    },
    deny: {
      effect: 'Deny',
      action: 's3:GetObject',
      resource: ['arn:aws:s3:::mybucket/file2']
    },
    expected: [
      {
        effect: 'Allow',
        action: 's3:GetObject',
        resource: ['arn:aws:s3:::mybucket/file1']
      }
    ]
  },
  {
    name: 'Resource & Deny.notResource subtraction',
    allow: {
      effect: 'Allow',
      action: 's3:GetObject',
      resource: ['arn:aws:s3:::bucket1/file1', 'arn:aws:s3:::bucket1/file2']
    },
    deny: {
      effect: 'Deny',
      action: 's3:GetObject',
      notResource: ['arn:aws:s3:::bucket1/file2']
    },
    expected: [
      {
        effect: 'Allow',
        action: 's3:GetObject',
        resource: ['arn:aws:s3:::bucket1/file2']
      }
    ]
  },
  {
    name: 'NotResource & Deny.resource subtraction',
    allow: {
      effect: 'Allow',
      action: 's3:DeleteObject',
      notResource: ['arn:aws:s3:::bucket2/private/*']
    },
    deny: {
      effect: 'Deny',
      action: 's3:DeleteObject',
      resource: ['arn:aws:s3:::bucket2/logs/*']
    },
    expected: [
      {
        effect: 'Allow',
        action: 's3:DeleteObject',
        notResource: ['arn:aws:s3:::bucket2/private/*', 'arn:aws:s3:::bucket2/logs/*']
      }
    ]
  },
  {
    name: 'NotResource & Deny.notResource subtraction',
    allow: {
      effect: 'Allow',
      action: 'dynamodb:PutItem',
      notResource: [
        'arn:aws:dynamodb:us-west-2:123:table/data/*',
        'arn:aws:dynamodb:us-west-2:123:table/logs/*'
      ]
    },
    deny: {
      effect: 'Deny',
      action: 'dynamodb:PutItem',
      notResource: ['arn:aws:dynamodb:us-west-2:123:table/logs/*']
    },
    expected: [
      {
        effect: 'Allow',
        action: 'dynamodb:PutItem',
        notResource: ['arn:aws:dynamodb:us-west-2:123:table/data/*']
      }
    ]
  },
  {
    name: 'Full deny results in no permissions',
    allow: {
      effect: 'Allow',
      action: 'sqs:SendMessage',
      resource: ['arn:aws:sqs:us-east-1:123:queue/myqueue']
    },
    deny: {
      effect: 'Deny',
      action: 'sqs:SendMessage',
      resource: ['arn:aws:sqs:us-east-1:123:queue/myqueue']
    },
    expected: []
  },
  {
    name: 'Full deny when allow all and deny wildcard',
    allow: {
      effect: 'Allow',
      action: 's3:DeleteObject',
      resource: ['*']
    },
    deny: {
      effect: 'Deny',
      action: 's3:DeleteObject',
      resource: ['*']
    },
    expected: []
  },
  {
    name: 'Condition subtraction with identical conditions yields nothing',
    allow: {
      effect: 'Allow',
      action: 'ec2:StartInstances',
      resource: ['*'],
      conditions: {
        StringEquals: { 'aws:PrincipalOrgId': ['o-123'] }
      }
    },
    deny: {
      effect: 'Deny',
      action: 'ec2:StartInstances',
      resource: ['*'],
      conditions: {
        StringEquals: { 'aws:PrincipalOrgId': ['o-123'] }
      }
    },
    expected: []
  },
  {
    name: 'Condition subtraction with superset conditions',
    allow: {
      effect: 'Allow',
      action: 'ec2:StartInstances',
      resource: ['*'],
      conditions: {
        StringEquals: { 'aws:PrincipalOrgId': ['o-123', 'o-456'] }
      }
    },
    deny: {
      effect: 'Deny',
      action: 'ec2:StartInstances',
      resource: ['*'],
      conditions: {
        StringEquals: { 'aws:PrincipalOrgId': ['o-123'] }
      }
    },
    expected: [
      {
        effect: 'Allow',
        action: 'ec2:StartInstances',
        resource: ['*'],
        conditions: {
          stringequals: { 'aws:principalorgid': ['o-456'] }
        }
      }
    ]
  },
  {
    name: 'NotResource & Deny.resource subtraction',
    allow: {
      effect: 'Allow',
      action: 's3:DeleteObject',
      notResource: ['arn:aws:s3:::bucket2/private/*']
    },
    deny: {
      effect: 'Deny',
      action: 's3:DeleteObject',
      resource: ['arn:aws:s3:::bucket2/private/extra-private/*']
    },
    expected: [
      {
        effect: 'Allow',
        action: 's3:DeleteObject',
        notResource: ['arn:aws:s3:::bucket2/private/*']
      }
    ]
  },
  {
    name: 'Resource & Deny.resource subset subtraction',
    allow: {
      effect: 'Allow',
      action: 's3:DeleteObject',
      resource: ['arn:aws:s3:::bucket2/private/*']
    },
    deny: {
      effect: 'Deny',
      action: 's3:DeleteObject',
      resource: ['arn:aws:s3:::bucket2/private/extra-private/*']
    },
    expected: [
      {
        effect: 'Allow',
        action: 's3:DeleteObject',
        resource: ['arn:aws:s3:::bucket2/private/*']
      },
      {
        effect: 'Deny',
        action: 's3:DeleteObject',
        resource: ['arn:aws:s3:::bucket2/private/extra-private/*']
      }
    ]
  },
  {
    name: 'Resource wildcard minus subset wildcard (needs two statements)',
    allow: {
      effect: 'Allow',
      action: 's3:DeleteObject',
      resource: ['arn:aws:s3:::bucket/private/*']
    },
    deny: {
      effect: 'Deny',
      action: 's3:DeleteObject',
      resource: ['arn:aws:s3:::bucket/private/extra/*']
    },
    expected: [
      {
        effect: 'Allow',
        action: 's3:DeleteObject',
        resource: ['arn:aws:s3:::bucket/private/*']
      },
      {
        effect: 'Deny',
        action: 's3:DeleteObject',
        resource: ['arn:aws:s3:::bucket/private/extra/*']
      }
    ]
  },
  {
    name: 'Full overlap identical resources returns empty',
    allow: {
      effect: 'Allow',
      action: 's3:GetObject',
      resource: ['arn:aws:s3:::bucket/file']
    },
    deny: {
      effect: 'Deny',
      action: 's3:GetObject',
      resource: ['arn:aws:s3:::bucket/file']
    },
    expected: []
  },
  {
    name: 'Resource & Deny.notResource no change (subset)',
    allow: {
      effect: 'Allow',
      action: 's3:GetObject',
      resource: ['arn:aws:s3:::bucket/*']
    },
    deny: {
      effect: 'Deny',
      action: 's3:GetObject',
      notResource: ['arn:aws:s3:::bucket/*']
    },
    expected: [
      {
        effect: 'Allow',
        action: 's3:GetObject',
        resource: ['arn:aws:s3:::bucket/*']
      }
    ]
  },
  {
    name: 'Resource & Deny.notResource disjoint (empty result)',
    allow: {
      effect: 'Allow',
      action: 's3:GetObject',
      resource: ['arn:aws:s3:::bucket/data/*']
    },
    deny: {
      effect: 'Deny',
      action: 's3:GetObject',
      notResource: ['arn:aws:s3:::bucket/logs/*']
    },
    expected: []
  },
  {
    name: 'NotResource union new exclusions',
    allow: {
      effect: 'Allow',
      action: 's3:PutObject',
      notResource: ['arn:aws:s3:::bucket/data/*']
    },
    deny: {
      effect: 'Deny',
      action: 's3:PutObject',
      resource: ['arn:aws:s3:::bucket/logs/*']
    },
    expected: [
      {
        effect: 'Allow',
        action: 's3:PutObject',
        notResource: ['arn:aws:s3:::bucket/data/*', 'arn:aws:s3:::bucket/logs/*']
      }
    ]
  }
]

describe('Permission#subtract', () => {
  for (const test of subtractTests) {
    const func = test.only ? it.only : it

    func(test.name, () => {
      //Given an allow and deny permission
      const [allowService, allowAction] = test.allow.action.split(':')
      const allowPermission = new Permission(
        test.allow.effect,
        allowService,
        allowAction,
        test.allow.resource,
        test.allow.notResource,
        test.allow.conditions
      )

      const [denyService, denyAction] = test.deny.action.split(':')
      const denyPermission = new Permission(
        test.deny.effect,
        denyService,
        denyAction,
        test.deny.resource,
        test.deny.notResource,
        test.deny.conditions
      )

      //When we subtract the deny from the allow
      const result = allowPermission.subtract(denyPermission)

      //Then the number of the resulting permissions should match the expected
      expect(result.length).toEqual(test.expected.length)

      //And the resulting permissions should match the expected permissions
      for (let i = 0; i < result.length; i++) {
        const actualResult = result[i]
        const expectedResult = test.expected[i]

        const [expectedService, expectedAction] = expectedResult.action.split(':')
        expect(actualResult.effect).toBe(expectedResult.effect)
        expect(actualResult.service).toBe(expectedService)
        expect(actualResult.action).toBe(expectedAction)
        expect(actualResult.resource).toEqual(expectedResult.resource)
        expect(actualResult.notResource).toEqual(expectedResult.notResource)
        expect(actualResult.conditions).toEqual(expectedResult.conditions)
      }
    })
  }
})

const invertConditionsTests: {
  only?: true
  name: string
  initial: PermissionConditions
  expected: PermissionConditions
}[] = [
  {
    name: 'invert StringEquals conditions',
    initial: {
      StringEquals: { 'aws:username': ['alice', 'bob'] }
    },
    expected: {
      stringnotequals: { 'aws:username': ['alice', 'bob'] }
    }
  },
  {
    name: 'invert Bool condition remains same',
    initial: {
      Bool: { 'aws:SecureTransport': ['true'] }
    },
    expected: {
      bool: { 'aws:securetransport': ['false'] }
    }
  },
  {
    name: 'invert Null condition',
    initial: {
      Null: { 'aws:TokenIssueTime': ['true'] }
    },
    expected: {
      null: { 'aws:tokenissuetime': ['false'] }
    }
  },
  {
    name: 'invert NotNull condition',
    initial: {
      Null: { 'aws:TokenIssueTime': ['false'] }
    },
    expected: {
      null: { 'aws:tokenissuetime': ['true'] }
    }
  },
  {
    name: 'invert ForAnyValue:StringEquals',
    initial: {
      'ForAnyValue:StringEquals': { 'aws:TagKeys': ['r1', 'r2', 'r3'] }
    },
    expected: {
      'forallvalues:stringnotequals': { 'aws:tagkeys': ['r1', 'r2', 'r3'] }
    }
  },
  {
    name: 'invert ForAllValues:StringEquals',
    initial: {
      'ForAllValues:StringEquals': { 'aws:TagKeys': ['r1', 'r2'] }
    },
    expected: {
      'foranyvalue:stringnotequals': { 'aws:tagkeys': ['r1', 'r2'] }
    }
  },
  {
    name: 'invert ForAllValues:StringEqualsIfExists',
    initial: {
      'ForAllValues:StringEqualsIfExists': { 'aws:TagKeys': ['prod'] }
    },
    expected: {
      'foranyvalue:stringnotequalsifexists': { 'aws:tagkeys': ['prod'] }
    }
  },
  {
    name: 'invert ForAnyValue:NumericLessThan',
    initial: {
      'ForAnyValue:NumericLessThan': { 's3:max-keys': ['100'] }
    },
    expected: {
      'forallvalues:numericgreaterthanequals': { 's3:max-keys': ['100'] }
    }
  },
  {
    name: 'invert ForAnyValue:StringLikeIfExists',
    initial: {
      'ForAnyValue:StringLikeIfExists': { 'aws:TagValues': ['Confidential*'] }
    },
    expected: {
      'forallvalues:stringnotlikeifexists': { 'aws:tagvalues': ['Confidential*'] }
    }
  },
  {
    name: 'invert ForAllValues:NumericGreaterThan',
    initial: {
      'ForAllValues:NumericGreaterThan': { 'lambda:memory-size': ['128'] }
    },
    expected: {
      'foranyvalue:numericlessthanequals': { 'lambda:memory-size': ['128'] }
    }
  },
  {
    name: 'invert IpAddressIfExists',
    initial: {
      IpAddressIfExists: { 'aws:SourceIp': ['10.0.0.0/8'] }
    },
    expected: {
      notipaddressifexists: { 'aws:sourceip': ['10.0.0.0/8'] }
    }
  },
  {
    name: 'invert Bool false to true',
    initial: {
      Bool: { 'aws:SecureTransport': ['false'] }
    },
    expected: {
      bool: { 'aws:securetransport': ['true'] }
    }
  }
]

describe('invertConditions', () => {
  for (const test of invertConditionsTests) {
    const func = test.only ? it.only : it

    func(test.name, () => {
      //Given a set of conditions
      const conditions = test.initial

      //When we invert the conditions
      const result = invertConditions(conditions)

      //Then the result should match the expected inverted conditions
      expect(result).toEqual(test.expected)
    })
  }
})
