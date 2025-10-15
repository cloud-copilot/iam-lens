import { splitArnParts } from '@cloud-copilot/iam-utils'
import { describe, expect, it } from 'vitest'
import { testStore } from '../../../collect/inMemoryClient.js'
import { expectPermissionSetToMatch, TestPermission } from '../../permissionSetTestUtils.js'
import { iamRolesSameAccount } from './iamRoles.js'

const iamRolesSameAccountTests: {
  name: string
  only?: true
  principal: string
  roles: { arn: string; policy: any }[]
  expectedPrincipalAllows: TestPermission[][]
  expectedAccountAllows: TestPermission[][]
  expectedDenies: TestPermission[][]
}[] = [
  {
    name: 'No roles in account',
    principal: 'arn:aws:iam::111122223333:user/Alice',
    roles: [],
    expectedPrincipalAllows: [],
    expectedAccountAllows: [],
    expectedDenies: []
  },
  {
    name: 'One role with no trust policy',
    principal: 'arn:aws:iam::111122223333:user/Alice',
    roles: [
      {
        arn: 'arn:aws:iam::111122223333:role/TestRole',
        policy: null
      }
    ],
    expectedPrincipalAllows: [],
    expectedAccountAllows: [],
    expectedDenies: []
  },
  {
    name: 'One role with matching principal allow in trust policy',
    principal: 'arn:aws:iam::111122223333:user/Alice',
    roles: [
      {
        arn: 'arn:aws:iam::111122223333:role/TestRole',
        policy: {
          Version: '2012-10-17',
          Statement: [
            {
              Effect: 'Allow',
              Principal: { AWS: 'arn:aws:iam::111122223333:user/Alice' },
              Action: 'sts:AssumeRole'
            }
          ]
        }
      }
    ],
    expectedPrincipalAllows: [
      [
        {
          effect: 'Allow',
          action: 'sts:AssumeRole',
          resource: ['arn:aws:iam::111122223333:role/TestRole']
        }
      ]
    ],
    expectedAccountAllows: [],
    expectedDenies: []
  },
  {
    name: 'One role with account-level allow in trust policy',
    principal: 'arn:aws:iam::111122223333:user/Alice',
    roles: [
      {
        arn: 'arn:aws:iam::111122223333:role/TestRole',
        policy: {
          Version: '2012-10-17',
          Statement: [
            {
              Effect: 'Allow',
              Principal: { AWS: 'arn:aws:iam::111122223333:root' },
              Action: 'sts:AssumeRole'
            }
          ]
        }
      }
    ],
    expectedPrincipalAllows: [],
    expectedAccountAllows: [
      [
        {
          effect: 'Allow',
          action: 'sts:AssumeRole',
          resource: ['arn:aws:iam::111122223333:role/TestRole']
        }
      ]
    ],
    expectedDenies: []
  },
  {
    name: 'One role with matching principal deny in trust policy',
    principal: 'arn:aws:iam::111122223333:user/Alice',
    roles: [
      {
        arn: 'arn:aws:iam::111122223333:role/TestRole',
        policy: {
          Version: '2012-10-17',
          Statement: [
            {
              Effect: 'Deny',
              Principal: { AWS: 'arn:aws:iam::111122223333:user/Alice' },
              Action: 'sts:AssumeRole'
            }
          ]
        }
      }
    ],
    expectedPrincipalAllows: [],
    expectedAccountAllows: [],
    expectedDenies: [
      [
        {
          effect: 'Deny',
          action: 'sts:AssumeRole',
          resource: ['arn:aws:iam::111122223333:role/TestRole']
        }
      ]
    ]
  },
  {
    name: 'Two roles, one with principal allow, one with deny',
    principal: 'arn:aws:iam::111122223333:user/Alice',
    roles: [
      {
        arn: 'arn:aws:iam::111122223333:role/AllowedRole',
        policy: {
          Version: '2012-10-17',
          Statement: [
            {
              Effect: 'Allow',
              Principal: { AWS: 'arn:aws:iam::111122223333:user/Alice' },
              Action: 'sts:AssumeRole'
            }
          ]
        }
      },
      {
        arn: 'arn:aws:iam::111122223333:role/DeniedRole',
        policy: {
          Version: '2012-10-17',
          Statement: [
            {
              Effect: 'Deny',
              Principal: { AWS: 'arn:aws:iam::111122223333:user/Alice' },
              Action: 'sts:AssumeRole'
            }
          ]
        }
      }
    ],
    expectedPrincipalAllows: [
      [
        {
          effect: 'Allow',
          action: 'sts:AssumeRole',
          resource: ['arn:aws:iam::111122223333:role/AllowedRole']
        }
      ]
    ],
    expectedAccountAllows: [],
    expectedDenies: [
      [
        {
          effect: 'Deny',
          action: 'sts:AssumeRole',
          resource: ['arn:aws:iam::111122223333:role/DeniedRole']
        }
      ]
    ]
  },
  {
    name: 'Role trust policy with statements for different principal',
    principal: 'arn:aws:iam::111122223333:user/Alice',
    roles: [
      {
        arn: 'arn:aws:iam::111122223333:role/TestRole',
        policy: {
          Version: '2012-10-17',
          Statement: [
            {
              Effect: 'Allow',
              Principal: { AWS: 'arn:aws:iam::111122223333:user/Bob' },
              Action: 'sts:AssumeRole'
            },
            {
              Effect: 'Deny',
              Principal: { AWS: 'arn:aws:iam::111122223333:user/Charlie' },
              Action: 'sts:AssumeRole'
            }
          ]
        }
      }
    ],
    expectedPrincipalAllows: [],
    expectedAccountAllows: [],
    expectedDenies: []
  },
  {
    name: 'Role trust policy with conditions should be included in results',
    principal: 'arn:aws:iam::111122223333:user/Alice',
    roles: [
      {
        arn: 'arn:aws:iam::111122223333:role/TestRole',
        policy: {
          Version: '2012-10-17',
          Statement: [
            {
              Effect: 'Allow',
              Principal: { AWS: 'arn:aws:iam::111122223333:user/Alice' },
              Action: 'sts:AssumeRole',
              Condition: {
                StringEquals: {
                  'sts:ExternalId': 'unique-external-id'
                }
              }
            },
            {
              Effect: 'Deny',
              Principal: { AWS: 'arn:aws:iam::111122223333:user/Alice' },
              Action: 'sts:AssumeRole',
              Condition: {
                IpAddress: {
                  'aws:SourceIp': '203.0.113.0/24'
                }
              }
            }
          ]
        }
      }
    ],
    expectedPrincipalAllows: [
      [
        {
          effect: 'Allow',
          action: 'sts:AssumeRole',
          resource: ['arn:aws:iam::111122223333:role/TestRole'],
          conditions: {
            StringEquals: {
              'sts:ExternalId': ['unique-external-id']
            }
          }
        }
      ]
    ],
    expectedAccountAllows: [],
    expectedDenies: [
      [
        {
          effect: 'Deny',
          action: 'sts:AssumeRole',
          resource: ['arn:aws:iam::111122223333:role/TestRole'],
          conditions: {
            IpAddress: {
              'aws:SourceIp': ['203.0.113.0/24']
            }
          }
        }
      ]
    ]
  },
  {
    name: 'Role trust policy with NotPrincipal excluding different principal should allow our principal',
    principal: 'arn:aws:iam::111122223333:user/Alice',
    roles: [
      {
        arn: 'arn:aws:iam::111122223333:role/TestRole',
        policy: {
          Version: '2012-10-17',
          Statement: [
            {
              Effect: 'Allow',
              NotPrincipal: { AWS: 'arn:aws:iam::111122223333:user/Bob' },
              Action: 'sts:AssumeRole'
            },
            {
              Effect: 'Deny',
              NotPrincipal: { AWS: 'arn:aws:iam::111122223333:user/Charlie' },
              Action: 'sts:AssumeRole'
            }
          ]
        }
      }
    ],
    expectedPrincipalAllows: [
      [
        {
          effect: 'Allow',
          action: 'sts:AssumeRole',
          resource: ['arn:aws:iam::111122223333:role/TestRole']
        }
      ]
    ],
    expectedAccountAllows: [],
    expectedDenies: [
      [
        {
          effect: 'Deny',
          action: 'sts:AssumeRole',
          resource: ['arn:aws:iam::111122223333:role/TestRole']
        }
      ]
    ]
  },
  {
    name: 'Role trust policy with principal condition key should be included when matching',
    principal: 'arn:aws:iam::111122223333:user/Alice',
    roles: [
      {
        arn: 'arn:aws:iam::111122223333:role/TestRole',
        policy: {
          Version: '2012-10-17',
          Statement: [
            {
              Effect: 'Allow',
              Principal: { AWS: '*' },
              Action: 'sts:AssumeRole',
              Condition: {
                StringEquals: {
                  'aws:PrincipalAccount': '111122223333'
                }
              }
            },
            {
              Effect: 'Deny',
              Principal: { AWS: '*' },
              Action: 'sts:AssumeRole',
              Condition: {
                StringEquals: {
                  'aws:PrincipalAccount': '999999999999'
                }
              }
            }
          ]
        }
      }
    ],
    expectedPrincipalAllows: [
      [
        {
          effect: 'Allow',
          action: 'sts:AssumeRole',
          resource: ['arn:aws:iam::111122223333:role/TestRole'],
          conditions: {
            StringEquals: {
              'aws:PrincipalAccount': ['111122223333']
            }
          }
        }
      ]
    ],
    expectedAccountAllows: [],
    expectedDenies: []
  },
  {
    name: 'Role trust policy with invalid actions should exclude actions other than sts:AssumeRole',
    principal: 'arn:aws:iam::111122223333:user/Alice',
    roles: [
      {
        arn: 'arn:aws:iam::111122223333:role/TestRole',
        policy: {
          Version: '2012-10-17',
          Statement: [
            {
              Effect: 'Allow',
              Principal: { AWS: 'arn:aws:iam::111122223333:user/Alice' },
              Action: ['sts:AssumeRole', 'sts:AssumeRoleWithSAML', 'sts:AssumeRoleWithWebIdentity']
            },
            {
              Effect: 'Deny',
              Principal: { AWS: 'arn:aws:iam::111122223333:user/Alice' },
              Action: ['sts:AssumeRole', 'sts:GetCallerIdentity', 'sts:GetSessionToken']
            }
          ]
        }
      }
    ],
    expectedPrincipalAllows: [
      [
        {
          effect: 'Allow',
          action: 'sts:AssumeRole',
          resource: ['arn:aws:iam::111122223333:role/TestRole']
        }
      ]
    ],
    expectedAccountAllows: [],
    expectedDenies: [
      [
        {
          effect: 'Deny',
          action: 'sts:AssumeRole',
          resource: ['arn:aws:iam::111122223333:role/TestRole']
        }
      ]
    ]
  },
  {
    name: 'Role with both principal and account-level allows',
    principal: 'arn:aws:iam::111122223333:user/Alice',
    roles: [
      {
        arn: 'arn:aws:iam::111122223333:role/TestRole',
        policy: {
          Version: '2012-10-17',
          Statement: [
            {
              Effect: 'Allow',
              Principal: { AWS: 'arn:aws:iam::111122223333:root' },
              Action: 'sts:AssumeRole'
            },
            {
              Effect: 'Allow',
              Principal: { AWS: 'arn:aws:iam::111122223333:user/Alice' },
              Action: 'sts:AssumeRole'
            }
          ]
        }
      }
    ],
    expectedPrincipalAllows: [
      [
        {
          effect: 'Allow',
          action: 'sts:AssumeRole',
          resource: ['arn:aws:iam::111122223333:role/TestRole']
        }
      ]
    ],
    expectedAccountAllows: [
      [
        {
          effect: 'Allow',
          action: 'sts:AssumeRole',
          resource: ['arn:aws:iam::111122223333:role/TestRole']
        }
      ]
    ],
    expectedDenies: []
  },
  {
    name: 'Role trust policy with Service principal should not match user principal',
    principal: 'arn:aws:iam::111122223333:user/Alice',
    roles: [
      {
        arn: 'arn:aws:iam::111122223333:role/LambdaExecutionRole',
        policy: {
          Version: '2012-10-17',
          Statement: [
            {
              Effect: 'Allow',
              Principal: { Service: 'lambda.amazonaws.com' },
              Action: 'sts:AssumeRole'
            },
            {
              Effect: 'Allow',
              Principal: { Service: 'ec2.amazonaws.com' },
              Action: 'sts:AssumeRole'
            }
          ]
        }
      }
    ],
    expectedPrincipalAllows: [],
    expectedAccountAllows: [],
    expectedDenies: []
  },
  {
    name: 'Role trust policy with mixed principals including federated',
    principal: 'arn:aws:iam::111122223333:user/Alice',
    roles: [
      {
        arn: 'arn:aws:iam::111122223333:role/FederatedRole',
        policy: {
          Version: '2012-10-17',
          Statement: [
            {
              Effect: 'Allow',
              Principal: {
                Federated: 'arn:aws:iam::111122223333:saml-provider/ExampleProvider'
              },
              Action: 'sts:AssumeRoleWithSAML',
              Condition: {
                StringEquals: {
                  'SAML:aud': 'https://signin.aws.amazon.com/saml'
                }
              }
            },
            {
              Effect: 'Allow',
              Principal: { AWS: 'arn:aws:iam::111122223333:user/Alice' },
              Action: 'sts:AssumeRole'
            }
          ]
        }
      }
    ],
    expectedPrincipalAllows: [
      [
        {
          effect: 'Allow',
          action: 'sts:AssumeRole',
          resource: ['arn:aws:iam::111122223333:role/FederatedRole']
        }
      ]
    ],
    expectedAccountAllows: [],
    expectedDenies: []
  },
  {
    name: 'Role trust policy with cross-account principal should not match',
    principal: 'arn:aws:iam::111122223333:user/Alice',
    roles: [
      {
        arn: 'arn:aws:iam::111122223333:role/CrossAccountRole',
        policy: {
          Version: '2012-10-17',
          Statement: [
            {
              Effect: 'Allow',
              Principal: { AWS: 'arn:aws:iam::999888777666:root' },
              Action: 'sts:AssumeRole'
            },
            {
              Effect: 'Allow',
              Principal: { AWS: 'arn:aws:iam::999888777666:user/Bob' },
              Action: 'sts:AssumeRole'
            }
          ]
        }
      }
    ],
    expectedPrincipalAllows: [],
    expectedAccountAllows: [],
    expectedDenies: []
  }
]

describe('iamRolesSameAccount', () => {
  iamRolesSameAccountTests.forEach((t) => {
    const testFn = t.only ? it.only : it
    testFn(t.name, async () => {
      // Given a mock principal and buckets
      const { store, client } = testStore()

      for (const r of t.roles) {
        const accountId = splitArnParts(r.arn).accountId!
        await store.saveResourceMetadata(accountId, r.arn, 'metadata', {
          arn: r.arn
        })
        await store.saveResourceMetadata(accountId, r.arn, 'trust-policy', r.policy)
      }

      const principalAccount = splitArnParts(t.principal).accountId!
      await store.saveResourceMetadata(principalAccount, t.principal, 'metadata', {
        arn: t.principal
      })

      // When we check access
      const { principalAllows, accountAllows, denies } = await iamRolesSameAccount(
        client,
        t.principal
      )

      // Then we get the expected allows and denies
      expect(principalAllows).toHaveLength(t.expectedPrincipalAllows.length)
      expect(accountAllows).toHaveLength(t.expectedAccountAllows.length)
      expect(denies).toHaveLength(t.expectedDenies.length)

      for (let i = 0; i < t.expectedAccountAllows.length; i++) {
        const expected = t.expectedAccountAllows[i]
        const actual = accountAllows[i]
        expectPermissionSetToMatch(actual, expected)
      }

      for (let i = 0; i < t.expectedPrincipalAllows.length; i++) {
        const expected = t.expectedPrincipalAllows[i]
        const actual = principalAllows[i]
        expectPermissionSetToMatch(actual, expected)
      }

      for (let i = 0; i < t.expectedDenies.length; i++) {
        const expected = t.expectedDenies[i]
        const actual = denies[i]
        expectPermissionSetToMatch(actual, expected)
      }
    })
  })
})
