import { splitArnParts } from '@cloud-copilot/iam-utils'
import { describe, expect, it } from 'vitest'
import { testStore } from '../../../collect/inMemoryClient.js'
import { expectPermissionSetToMatch, TestPermission } from '../../permissionSetTestUtils.js'
import { kmsKeysSameAccount } from './kmsKeys.js'

const kmsKeysSameAccountTests: {
  name: string
  only?: true
  principal: string
  keys: { arn: string; policy: any }[]
  expectedPrincipalAllows: TestPermission[][]
  expectedAccountAllows: TestPermission[][]
  expectedDenies: TestPermission[][]
}[] = [
  {
    name: 'No keys in account',
    principal: 'arn:aws:iam::111122223333:user/Alice',
    keys: [],
    expectedPrincipalAllows: [],
    expectedAccountAllows: [],
    expectedDenies: []
  },
  {
    name: 'One key with no policy',
    principal: 'arn:aws:iam::111122223333:user/Alice',
    keys: [
      {
        arn: 'arn:aws:kms:us-east-1:111122223333:key/12345678-1234-1234-1234-123456789012',
        policy: null
      }
    ],
    expectedPrincipalAllows: [],
    expectedAccountAllows: [],
    expectedDenies: []
  },
  {
    name: 'One key with matching principal allow policy',
    principal: 'arn:aws:iam::111122223333:user/Alice',
    keys: [
      {
        arn: 'arn:aws:kms:us-east-1:111122223333:key/12345678-1234-1234-1234-123456789012',
        policy: {
          Version: '2012-10-17',
          Statement: [
            {
              Sid: 'Allow Alice to use the key',
              Effect: 'Allow',
              Principal: { AWS: 'arn:aws:iam::111122223333:user/Alice' },
              Action: ['kms:Encrypt', 'kms:Decrypt', 'kms:DescribeKey'],
              Resource: '*'
            }
          ]
        }
      }
    ],
    expectedPrincipalAllows: [
      [
        {
          effect: 'Allow',
          action: 'kms:Encrypt',
          resource: ['arn:aws:kms:us-east-1:111122223333:key/12345678-1234-1234-1234-123456789012']
        },
        {
          effect: 'Allow',
          action: 'kms:Decrypt',
          resource: ['arn:aws:kms:us-east-1:111122223333:key/12345678-1234-1234-1234-123456789012']
        },
        {
          effect: 'Allow',
          action: 'kms:DescribeKey',
          resource: ['arn:aws:kms:us-east-1:111122223333:key/12345678-1234-1234-1234-123456789012']
        }
      ]
    ],
    expectedAccountAllows: [],
    expectedDenies: []
  },
  {
    name: 'One key with account-level allow policy',
    principal: 'arn:aws:iam::111122223333:user/Alice',
    keys: [
      {
        arn: 'arn:aws:kms:us-east-1:111122223333:key/12345678-1234-1234-1234-123456789012',
        policy: {
          Version: '2012-10-17',
          Statement: [
            {
              Sid: 'Allow account access',
              Effect: 'Allow',
              Principal: { AWS: 'arn:aws:iam::111122223333:root' },
              Action: ['kms:Encrypt', 'kms:Decrypt'],
              Resource: '*'
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
          action: 'kms:Encrypt',
          resource: ['arn:aws:kms:us-east-1:111122223333:key/12345678-1234-1234-1234-123456789012']
        },
        {
          effect: 'Allow',
          action: 'kms:Decrypt',
          resource: ['arn:aws:kms:us-east-1:111122223333:key/12345678-1234-1234-1234-123456789012']
        }
      ]
    ],
    expectedDenies: []
  },
  {
    name: 'One key with matching principal deny policy',
    principal: 'arn:aws:iam::111122223333:user/Alice',
    keys: [
      {
        arn: 'arn:aws:kms:us-east-1:111122223333:key/12345678-1234-1234-1234-123456789012',
        policy: {
          Version: '2012-10-17',
          Statement: [
            {
              Sid: 'Deny Alice from deleting the key',
              Effect: 'Deny',
              Principal: { AWS: 'arn:aws:iam::111122223333:user/Alice' },
              Action: ['kms:ScheduleKeyDeletion'],
              Resource: '*'
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
          action: 'kms:ScheduleKeyDeletion',
          resource: ['arn:aws:kms:us-east-1:111122223333:key/12345678-1234-1234-1234-123456789012']
        }
      ]
    ]
  },
  {
    name: 'Two keys, one with principal allow, one with deny',
    principal: 'arn:aws:iam::111122223333:user/Alice',
    keys: [
      {
        arn: 'arn:aws:kms:us-east-1:111122223333:key/aaaaaaaa-1111-1111-1111-aaaaaaaaaaaa',
        policy: {
          Version: '2012-10-17',
          Statement: [
            {
              Effect: 'Allow',
              Principal: { AWS: 'arn:aws:iam::111122223333:user/Alice' },
              Action: ['kms:Encrypt', 'kms:Decrypt'],
              Resource: '*'
            }
          ]
        }
      },
      {
        arn: 'arn:aws:kms:us-east-1:111122223333:key/bbbbbbbb-2222-2222-2222-bbbbbbbbbbbb',
        policy: {
          Version: '2012-10-17',
          Statement: [
            {
              Effect: 'Deny',
              Principal: { AWS: 'arn:aws:iam::111122223333:user/Alice' },
              Action: ['kms:ScheduleKeyDeletion'],
              Resource: '*'
            }
          ]
        }
      }
    ],
    expectedPrincipalAllows: [
      [
        {
          effect: 'Allow',
          action: 'kms:Encrypt',
          resource: ['arn:aws:kms:us-east-1:111122223333:key/aaaaaaaa-1111-1111-1111-aaaaaaaaaaaa']
        },
        {
          effect: 'Allow',
          action: 'kms:Decrypt',
          resource: ['arn:aws:kms:us-east-1:111122223333:key/aaaaaaaa-1111-1111-1111-aaaaaaaaaaaa']
        }
      ]
    ],
    expectedAccountAllows: [],
    expectedDenies: [
      [
        {
          effect: 'Deny',
          action: 'kms:ScheduleKeyDeletion',
          resource: ['arn:aws:kms:us-east-1:111122223333:key/bbbbbbbb-2222-2222-2222-bbbbbbbbbbbb']
        }
      ]
    ]
  },
  {
    name: 'Key policy with statements for different principal',
    principal: 'arn:aws:iam::111122223333:user/Alice',
    keys: [
      {
        arn: 'arn:aws:kms:us-east-1:111122223333:key/12345678-1234-1234-1234-123456789012',
        policy: {
          Version: '2012-10-17',
          Statement: [
            {
              Effect: 'Allow',
              Principal: { AWS: 'arn:aws:iam::111122223333:user/Bob' },
              Action: ['kms:Encrypt', 'kms:Decrypt'],
              Resource: '*'
            },
            {
              Effect: 'Deny',
              Principal: { AWS: 'arn:aws:iam::111122223333:user/Charlie' },
              Action: ['kms:ScheduleKeyDeletion'],
              Resource: '*'
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
    name: 'Key policy with conditions should be included in results',
    principal: 'arn:aws:iam::111122223333:user/Alice',
    keys: [
      {
        arn: 'arn:aws:kms:us-east-1:111122223333:key/12345678-1234-1234-1234-123456789012',
        policy: {
          Version: '2012-10-17',
          Statement: [
            {
              Effect: 'Allow',
              Principal: { AWS: 'arn:aws:iam::111122223333:user/Alice' },
              Action: ['kms:Encrypt', 'kms:Decrypt'],
              Resource: '*',
              Condition: {
                StringEquals: {
                  'kms:EncryptionContext:Department': 'Engineering'
                }
              }
            },
            {
              Effect: 'Deny',
              Principal: { AWS: 'arn:aws:iam::111122223333:user/Alice' },
              Action: ['kms:ScheduleKeyDeletion'],
              Resource: '*',
              Condition: {
                DateGreaterThan: {
                  'aws:CurrentTime': '2025-01-01T00:00:00Z'
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
          action: 'kms:Encrypt',
          resource: ['arn:aws:kms:us-east-1:111122223333:key/12345678-1234-1234-1234-123456789012'],
          conditions: {
            StringEquals: {
              'kms:EncryptionContext:Department': ['Engineering']
            }
          }
        },
        {
          effect: 'Allow',
          action: 'kms:Decrypt',
          resource: ['arn:aws:kms:us-east-1:111122223333:key/12345678-1234-1234-1234-123456789012'],
          conditions: {
            StringEquals: {
              'kms:EncryptionContext:Department': ['Engineering']
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
          action: 'kms:ScheduleKeyDeletion',
          resource: ['arn:aws:kms:us-east-1:111122223333:key/12345678-1234-1234-1234-123456789012'],
          conditions: {
            DateGreaterThan: {
              'aws:CurrentTime': ['2025-01-01T00:00:00Z']
            }
          }
        }
      ]
    ]
  },
  {
    name: 'Key policy with NotPrincipal excluding different principal should allow our principal',
    principal: 'arn:aws:iam::111122223333:user/Alice',
    keys: [
      {
        arn: 'arn:aws:kms:us-east-1:111122223333:key/12345678-1234-1234-1234-123456789012',
        policy: {
          Version: '2012-10-17',
          Statement: [
            {
              Effect: 'Allow',
              NotPrincipal: { AWS: 'arn:aws:iam::111122223333:user/Bob' },
              Action: ['kms:Encrypt', 'kms:Decrypt'],
              Resource: '*'
            },
            {
              Effect: 'Deny',
              NotPrincipal: { AWS: 'arn:aws:iam::111122223333:user/Charlie' },
              Action: ['kms:ScheduleKeyDeletion'],
              Resource: '*'
            }
          ]
        }
      }
    ],
    expectedPrincipalAllows: [
      [
        {
          effect: 'Allow',
          action: 'kms:Encrypt',
          resource: ['arn:aws:kms:us-east-1:111122223333:key/12345678-1234-1234-1234-123456789012']
        },
        {
          effect: 'Allow',
          action: 'kms:Decrypt',
          resource: ['arn:aws:kms:us-east-1:111122223333:key/12345678-1234-1234-1234-123456789012']
        }
      ]
    ],
    expectedAccountAllows: [],
    expectedDenies: [
      [
        {
          effect: 'Deny',
          action: 'kms:ScheduleKeyDeletion',
          resource: ['arn:aws:kms:us-east-1:111122223333:key/12345678-1234-1234-1234-123456789012']
        }
      ]
    ]
  },
  {
    name: 'Key policy with principal condition key should be included when matching',
    principal: 'arn:aws:iam::111122223333:user/Alice',
    keys: [
      {
        arn: 'arn:aws:kms:us-east-1:111122223333:key/12345678-1234-1234-1234-123456789012',
        policy: {
          Version: '2012-10-17',
          Statement: [
            {
              Effect: 'Allow',
              Principal: '*',
              Action: ['kms:Encrypt', 'kms:Decrypt'],
              Resource: '*',
              Condition: {
                StringEquals: {
                  'aws:PrincipalAccount': '111122223333'
                }
              }
            },
            {
              Effect: 'Deny',
              Principal: '*',
              Action: ['kms:ScheduleKeyDeletion'],
              Resource: '*',
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
          action: 'kms:Encrypt',
          resource: ['arn:aws:kms:us-east-1:111122223333:key/12345678-1234-1234-1234-123456789012'],
          conditions: {
            StringEquals: {
              'aws:PrincipalAccount': ['111122223333']
            }
          }
        },
        {
          effect: 'Allow',
          action: 'kms:Decrypt',
          resource: ['arn:aws:kms:us-east-1:111122223333:key/12345678-1234-1234-1234-123456789012'],
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
    name: 'Key policy with invalid actions should exclude actions that do not apply to keys',
    principal: 'arn:aws:iam::111122223333:user/Alice',
    keys: [
      {
        arn: 'arn:aws:kms:us-east-1:111122223333:key/12345678-1234-1234-1234-123456789012',
        policy: {
          Version: '2012-10-17',
          Statement: [
            {
              Effect: 'Allow',
              Principal: { AWS: 'arn:aws:iam::111122223333:user/Alice' },
              Action: ['kms:Encrypt', 'kms:ListAliases', 'kms:Decrypt', 'kms:CreateKey'],
              Resource: '*'
            },
            {
              Effect: 'Deny',
              Principal: { AWS: 'arn:aws:iam::111122223333:user/Alice' },
              Action: ['kms:ScheduleKeyDeletion', 'kms:ListKeys', 'kms:DisableKey'],
              Resource: '*'
            }
          ]
        }
      }
    ],
    expectedPrincipalAllows: [
      [
        {
          effect: 'Allow',
          action: 'kms:Encrypt',
          resource: ['arn:aws:kms:us-east-1:111122223333:key/12345678-1234-1234-1234-123456789012']
        },
        {
          effect: 'Allow',
          action: 'kms:Decrypt',
          resource: ['arn:aws:kms:us-east-1:111122223333:key/12345678-1234-1234-1234-123456789012']
        }
      ]
    ],
    expectedAccountAllows: [],
    expectedDenies: [
      [
        {
          effect: 'Deny',
          action: 'kms:ScheduleKeyDeletion',
          resource: ['arn:aws:kms:us-east-1:111122223333:key/12345678-1234-1234-1234-123456789012']
        },
        {
          effect: 'Deny',
          action: 'kms:DisableKey',
          resource: ['arn:aws:kms:us-east-1:111122223333:key/12345678-1234-1234-1234-123456789012']
        }
      ]
    ]
  },
  {
    name: 'Key with both principal and account-level allows',
    principal: 'arn:aws:iam::111122223333:user/Alice',
    keys: [
      {
        arn: 'arn:aws:kms:us-east-1:111122223333:key/12345678-1234-1234-1234-123456789012',
        policy: {
          Version: '2012-10-17',
          Statement: [
            {
              Sid: 'Allow account root',
              Effect: 'Allow',
              Principal: { AWS: 'arn:aws:iam::111122223333:root' },
              Action: ['kms:DescribeKey'],
              Resource: '*'
            },
            {
              Sid: 'Allow Alice specifically',
              Effect: 'Allow',
              Principal: { AWS: 'arn:aws:iam::111122223333:user/Alice' },
              Action: ['kms:DescribeKey'],
              Resource: '*'
            }
          ]
        }
      }
    ],
    expectedPrincipalAllows: [
      [
        {
          effect: 'Allow',
          action: 'kms:DescribeKey',
          resource: ['arn:aws:kms:us-east-1:111122223333:key/12345678-1234-1234-1234-123456789012']
        }
      ]
    ],
    expectedAccountAllows: [
      [
        {
          effect: 'Allow',
          action: 'kms:DescribeKey',
          resource: ['arn:aws:kms:us-east-1:111122223333:key/12345678-1234-1234-1234-123456789012']
        }
      ]
    ],
    expectedDenies: []
  },
  {
    name: 'Key policy with kms:ViaService condition should be ignored',
    principal: 'arn:aws:iam::111122223333:user/Alice',
    keys: [
      {
        arn: 'arn:aws:kms:us-east-1:111122223333:key/12345678-1234-1234-1234-123456789012',
        policy: {
          Version: '2012-10-17',
          Statement: [
            {
              Effect: 'Allow',
              Principal: { AWS: 'arn:aws:iam::111122223333:user/Alice' },
              Action: ['kms:Encrypt', 'kms:Decrypt'],
              Resource: '*',
              Condition: {
                StringEquals: {
                  'kms:ViaService': 's3.us-east-1.amazonaws.com'
                }
              }
            },
            {
              Effect: 'Allow',
              NotPrincipal: { AWS: 'arn:aws:iam::111122223333:root' },
              Action: ['kms:ScheduleKeyDeletion'],
              Resource: '*',
              Condition: {
                StringEquals: {
                  'kms:ViaService': 's3.us-east-1.amazonaws.com'
                }
              }
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

describe('kmsKeysSameAccount', () => {
  kmsKeysSameAccountTests.forEach((t) => {
    const testFn = t.only ? it.only : it
    testFn(t.name, async () => {
      // Given a mock principal and buckets
      const { store, client } = testStore()

      for (const k of t.keys) {
        const accountId = splitArnParts(k.arn).accountId!
        await store.saveResourceMetadata(accountId, k.arn, 'metadata', {
          arn: k.arn
        })
        await store.saveResourceMetadata(accountId, k.arn, 'policy', k.policy)
      }

      const principalAccount = splitArnParts(t.principal).accountId!
      await store.saveResourceMetadata(principalAccount, t.principal, 'metadata', {
        arn: t.principal
      })

      // When we check access
      const { principalAllows, accountAllows, denies } = await kmsKeysSameAccount(
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
