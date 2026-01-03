import { loadPolicy } from '@cloud-copilot/iam-policy'
import { splitArnParts } from '@cloud-copilot/iam-utils'
import { describe, expect, it } from 'vitest'
import { testStore } from '../../../collect/inMemoryClient.js'
import { addStatementToPermissionSet, PermissionSet } from '../../permissionSet.js'
import { expectPermissionSetToMatch, TestPermission } from '../../permissionSetTestUtils.js'
import { s3BucketsCrossAccount, s3BucketsSameAccount } from './s3Buckets.js'

const s3BucketsSameAccountTests: {
  name: string
  only?: true
  principal: string
  buckets: { arn: string; account: string; policy: any }[]
  expectedAllows: TestPermission[][]
  expectedDenies: TestPermission[][]
}[] = [
  {
    name: 'no buckets',
    principal: 'arn:aws:iam::100000000001:user/Alice',
    buckets: [],
    expectedAllows: [],
    expectedDenies: []
  },
  {
    name: 'one bucket no policy',
    principal: 'arn:aws:iam::100000000001:user/Alice',
    buckets: [
      {
        arn: 'arn:aws:s3:::example-bucket',
        account: '100000000001',
        policy: null
      }
    ],
    expectedAllows: [],
    expectedDenies: []
  },
  {
    name: 'one bucket with matching allow policy',
    principal: 'arn:aws:iam::100000000001:user/Alice',
    buckets: [
      {
        arn: 'arn:aws:s3:::example-bucket',
        account: '100000000001',
        policy: {
          Version: '2012-10-17',
          Statement: [
            {
              Effect: 'Allow',
              Principal: { AWS: 'arn:aws:iam::100000000001:user/Alice' },
              Action: ['s3:GetObject', 's3:ListBucket'],
              Resource: ['arn:aws:s3:::example-bucket', 'arn:aws:s3:::example-bucket/*']
            }
          ]
        }
      }
    ],
    expectedAllows: [
      [
        {
          effect: 'Allow',
          action: 's3:GetObject',
          resource: ['arn:aws:s3:::example-bucket', 'arn:aws:s3:::example-bucket/*']
        },
        {
          effect: 'Allow',
          action: 's3:ListBucket',
          resource: ['arn:aws:s3:::example-bucket', 'arn:aws:s3:::example-bucket/*']
        }
      ]
    ],
    expectedDenies: []
  },
  {
    name: 'two buckets, one allow, one deny',
    principal: 'arn:aws:iam::100000000001:user/Alice',
    buckets: [
      {
        arn: 'arn:aws:s3:::example-bucket-allow',
        account: '100000000001',
        policy: {
          Version: '2012-10-17',
          Statement: [
            {
              Effect: 'Allow',
              Principal: { AWS: 'arn:aws:iam::100000000001:user/Alice' },
              Action: ['s3:GetObject', 's3:ListBucket'],
              Resource: ['arn:aws:s3:::example-bucket-allow', 'arn:aws:s3:::example-bucket-allow/*']
            }
          ]
        }
      },
      {
        arn: 'arn:aws:s3:::example-bucket-deny',
        account: '100000000001',
        policy: {
          Version: '2012-10-17',
          Statement: [
            {
              Effect: 'Deny',
              Principal: { AWS: 'arn:aws:iam::100000000001:user/Alice' },
              Action: ['s3:DeleteObject'],
              Resource: ['arn:aws:s3:::example-bucket-deny', 'arn:aws:s3:::example-bucket-deny/*']
            }
          ]
        }
      }
    ],
    expectedAllows: [
      [
        {
          effect: 'Allow',
          action: 's3:GetObject',
          resource: ['arn:aws:s3:::example-bucket-allow', 'arn:aws:s3:::example-bucket-allow/*']
        },
        {
          effect: 'Allow',
          action: 's3:ListBucket',
          resource: ['arn:aws:s3:::example-bucket-allow', 'arn:aws:s3:::example-bucket-allow/*']
        }
      ]
    ],
    expectedDenies: [
      [
        {
          effect: 'Deny',
          action: 's3:DeleteObject',
          resource: ['arn:aws:s3:::example-bucket-deny', 'arn:aws:s3:::example-bucket-deny/*']
        }
      ]
    ]
  },
  {
    name: 'bucket policy with statements for different principal',
    principal: 'arn:aws:iam::100000000001:user/Alice',
    buckets: [
      {
        arn: 'arn:aws:s3:::example-bucket',
        account: '100000000001',
        policy: {
          Version: '2012-10-17',
          Statement: [
            {
              Effect: 'Allow',
              Principal: { AWS: 'arn:aws:iam::100000000001:user/Bob' },
              Action: ['s3:GetObject', 's3:ListBucket'],
              Resource: ['arn:aws:s3:::example-bucket', 'arn:aws:s3:::example-bucket/*']
            },
            {
              Effect: 'Deny',
              Principal: { AWS: 'arn:aws:iam::100000000001:user/Charlie' },
              Action: ['s3:DeleteObject'],
              Resource: ['arn:aws:s3:::example-bucket', 'arn:aws:s3:::example-bucket/*']
            }
          ]
        }
      }
    ],
    expectedAllows: [],
    expectedDenies: []
  },
  {
    name: 'bucket policy with statements for different bucket resource',
    principal: 'arn:aws:iam::100000000001:user/Alice',
    buckets: [
      {
        arn: 'arn:aws:s3:::example-bucket',
        account: '100000000001',
        policy: {
          Version: '2012-10-17',
          Statement: [
            {
              Effect: 'Allow',
              Principal: { AWS: 'arn:aws:iam::100000000001:user/Alice' },
              Action: ['s3:GetObject', 's3:ListBucket'],
              Resource: ['arn:aws:s3:::different-bucket', 'arn:aws:s3:::different-bucket/*']
            },
            {
              Effect: 'Deny',
              Principal: { AWS: 'arn:aws:iam::100000000001:user/Alice' },
              Action: ['s3:DeleteObject'],
              Resource: ['arn:aws:s3:::another-bucket', 'arn:aws:s3:::another-bucket/*']
            }
          ]
        }
      }
    ],
    expectedAllows: [],
    expectedDenies: []
  },
  {
    name: 'bucket policy with wildcard resource should be limited to bucket scope',
    principal: 'arn:aws:iam::100000000001:user/Alice',
    buckets: [
      {
        arn: 'arn:aws:s3:::example-bucket',
        account: '100000000001',
        policy: {
          Version: '2012-10-17',
          Statement: [
            {
              Effect: 'Allow',
              Principal: { AWS: 'arn:aws:iam::100000000001:user/Alice' },
              Action: ['s3:GetObject', 's3:ListBucket'],
              Resource: '*'
            },
            {
              Effect: 'Deny',
              Principal: { AWS: 'arn:aws:iam::100000000001:user/Alice' },
              Action: ['s3:DeleteObject'],
              Resource: '*'
            }
          ]
        }
      }
    ],
    expectedAllows: [
      [
        {
          effect: 'Allow',
          action: 's3:GetObject',
          resource: ['arn:aws:s3:::example-bucket', 'arn:aws:s3:::example-bucket/*']
        },
        {
          effect: 'Allow',
          action: 's3:ListBucket',
          resource: ['arn:aws:s3:::example-bucket', 'arn:aws:s3:::example-bucket/*']
        }
      ]
    ],
    expectedDenies: [
      [
        {
          effect: 'Deny',
          action: 's3:DeleteObject',
          resource: ['arn:aws:s3:::example-bucket', 'arn:aws:s3:::example-bucket/*']
        }
      ]
    ]
  },
  {
    name: 'bucket policy with conditions should still be included in results',
    principal: 'arn:aws:iam::100000000001:user/Alice',
    buckets: [
      {
        arn: 'arn:aws:s3:::example-bucket',
        account: '100000000001',
        policy: {
          Version: '2012-10-17',
          Statement: [
            {
              Effect: 'Allow',
              Principal: { AWS: 'arn:aws:iam::100000000001:user/Alice' },
              Action: ['s3:GetObject', 's3:PutObject'],
              Resource: ['arn:aws:s3:::example-bucket', 'arn:aws:s3:::example-bucket/*'],
              Condition: {
                Bool: {
                  'aws:SecureTransport': 'true'
                }
              }
            },
            {
              Effect: 'Deny',
              Principal: { AWS: 'arn:aws:iam::100000000001:user/Alice' },
              Action: ['s3:DeleteObject'],
              Resource: ['arn:aws:s3:::example-bucket/*'],
              Condition: {
                StringNotEquals: {
                  's3:x-amz-server-side-encryption': 'AES256'
                }
              }
            }
          ]
        }
      }
    ],
    expectedAllows: [
      [
        {
          effect: 'Allow',
          action: 's3:GetObject',
          resource: ['arn:aws:s3:::example-bucket', 'arn:aws:s3:::example-bucket/*'],
          conditions: {
            Bool: {
              'aws:SecureTransport': ['true']
            }
          }
        },
        {
          effect: 'Allow',
          action: 's3:PutObject',
          resource: ['arn:aws:s3:::example-bucket', 'arn:aws:s3:::example-bucket/*'],
          conditions: {
            Bool: {
              'aws:SecureTransport': ['true']
            }
          }
        }
      ]
    ],
    expectedDenies: [
      [
        {
          effect: 'Deny',
          action: 's3:DeleteObject',
          resource: ['arn:aws:s3:::example-bucket/*'],
          conditions: {
            StringNotEquals: {
              's3:x-amz-server-side-encryption': ['AES256']
            }
          }
        }
      ]
    ]
  },
  {
    name: 'bucket policy with NotPrincipal excluding different principal should allow our principal',
    principal: 'arn:aws:iam::100000000001:user/Alice',
    buckets: [
      {
        arn: 'arn:aws:s3:::example-bucket',
        account: '100000000001',
        policy: {
          Version: '2012-10-17',
          Statement: [
            {
              Effect: 'Allow',
              NotPrincipal: { AWS: 'arn:aws:iam::100000000001:user/Bob' },
              Action: ['s3:GetObject', 's3:ListBucket'],
              Resource: ['arn:aws:s3:::example-bucket', 'arn:aws:s3:::example-bucket/*']
            },
            {
              Effect: 'Deny',
              NotPrincipal: { AWS: 'arn:aws:iam::100000000001:user/Charlie' },
              Action: ['s3:DeleteObject'],
              Resource: ['arn:aws:s3:::example-bucket/*']
            }
          ]
        }
      }
    ],
    expectedAllows: [
      [
        {
          effect: 'Allow',
          action: 's3:GetObject',
          resource: ['arn:aws:s3:::example-bucket', 'arn:aws:s3:::example-bucket/*']
        },
        {
          effect: 'Allow',
          action: 's3:ListBucket',
          resource: ['arn:aws:s3:::example-bucket', 'arn:aws:s3:::example-bucket/*']
        }
      ]
    ],
    expectedDenies: [
      [
        {
          effect: 'Deny',
          action: 's3:DeleteObject',
          resource: ['arn:aws:s3:::example-bucket/*']
        }
      ]
    ]
  },
  {
    name: 'bucket policy with principal condition key should be included when matching',
    principal: 'arn:aws:iam::100000000001:user/Alice',
    buckets: [
      {
        arn: 'arn:aws:s3:::example-bucket',
        account: '100000000001',
        policy: {
          Version: '2012-10-17',
          Statement: [
            {
              Effect: 'Allow',
              Principal: '*',
              Action: ['s3:GetObject', 's3:ListBucket'],
              Resource: ['arn:aws:s3:::example-bucket', 'arn:aws:s3:::example-bucket/*'],
              Condition: {
                StringEquals: {
                  'aws:PrincipalAccount': '100000000001'
                }
              }
            },
            {
              Effect: 'Deny',
              Principal: '*',
              Action: ['s3:DeleteObject'],
              Resource: ['arn:aws:s3:::example-bucket/*'],
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
    expectedAllows: [
      [
        {
          effect: 'Allow',
          action: 's3:GetObject',
          resource: ['arn:aws:s3:::example-bucket', 'arn:aws:s3:::example-bucket/*'],
          conditions: {
            StringEquals: {
              'aws:PrincipalAccount': ['100000000001']
            }
          }
        },
        {
          effect: 'Allow',
          action: 's3:ListBucket',
          resource: ['arn:aws:s3:::example-bucket', 'arn:aws:s3:::example-bucket/*'],
          conditions: {
            StringEquals: {
              'aws:PrincipalAccount': ['100000000001']
            }
          }
        }
      ]
    ],
    expectedDenies: []
  },
  {
    name: 'bucket policy with invalid actions should exclude actions that do not apply to buckets',
    principal: 'arn:aws:iam::100000000001:user/Alice',
    buckets: [
      {
        arn: 'arn:aws:s3:::example-bucket',
        account: '100000000001',
        policy: {
          Version: '2012-10-17',
          Statement: [
            {
              Effect: 'Allow',
              Principal: { AWS: 'arn:aws:iam::100000000001:user/Alice' },
              Action: ['s3:GetObject', 's3:ListAllMyBuckets', 's3:ListBucket', 's3:CreateBucket'],
              Resource: ['arn:aws:s3:::example-bucket', 'arn:aws:s3:::example-bucket/*']
            },
            {
              Effect: 'Deny',
              Principal: { AWS: 'arn:aws:iam::100000000001:user/Alice' },
              Action: ['s3:DeleteObject', 's3:ListAllMyBuckets', 's3:GetAccountPublicAccessBlock'],
              Resource: ['arn:aws:s3:::example-bucket/*']
            }
          ]
        }
      }
    ],
    expectedAllows: [
      [
        {
          effect: 'Allow',
          action: 's3:GetObject',
          resource: ['arn:aws:s3:::example-bucket', 'arn:aws:s3:::example-bucket/*']
        },
        {
          effect: 'Allow',
          action: 's3:ListBucket',
          resource: ['arn:aws:s3:::example-bucket', 'arn:aws:s3:::example-bucket/*']
        }
      ]
    ],
    expectedDenies: [
      [
        {
          effect: 'Deny',
          action: 's3:DeleteObject',
          resource: ['arn:aws:s3:::example-bucket/*']
        }
      ]
    ]
  }
]

describe('s3BucketsSameAccount', () => {
  s3BucketsSameAccountTests.forEach((t) => {
    const testFn = t.only ? it.only : it
    testFn(t.name, async () => {
      // Given a mock principal and buckets
      const { store, client } = testStore()

      for (const b of t.buckets) {
        await store.saveResourceMetadata(b.account, b.arn, 'metadata', {
          arn: b.arn
        })
        await store.saveResourceMetadata(b.account, b.arn, 'policy', b.policy)
      }

      const principalAccount = splitArnParts(t.principal).accountId!
      await store.saveResourceMetadata(principalAccount, t.principal, 'metadata', {
        arn: t.principal
      })

      // When we check access
      const { allows, denies } = await s3BucketsSameAccount(client, t.principal)

      // Then we get the expected allows and denies
      expect(allows).toHaveLength(t.expectedAllows.length)
      expect(denies).toHaveLength(t.expectedDenies.length)

      for (let i = 0; i < t.expectedAllows.length; i++) {
        const expected = t.expectedAllows[i]
        const actual = allows[i]
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

const s3BucketCrossAccountTests: {
  name: string
  only?: true
  principal: string
  accountId: string
  buckets: { arn: string; account: string; policy: any }[]
  rcps: any[]
  expectedAllows: TestPermission[][]
  expectedDenies: TestPermission[][]
}[] = [
  {
    name: 'no buckets',
    principal: 'arn:aws:iam::200000000001:user/Alice',
    accountId: '100000000001',
    buckets: [],
    rcps: [],
    expectedAllows: [],
    expectedDenies: []
  },
  {
    name: 'one bucket but no cross account policy',
    principal: 'arn:aws:iam::200000000001:user/Alice',
    accountId: '100000000001',
    buckets: [
      {
        arn: 'arn:aws:s3:::example-bucket',
        account: '100000000001',
        policy: null
      }
    ],
    rcps: [],
    expectedAllows: [],
    expectedDenies: []
  },
  {
    name: 'one bucket with matching cross-account allow policy',
    principal: 'arn:aws:iam::200000000001:user/Alice',
    accountId: '100000000001',
    buckets: [
      {
        arn: 'arn:aws:s3:::example-bucket',
        account: '100000000001',
        policy: {
          Version: '2012-10-17',
          Statement: [
            {
              Effect: 'Allow',
              Principal: { AWS: 'arn:aws:iam::200000000001:user/Alice' },
              Action: ['s3:GetObject', 's3:ListBucket'],
              Resource: ['arn:aws:s3:::example-bucket', 'arn:aws:s3:::example-bucket/*']
            }
          ]
        }
      }
    ],
    rcps: [],
    expectedAllows: [
      [
        {
          effect: 'Allow',
          action: 's3:GetObject',
          resource: ['arn:aws:s3:::example-bucket', 'arn:aws:s3:::example-bucket/*']
        },
        {
          effect: 'Allow',
          action: 's3:ListBucket',
          resource: ['arn:aws:s3:::example-bucket', 'arn:aws:s3:::example-bucket/*']
        }
      ]
    ],
    expectedDenies: []
  },
  {
    name: 'bucket with cross-account allow granted to principal account',
    principal: 'arn:aws:iam::200000000001:user/Alice',
    accountId: '100000000001',
    buckets: [
      {
        arn: 'arn:aws:s3:::example-bucket',
        account: '100000000001',
        policy: {
          Version: '2012-10-17',
          Statement: [
            {
              Effect: 'Allow',
              Principal: { AWS: 'arn:aws:iam::200000000001:root' },
              Action: ['s3:GetObject', 's3:ListBucket'],
              Resource: ['arn:aws:s3:::example-bucket', 'arn:aws:s3:::example-bucket/*']
            }
          ]
        }
      }
    ],
    rcps: [],
    expectedAllows: [
      [
        {
          effect: 'Allow',
          action: 's3:GetObject',
          resource: ['arn:aws:s3:::example-bucket', 'arn:aws:s3:::example-bucket/*']
        },
        {
          effect: 'Allow',
          action: 's3:ListBucket',
          resource: ['arn:aws:s3:::example-bucket', 'arn:aws:s3:::example-bucket/*']
        }
      ]
    ],
    expectedDenies: []
  },
  {
    name: 'bucket with deny statement for cross-account principal without corresponding allow',
    principal: 'arn:aws:iam::200000000001:user/Alice',
    accountId: '100000000001',
    buckets: [
      {
        arn: 'arn:aws:s3:::example-bucket',
        account: '100000000001',
        policy: {
          Version: '2012-10-17',
          Statement: [
            {
              Effect: 'Deny',
              Principal: { AWS: 'arn:aws:iam::200000000001:user/Alice' },
              Action: ['s3:DeleteObject'],
              Resource: ['arn:aws:s3:::example-bucket/*']
            }
          ]
        }
      }
    ],
    rcps: [],
    expectedAllows: [],
    // Denies only included if there's a corresponding allow
    expectedDenies: []
  },
  {
    name: 'bucket with both allow and deny for cross-account principal',
    principal: 'arn:aws:iam::200000000001:user/Alice',
    accountId: '100000000001',
    buckets: [
      {
        arn: 'arn:aws:s3:::example-bucket',
        account: '100000000001',
        policy: {
          Version: '2012-10-17',
          Statement: [
            {
              Effect: 'Allow',
              Principal: { AWS: 'arn:aws:iam::200000000001:user/Alice' },
              Action: ['s3:GetObject', 's3:PutObject'],
              Resource: ['arn:aws:s3:::example-bucket', 'arn:aws:s3:::example-bucket/*']
            },
            {
              Effect: 'Deny',
              Principal: { AWS: 'arn:aws:iam::200000000001:user/Alice' },
              Action: ['s3:DeleteObject'],
              Resource: ['arn:aws:s3:::example-bucket/*']
            }
          ]
        }
      }
    ],
    rcps: [],
    expectedAllows: [
      [
        {
          effect: 'Allow',
          action: 's3:GetObject',
          resource: ['arn:aws:s3:::example-bucket', 'arn:aws:s3:::example-bucket/*']
        },
        {
          effect: 'Allow',
          action: 's3:PutObject',
          resource: ['arn:aws:s3:::example-bucket', 'arn:aws:s3:::example-bucket/*']
        }
      ]
    ],
    expectedDenies: [
      // We don't expect the deny to be included since there's no corresponding allow for DeleteObject
    ]
  },
  {
    name: 'bucket policy for different cross-account principal should not match',
    principal: 'arn:aws:iam::200000000001:user/Alice',
    accountId: '100000000001',
    buckets: [
      {
        arn: 'arn:aws:s3:::example-bucket',
        account: '100000000001',
        policy: {
          Version: '2012-10-17',
          Statement: [
            {
              Effect: 'Allow',
              Principal: { AWS: 'arn:aws:iam::200000000001:user/Bob' },
              Action: ['s3:GetObject', 's3:ListBucket'],
              Resource: ['arn:aws:s3:::example-bucket', 'arn:aws:s3:::example-bucket/*']
            }
          ]
        }
      }
    ],
    rcps: [],
    expectedAllows: [],
    expectedDenies: []
  },
  {
    name: 'bucket policy for same-account principal should not match cross-account principal',
    principal: 'arn:aws:iam::200000000001:user/Alice',
    accountId: '100000000001',
    buckets: [
      {
        arn: 'arn:aws:s3:::example-bucket',
        account: '100000000001',
        policy: {
          Version: '2012-10-17',
          Statement: [
            {
              Effect: 'Allow',
              Principal: { AWS: 'arn:aws:iam::100000000001:user/Alice' },
              Action: ['s3:GetObject', 's3:ListBucket'],
              Resource: ['arn:aws:s3:::example-bucket', 'arn:aws:s3:::example-bucket/*']
            }
          ]
        }
      }
    ],
    rcps: [],
    expectedAllows: [],
    expectedDenies: []
  },
  {
    name: 'bucket policy with wildcard resource should be limited to bucket scope',
    principal: 'arn:aws:iam::200000000001:user/Alice',
    accountId: '100000000001',
    buckets: [
      {
        arn: 'arn:aws:s3:::example-bucket',
        account: '100000000001',
        policy: {
          Version: '2012-10-17',
          Statement: [
            {
              Effect: 'Allow',
              Principal: { AWS: 'arn:aws:iam::200000000001:user/Alice' },
              Action: ['s3:GetObject', 's3:ListBucket'],
              Resource: '*'
            }
          ]
        }
      }
    ],
    rcps: [],
    expectedAllows: [
      [
        {
          effect: 'Allow',
          action: 's3:GetObject',
          resource: ['arn:aws:s3:::example-bucket', 'arn:aws:s3:::example-bucket/*']
        },
        {
          effect: 'Allow',
          action: 's3:ListBucket',
          resource: ['arn:aws:s3:::example-bucket', 'arn:aws:s3:::example-bucket/*']
        }
      ]
    ],
    expectedDenies: []
  },
  {
    name: 'bucket policy with conditions should be preserved',
    principal: 'arn:aws:iam::200000000001:user/Alice',
    accountId: '100000000001',
    buckets: [
      {
        arn: 'arn:aws:s3:::example-bucket',
        account: '100000000001',
        policy: {
          Version: '2012-10-17',
          Statement: [
            {
              Effect: 'Allow',
              Principal: { AWS: 'arn:aws:iam::200000000001:user/Alice' },
              Action: ['s3:GetObject', 's3:PutObject'],
              Resource: ['arn:aws:s3:::example-bucket', 'arn:aws:s3:::example-bucket/*'],
              Condition: {
                Bool: {
                  'aws:SecureTransport': 'true'
                }
              }
            }
          ]
        }
      }
    ],
    rcps: [],
    expectedAllows: [
      [
        {
          effect: 'Allow',
          action: 's3:GetObject',
          resource: ['arn:aws:s3:::example-bucket', 'arn:aws:s3:::example-bucket/*'],
          conditions: {
            Bool: {
              'aws:SecureTransport': ['true']
            }
          }
        },
        {
          effect: 'Allow',
          action: 's3:PutObject',
          resource: ['arn:aws:s3:::example-bucket', 'arn:aws:s3:::example-bucket/*'],
          conditions: {
            Bool: {
              'aws:SecureTransport': ['true']
            }
          }
        }
      ]
    ],
    expectedDenies: []
  },
  {
    name: 'RCP denies should restrict cross-account bucket access',
    principal: 'arn:aws:iam::200000000001:user/Alice',
    accountId: '100000000001',
    buckets: [
      {
        arn: 'arn:aws:s3:::example-bucket',
        account: '100000000001',
        policy: {
          Version: '2012-10-17',
          Statement: [
            {
              Effect: 'Allow',
              Principal: { AWS: 'arn:aws:iam::200000000001:user/Alice' },
              Action: ['s3:GetObject', 's3:PutObject', 's3:DeleteObject'],
              Resource: ['arn:aws:s3:::example-bucket', 'arn:aws:s3:::example-bucket/*']
            }
          ]
        }
      }
    ],
    rcps: [
      {
        Version: '2012-10-17',
        Statement: [
          {
            Effect: 'Deny',
            Principal: '*',
            Action: ['s3:DeleteObject'],
            Resource: '*'
          }
        ]
      }
    ],
    expectedAllows: [
      [
        {
          effect: 'Allow',
          action: 's3:GetObject',
          resource: ['arn:aws:s3:::example-bucket', 'arn:aws:s3:::example-bucket/*']
        },
        {
          effect: 'Allow',
          action: 's3:PutObject',
          resource: ['arn:aws:s3:::example-bucket', 'arn:aws:s3:::example-bucket/*']
        }
      ]
    ],
    expectedDenies: []
  },
  {
    name: 'RCP denies all actions should block cross-account access entirely',
    principal: 'arn:aws:iam::200000000001:user/Alice',
    accountId: '100000000001',
    buckets: [
      {
        arn: 'arn:aws:s3:::example-bucket',
        account: '100000000001',
        policy: {
          Version: '2012-10-17',
          Statement: [
            {
              Effect: 'Allow',
              Principal: { AWS: 'arn:aws:iam::200000000001:user/Alice' },
              Action: ['s3:GetObject', 's3:PutObject'],
              Resource: ['arn:aws:s3:::example-bucket', 'arn:aws:s3:::example-bucket/*']
            }
          ]
        }
      }
    ],
    rcps: [
      {
        Version: '2012-10-17',
        Statement: [
          {
            Effect: 'Deny',
            Principal: '*',
            Action: ['s3:*'],
            Resource: '*'
          }
        ]
      }
    ],
    expectedAllows: [],
    expectedDenies: []
  },
  {
    name: 'multiple buckets with mixed policies',
    principal: 'arn:aws:iam::200000000001:user/Alice',
    accountId: '100000000001',
    buckets: [
      {
        arn: 'arn:aws:s3:::bucket-one',
        account: '100000000001',
        policy: {
          Version: '2012-10-17',
          Statement: [
            {
              Effect: 'Allow',
              Principal: { AWS: 'arn:aws:iam::200000000001:user/Alice' },
              Action: ['s3:GetObject'],
              Resource: ['arn:aws:s3:::bucket-one', 'arn:aws:s3:::bucket-one/*']
            }
          ]
        }
      },
      {
        arn: 'arn:aws:s3:::bucket-two',
        account: '100000000001',
        policy: {
          Version: '2012-10-17',
          Statement: [
            {
              Effect: 'Allow',
              Principal: { AWS: 'arn:aws:iam::200000000001:user/Alice' },
              Action: ['s3:PutObject'],
              Resource: ['arn:aws:s3:::bucket-two', 'arn:aws:s3:::bucket-two/*']
            }
          ]
        }
      },
      {
        arn: 'arn:aws:s3:::bucket-three',
        account: '100000000001',
        policy: null
      }
    ],
    rcps: [],
    expectedAllows: [
      [
        {
          effect: 'Allow',
          action: 's3:GetObject',
          resource: ['arn:aws:s3:::bucket-one', 'arn:aws:s3:::bucket-one/*']
        }
      ],
      [
        {
          effect: 'Allow',
          action: 's3:PutObject',
          resource: ['arn:aws:s3:::bucket-two', 'arn:aws:s3:::bucket-two/*']
        }
      ]
    ],
    expectedDenies: []
  },
  {
    name: 'bucket with NotPrincipal excluding different principal should allow cross-account access',
    principal: 'arn:aws:iam::200000000001:user/Alice',
    accountId: '100000000001',
    buckets: [
      {
        arn: 'arn:aws:s3:::example-bucket',
        account: '100000000001',
        policy: {
          Version: '2012-10-17',
          Statement: [
            {
              Effect: 'Allow',
              NotPrincipal: { AWS: 'arn:aws:iam::200000000001:user/Bob' },
              Action: ['s3:GetObject', 's3:ListBucket'],
              Resource: ['arn:aws:s3:::example-bucket', 'arn:aws:s3:::example-bucket/*']
            }
          ]
        }
      }
    ],
    rcps: [],
    expectedAllows: [
      [
        {
          effect: 'Allow',
          action: 's3:GetObject',
          resource: ['arn:aws:s3:::example-bucket', 'arn:aws:s3:::example-bucket/*']
        },
        {
          effect: 'Allow',
          action: 's3:ListBucket',
          resource: ['arn:aws:s3:::example-bucket', 'arn:aws:s3:::example-bucket/*']
        }
      ]
    ],
    expectedDenies: []
  },
  {
    name: 'bucket with Principal * and PrincipalAccount condition matching cross-account',
    principal: 'arn:aws:iam::200000000001:user/Alice',
    accountId: '100000000001',
    buckets: [
      {
        arn: 'arn:aws:s3:::example-bucket',
        account: '100000000001',
        policy: {
          Version: '2012-10-17',
          Statement: [
            {
              Effect: 'Allow',
              Principal: '*',
              Action: ['s3:GetObject', 's3:ListBucket'],
              Resource: ['arn:aws:s3:::example-bucket', 'arn:aws:s3:::example-bucket/*'],
              Condition: {
                StringEquals: {
                  'aws:PrincipalAccount': '200000000001'
                }
              }
            }
          ]
        }
      }
    ],
    rcps: [],
    expectedAllows: [
      [
        {
          effect: 'Allow',
          action: 's3:GetObject',
          resource: ['arn:aws:s3:::example-bucket', 'arn:aws:s3:::example-bucket/*'],
          conditions: {
            StringEquals: {
              'aws:PrincipalAccount': ['200000000001']
            }
          }
        },
        {
          effect: 'Allow',
          action: 's3:ListBucket',
          resource: ['arn:aws:s3:::example-bucket', 'arn:aws:s3:::example-bucket/*'],
          conditions: {
            StringEquals: {
              'aws:PrincipalAccount': ['200000000001']
            }
          }
        }
      ]
    ],
    expectedDenies: []
  },
  {
    name: 'bucket with Principal * and PrincipalAccount condition NOT matching cross-account',
    principal: 'arn:aws:iam::200000000001:user/Alice',
    accountId: '100000000001',
    buckets: [
      {
        arn: 'arn:aws:s3:::example-bucket',
        account: '100000000001',
        policy: {
          Version: '2012-10-17',
          Statement: [
            {
              Effect: 'Allow',
              Principal: '*',
              Action: ['s3:GetObject', 's3:ListBucket'],
              Resource: ['arn:aws:s3:::example-bucket', 'arn:aws:s3:::example-bucket/*'],
              Condition: {
                StringEquals: {
                  'aws:PrincipalAccount': '300000000001'
                }
              }
            }
          ]
        }
      }
    ],
    rcps: [],
    expectedAllows: [],
    expectedDenies: []
  },
  {
    name: 'bucket policy with invalid actions should exclude actions that do not apply to buckets',
    principal: 'arn:aws:iam::200000000001:user/Alice',
    accountId: '100000000001',
    buckets: [
      {
        arn: 'arn:aws:s3:::example-bucket',
        account: '100000000001',
        policy: {
          Version: '2012-10-17',
          Statement: [
            {
              Effect: 'Allow',
              Principal: { AWS: 'arn:aws:iam::200000000001:user/Alice' },
              Action: ['s3:GetObject', 's3:ListAllMyBuckets', 's3:ListBucket', 's3:CreateBucket'],
              Resource: ['arn:aws:s3:::example-bucket', 'arn:aws:s3:::example-bucket/*']
            }
          ]
        }
      }
    ],
    rcps: [],
    expectedAllows: [
      [
        {
          effect: 'Allow',
          action: 's3:GetObject',
          resource: ['arn:aws:s3:::example-bucket', 'arn:aws:s3:::example-bucket/*']
        },
        {
          effect: 'Allow',
          action: 's3:ListBucket',
          resource: ['arn:aws:s3:::example-bucket', 'arn:aws:s3:::example-bucket/*']
        }
      ]
    ],
    expectedDenies: []
  }
]

describe('s3BucketsCrossAccount', () => {
  s3BucketCrossAccountTests.forEach((t) => {
    const testFn = t.only ? it.only : it
    testFn(t.name, async () => {
      // Given a mock principal and buckets
      const { store, client } = testStore()

      for (const b of t.buckets) {
        await store.saveResourceMetadata(b.account, b.arn, 'metadata', {
          arn: b.arn
        })
        await store.saveResourceMetadata(b.account, b.arn, 'policy', b.policy)
      }

      const principalAccount = splitArnParts(t.principal).accountId!
      await store.saveResourceMetadata(principalAccount, t.principal, 'metadata', {
        arn: t.principal
      })

      const rcpDenyPermissionSet = new PermissionSet('Deny')
      for (const rcp of t.rcps) {
        const policy = loadPolicy(rcp)
        for (const statement of policy.statements()) {
          addStatementToPermissionSet(statement, rcpDenyPermissionSet)
        }
      }

      // When we check access
      const { allows, denies } = await s3BucketsCrossAccount(
        client,
        t.accountId,
        rcpDenyPermissionSet,
        t.principal
      )

      // Then we get the expected allows and denies
      expect(allows).toHaveLength(t.expectedAllows.length)
      expect(denies).toHaveLength(t.expectedDenies.length)

      for (let i = 0; i < t.expectedAllows.length; i++) {
        const expected = t.expectedAllows[i]
        const actual = allows[i]
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
