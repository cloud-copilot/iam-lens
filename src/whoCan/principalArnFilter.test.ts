import { describe, it, expect } from 'vitest'
import {
  iamPatternToRegex,
  buildPrincipalArnFilter,
  principalMatchesFilter,
  type PrincipalArnFilter,
  type DenyFilterEntry
} from './principalArnFilter.js'

// ---------------------------------------------------------------------------
// iamPatternToRegex
// ---------------------------------------------------------------------------

interface IamPatternToRegexTest {
  name: string
  only?: true
  pattern: string
  testValue: string
  expectedMatch: boolean
}

const iamPatternToRegexTests: IamPatternToRegexTest[] = [
  {
    name: 'exact ARN matches itself',
    pattern: 'arn:aws:iam::123456789012:role/MyRole',
    testValue: 'arn:aws:iam::123456789012:role/MyRole',
    expectedMatch: true
  },
  {
    name: 'exact ARN does not match a different ARN',
    pattern: 'arn:aws:iam::123456789012:role/MyRole',
    testValue: 'arn:aws:iam::123456789012:role/OtherRole',
    expectedMatch: false
  },
  {
    name: '* in account position matches any account',
    pattern: 'arn:aws:iam::*:role/deploy/MyRole',
    testValue: 'arn:aws:iam::123456789012:role/deploy/MyRole',
    expectedMatch: true
  },
  {
    name: '* in account position matches a different account',
    pattern: 'arn:aws:iam::*:role/deploy/MyRole',
    testValue: 'arn:aws:iam::999999999999:role/deploy/MyRole',
    expectedMatch: true
  },
  {
    name: '* in resource path matches nested paths',
    pattern: 'arn:aws:iam::*:role/ec2/*',
    testValue: 'arn:aws:iam::123456789012:role/ec2/instance-profile',
    expectedMatch: true
  },
  {
    name: '* in resource path matches deeply nested paths',
    pattern: 'arn:aws:iam::*:role/ec2/*',
    testValue: 'arn:aws:iam::123456789012:role/ec2/deep/nested/path',
    expectedMatch: true
  },
  {
    name: '* in resource path does not match different prefix',
    pattern: 'arn:aws:iam::*:role/ec2/*',
    testValue: 'arn:aws:iam::123456789012:role/lambda/my-func',
    expectedMatch: false
  },
  {
    name: '? matches exactly one character',
    pattern: 'arn:aws:iam::*:role/app-?',
    testValue: 'arn:aws:iam::123456789012:role/app-a',
    expectedMatch: true
  },
  {
    name: '? does not match zero characters',
    pattern: 'arn:aws:iam::*:role/app-?',
    testValue: 'arn:aws:iam::123456789012:role/app-',
    expectedMatch: false
  },
  {
    name: '? does not match two characters',
    pattern: 'arn:aws:iam::*:role/app-?',
    testValue: 'arn:aws:iam::123456789012:role/app-ab',
    expectedMatch: false
  },
  {
    name: 'match is case-sensitive',
    pattern: 'arn:aws:iam::*:role/MyRole',
    testValue: 'arn:aws:iam::123456789012:role/myrole',
    expectedMatch: false
  },
  {
    name: 'does not match with prefix',
    pattern: 'arn:aws:iam::*:role/MyRole',
    testValue: 'prefix-arn:aws:iam::123:role/MyRole',
    expectedMatch: false
  },
  {
    name: 'does not match with suffix',
    pattern: 'arn:aws:iam::*:role/MyRole',
    testValue: 'arn:aws:iam::123:role/MyRole-suffix',
    expectedMatch: false
  },
  {
    name: 'escapes dots as literals',
    pattern: 'arn:aws:iam::*:role/my.role',
    testValue: 'arn:aws:iam::123:role/my.role',
    expectedMatch: true
  },
  {
    name: 'escaped dot does not match arbitrary character',
    pattern: 'arn:aws:iam::*:role/my.role',
    testValue: 'arn:aws:iam::123:role/myXrole',
    expectedMatch: false
  },
  {
    name: 'escapes plus as literal',
    pattern: 'arn:aws:iam::*:role/my+role',
    testValue: 'arn:aws:iam::123:role/my+role',
    expectedMatch: true
  }
]

describe('iamPatternToRegex', () => {
  for (const test of iamPatternToRegexTests) {
    const func = test.only ? it.only : it
    func(test.name, () => {
      //Given an IAM pattern
      const regex = iamPatternToRegex(test.pattern)

      //When we test it against a value
      const result = regex.test(test.testValue)

      //Then it should match or not match as expected
      expect(result).toBe(test.expectedMatch)
    })
  }
})

// ---------------------------------------------------------------------------
// buildPrincipalArnFilter
// ---------------------------------------------------------------------------

interface BuildFilterTest {
  name: string
  only?: true
  policy: any
  /** The IAM pattern strings expected in allowPatterns. Undefined means filter should be undefined (unless deny entries are expected). */
  expectedPatterns: string[] | undefined
  /** Accounts that should be in exemptAccounts (when filter is defined). */
  expectedExemptAccounts?: string[]
  /** Expected deny-derived allow entries (from Deny + StringNotLike/etc). */
  expectedDenyDerivedAllowEntries?: { actionPatterns: string[]; principalPatterns: string[] }[]
  /** Expected deny entries (from Deny + StringLike/etc). */
  expectedDenyEntries?: { actionPatterns: string[]; principalPatterns: string[] }[]
}

const buildFilterTests: BuildFilterTest[] = [
  {
    name: 'no resource policy',
    policy: undefined,
    expectedPatterns: undefined
  },
  {
    name: 'no wildcard principals',
    policy: {
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Allow',
          Principal: { AWS: 'arn:aws:iam::123456789012:role/SpecificRole' },
          Action: 's3:GetObject',
          Resource: 'arn:aws:s3:::my-bucket/*'
        }
      ]
    },
    expectedPatterns: undefined
  },
  {
    name: 'wildcard-Allow with no conditions',
    policy: {
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Allow',
          Principal: '*',
          Action: 's3:GetObject',
          Resource: 'arn:aws:s3:::my-bucket/*'
        }
      ]
    },
    expectedPatterns: undefined
  },
  {
    name: 'wildcard-Allow with only non-PrincipalArn conditions',
    policy: {
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Allow',
          Principal: { AWS: '*' },
          Action: 's3:GetObject',
          Resource: 'arn:aws:s3:::my-bucket/*',
          Condition: { StringEquals: { 'aws:SourceVpce': 'vpce-123456' } }
        }
      ]
    },
    expectedPatterns: undefined
  },
  {
    name: 'single Allow with StringLike PrincipalArn',
    policy: {
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Allow',
          Principal: { AWS: '*' },
          Action: 's3:GetObject',
          Resource: 'arn:aws:s3:::my-bucket/*',
          Condition: {
            StringLike: { 'aws:PrincipalArn': 'arn:aws:iam::*:role/deploy/*' }
          }
        }
      ]
    },
    expectedPatterns: ['arn:aws:iam::*:role/deploy/*']
  },
  {
    name: 'single Allow with ArnLike PrincipalArn',
    policy: {
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Allow',
          Principal: { AWS: '*' },
          Action: 's3:GetObject',
          Resource: 'arn:aws:s3:::my-bucket/*',
          Condition: {
            ArnLike: { 'aws:PrincipalArn': 'arn:aws:iam::123456789012:role/ec2/*' }
          }
        }
      ]
    },
    expectedPatterns: ['arn:aws:iam::123456789012:role/ec2/*']
  },
  {
    name: 'StringEquals with literal ARN returns no filter (handled as specific principal)',
    policy: {
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Allow',
          Principal: { AWS: '*' },
          Action: 's3:GetObject',
          Resource: 'arn:aws:s3:::my-bucket/*',
          Condition: {
            StringEquals: {
              'aws:PrincipalArn': 'arn:aws:iam::123456789012:role/ExactRole'
            }
          }
        }
      ]
    },
    expectedPatterns: undefined
  },
  {
    name: 'multiple values in a single condition',
    policy: {
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Allow',
          Principal: { AWS: '*' },
          Action: 's3:GetObject',
          Resource: 'arn:aws:s3:::my-bucket/*',
          Condition: {
            StringLike: {
              'aws:PrincipalArn': ['arn:aws:iam::*:role/deploy/*', 'arn:aws:iam::*:role/admin/*']
            }
          }
        }
      ]
    },
    expectedPatterns: ['arn:aws:iam::*:role/admin/*', 'arn:aws:iam::*:role/deploy/*']
  },
  {
    name: 'union patterns across multiple Allow statements',
    policy: {
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Allow',
          Principal: { AWS: '*' },
          Action: 's3:GetObject',
          Resource: 'arn:aws:s3:::my-bucket/*',
          Condition: {
            StringLike: { 'aws:PrincipalArn': 'arn:aws:iam::*:role/deploy/*' }
          }
        },
        {
          Effect: 'Allow',
          Principal: { AWS: '*' },
          Action: 's3:PutObject',
          Resource: 'arn:aws:s3:::my-bucket/*',
          Condition: {
            ArnLike: { 'aws:PrincipalArn': 'arn:aws:iam::*:role/admin/*' }
          }
        }
      ]
    },
    expectedPatterns: ['arn:aws:iam::*:role/admin/*', 'arn:aws:iam::*:role/deploy/*']
  },
  {
    name: 'one wildcard-Allow without PrincipalArn disables filter',
    policy: {
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Allow',
          Principal: { AWS: '*' },
          Action: 's3:GetObject',
          Resource: 'arn:aws:s3:::my-bucket/*',
          Condition: {
            StringLike: { 'aws:PrincipalArn': 'arn:aws:iam::*:role/deploy/*' }
          }
        },
        {
          Effect: 'Allow',
          Principal: '*',
          Action: 's3:ListBucket',
          Resource: 'arn:aws:s3:::my-bucket'
        }
      ]
    },
    expectedPatterns: undefined
  },
  {
    name: 'any condition value with replacement variable disables filter',
    policy: {
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Allow',
          Principal: { AWS: '*' },
          Action: 's3:GetObject',
          Resource: 'arn:aws:s3:::my-bucket/*',
          Condition: {
            StringLike: {
              'aws:PrincipalArn': [
                'arn:aws:iam::${aws:PrincipalAccount}:role/deploy/*',
                'arn:aws:iam::*:role/admin/*'
              ]
            }
          }
        }
      ]
    },
    expectedPatterns: undefined
  },
  {
    name: 'Deny statements are ignored',
    policy: {
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Allow',
          Principal: { AWS: '*' },
          Action: 's3:GetObject',
          Resource: 'arn:aws:s3:::my-bucket/*',
          Condition: {
            StringLike: { 'aws:PrincipalArn': 'arn:aws:iam::*:role/deploy/*' }
          }
        },
        {
          Effect: 'Deny',
          Principal: '*',
          Action: 's3:*',
          Resource: 'arn:aws:s3:::my-bucket/*',
          Condition: {
            StringNotLike: { 'aws:PrincipalArn': 'arn:aws:iam::*:role/deploy/*' }
          }
        }
      ]
    },
    expectedPatterns: ['arn:aws:iam::*:role/deploy/*']
  },
  {
    name: 'unsupported operator StringNotLike on Allow disables filter',
    policy: {
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Allow',
          Principal: { AWS: '*' },
          Action: 's3:GetObject',
          Resource: 'arn:aws:s3:::my-bucket/*',
          Condition: {
            StringNotLike: { 'aws:PrincipalArn': 'arn:aws:iam::*:role/bad/*' }
          }
        }
      ]
    },
    expectedPatterns: undefined
  },
  {
    name: 'NotPrincipal Allow disables filter',
    policy: {
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Allow',
          NotPrincipal: { AWS: 'arn:aws:iam::123456789012:role/Excluded' },
          Action: 's3:GetObject',
          Resource: 'arn:aws:s3:::my-bucket/*'
        }
      ]
    },
    expectedPatterns: undefined
  },
  {
    name: 'non-wildcard Allow statements are skipped',
    policy: {
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Allow',
          Principal: { AWS: 'arn:aws:iam::123456789012:role/SpecificRole' },
          Action: 's3:GetObject',
          Resource: 'arn:aws:s3:::my-bucket/*'
        },
        {
          Effect: 'Allow',
          Principal: { AWS: '*' },
          Action: 's3:PutObject',
          Resource: 'arn:aws:s3:::my-bucket/*',
          Condition: {
            ArnLike: { 'aws:PrincipalArn': 'arn:aws:iam::*:role/deploy/*' }
          }
        }
      ]
    },
    expectedPatterns: ['arn:aws:iam::*:role/deploy/*']
  },
  {
    name: 'explicit account principal is added to exemptAccounts',
    policy: {
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Allow',
          Principal: { AWS: '111122223333' },
          Action: 's3:GetObject',
          Resource: 'arn:aws:s3:::my-bucket/*'
        },
        {
          Effect: 'Allow',
          Principal: { AWS: '*' },
          Action: 's3:GetObject',
          Resource: 'arn:aws:s3:::my-bucket/*',
          Condition: {
            StringLike: { 'aws:PrincipalArn': 'arn:aws:iam::*:role/ReadOnly*' }
          }
        }
      ]
    },
    expectedPatterns: ['arn:aws:iam::*:role/ReadOnly*'],
    expectedExemptAccounts: ['111122223333']
  },
  {
    name: 'multiple explicit account principals are all exempt',
    policy: {
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Allow',
          Principal: { AWS: ['111122223333', '444455556666'] },
          Action: 's3:GetObject',
          Resource: 'arn:aws:s3:::my-bucket/*'
        },
        {
          Effect: 'Allow',
          Principal: { AWS: '*' },
          Action: 's3:GetObject',
          Resource: 'arn:aws:s3:::my-bucket/*',
          Condition: {
            ArnLike: { 'aws:PrincipalArn': 'arn:aws:iam::*:role/deploy/*' }
          }
        }
      ]
    },
    expectedPatterns: ['arn:aws:iam::*:role/deploy/*'],
    expectedExemptAccounts: ['111122223333', '444455556666']
  },
  {
    name: 'root ARN account principal is added to exemptAccounts',
    policy: {
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Allow',
          Principal: { AWS: 'arn:aws:iam::111122223333:root' },
          Action: 's3:GetObject',
          Resource: 'arn:aws:s3:::my-bucket/*'
        },
        {
          Effect: 'Allow',
          Principal: { AWS: '*' },
          Action: 's3:GetObject',
          Resource: 'arn:aws:s3:::my-bucket/*',
          Condition: {
            StringLike: { 'aws:PrincipalArn': 'arn:aws:iam::*:role/ReadOnly*' }
          }
        }
      ]
    },
    expectedPatterns: ['arn:aws:iam::*:role/ReadOnly*'],
    expectedExemptAccounts: ['111122223333']
  },
  {
    name: 'ArnLikeIfExists uses baseOperator and produces a filter',
    policy: {
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Allow',
          Principal: { AWS: '*' },
          Action: 's3:GetObject',
          Resource: 'arn:aws:s3:::my-bucket/*',
          Condition: {
            ArnLikeIfExists: { 'aws:PrincipalArn': 'arn:aws:iam::*:role/deploy/*' }
          }
        }
      ]
    },
    expectedPatterns: ['arn:aws:iam::*:role/deploy/*']
  },
  {
    name: 'ForAnyValue: set operator prefix is supported',
    policy: {
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Allow',
          Principal: { AWS: '*' },
          Action: 's3:GetObject',
          Resource: 'arn:aws:s3:::my-bucket/*',
          Condition: {
            'ForAnyValue:StringLike': {
              'aws:PrincipalArn': 'arn:aws:iam::*:role/deploy/*'
            }
          }
        }
      ]
    },
    expectedPatterns: ['arn:aws:iam::*:role/deploy/*']
  },
  {
    name: 'Statement with one literal Principal ARN and one wildcard ARN',
    policy: {
      Statement: [
        {
          Sid: 'LambdaAccess',
          Effect: 'Allow',
          Action: 's3:GetObject*',
          Principal: {
            AWS: '*'
          },
          Resource: 'arn:aws:s3:::my-bucket/*',
          Condition: {
            StringEquals: {
              'aws:PrincipalOrgID': 'o-111111'
            },
            StringLike: {
              'aws:PrincipalArn': 'arn:aws:iam::111111111111:role/lambda/util/logger'
            }
          }
        },
        {
          Sid: 'OrgAccess',
          Effect: 'Allow',
          Action: 's3:GetObject',
          Principal: {
            AWS: '*'
          },
          Resource: 'arn:aws:s3:::my-bucket/*',
          Condition: {
            StringEquals: {
              'aws:PrincipalOrgID': 'o-111111'
            },
            StringLike: {
              'aws:PrincipalArn': 'arn:aws:iam::*:role/engineer'
            }
          }
        }
      ]
    },
    expectedPatterns: ['arn:aws:iam::*:role/engineer']
  },
  // --- Deny statement extraction: Case 1 (StringNotLike → denyDerivedAllowEntries) ---
  {
    name: 'Deny with StringNotLike extracts deny-derived allow entry',
    policy: {
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Deny',
          Principal: '*',
          Action: 'secretsmanager:GetSecretValue',
          Resource: '*',
          Condition: {
            StringNotLike: {
              'aws:PrincipalArn': [
                'arn:aws:iam::*:role/bx_admin',
                'arn:aws:iam::*:role/k8s-pod/msvc/*'
              ]
            }
          }
        }
      ]
    },
    expectedPatterns: undefined,
    expectedDenyDerivedAllowEntries: [
      {
        actionPatterns: ['secretsmanager:GetSecretValue'],
        principalPatterns: ['arn:aws:iam::*:role/bx_admin', 'arn:aws:iam::*:role/k8s-pod/msvc/*']
      }
    ]
  },
  {
    name: 'Deny with ArnNotLike extracts deny-derived allow entry',
    policy: {
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Deny',
          Principal: { AWS: '*' },
          Action: 's3:GetObject',
          Resource: '*',
          Condition: {
            ArnNotLike: { 'aws:PrincipalArn': 'arn:aws:iam::*:role/deploy/*' }
          }
        }
      ]
    },
    expectedPatterns: undefined,
    expectedDenyDerivedAllowEntries: [
      { actionPatterns: ['s3:GetObject'], principalPatterns: ['arn:aws:iam::*:role/deploy/*'] }
    ]
  },
  {
    name: 'Deny with StringNotEquals extracts deny-derived allow entry',
    policy: {
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Deny',
          Principal: '*',
          Action: 'kms:Decrypt',
          Resource: '*',
          Condition: {
            StringNotEquals: {
              'aws:PrincipalArn': 'arn:aws:iam::123456789012:role/AllowedRole'
            }
          }
        }
      ]
    },
    expectedPatterns: undefined,
    expectedDenyDerivedAllowEntries: [
      {
        actionPatterns: ['kms:Decrypt'],
        principalPatterns: ['arn:aws:iam::123456789012:role/AllowedRole']
      }
    ]
  },
  {
    name: 'Deny with wildcard action extracts entry with wildcard action',
    policy: {
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Deny',
          Principal: '*',
          Action: '*',
          Resource: '*',
          Condition: {
            StringNotLike: { 'aws:PrincipalArn': 'arn:aws:iam::*:role/admin' }
          }
        }
      ]
    },
    expectedPatterns: undefined,
    expectedDenyDerivedAllowEntries: [
      { actionPatterns: ['*'], principalPatterns: ['arn:aws:iam::*:role/admin'] }
    ]
  },
  // --- Deny statement extraction: Case 2 (StringLike → denyEntries) ---
  {
    name: 'Deny with StringLike extracts deny entry',
    policy: {
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Deny',
          Principal: '*',
          Action: 's3:GetObject',
          Resource: '*',
          Condition: {
            StringLike: { 'aws:PrincipalArn': 'arn:aws:iam::*:role/blocked-*' }
          }
        }
      ]
    },
    expectedPatterns: undefined,
    expectedDenyEntries: [
      { actionPatterns: ['s3:GetObject'], principalPatterns: ['arn:aws:iam::*:role/blocked-*'] }
    ]
  },
  {
    name: 'Deny with ArnLike extracts deny entry',
    policy: {
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Deny',
          Principal: '*',
          Action: 's3:PutObject',
          Resource: '*',
          Condition: {
            ArnLike: { 'aws:PrincipalArn': 'arn:aws:iam::*:role/readonly-*' }
          }
        }
      ]
    },
    expectedPatterns: undefined,
    expectedDenyEntries: [
      { actionPatterns: ['s3:PutObject'], principalPatterns: ['arn:aws:iam::*:role/readonly-*'] }
    ]
  },
  {
    name: 'Deny with StringEquals extracts deny entry',
    policy: {
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Deny',
          Principal: '*',
          Action: 'kms:Encrypt',
          Resource: '*',
          Condition: {
            StringEquals: {
              'aws:PrincipalArn': 'arn:aws:iam::123456789012:role/BlockedRole'
            }
          }
        }
      ]
    },
    expectedPatterns: undefined,
    expectedDenyEntries: [
      {
        actionPatterns: ['kms:Encrypt'],
        principalPatterns: ['arn:aws:iam::123456789012:role/BlockedRole']
      }
    ]
  },
  // --- Conditions that prevent deny extraction ---
  {
    name: 'Deny with additional conditions — not extracted',
    policy: {
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Deny',
          Principal: '*',
          Action: 's3:GetObject',
          Resource: '*',
          Condition: {
            StringNotLike: { 'aws:PrincipalArn': 'arn:aws:iam::*:role/admin' },
            Bool: { 'aws:ViaAWSService': 'true' }
          }
        }
      ]
    },
    expectedPatterns: undefined
  },
  {
    name: 'Deny with IfExists — not extracted',
    policy: {
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Deny',
          Principal: '*',
          Action: 's3:GetObject',
          Resource: '*',
          Condition: {
            StringNotLikeIfExists: { 'aws:PrincipalArn': 'arn:aws:iam::*:role/admin' }
          }
        }
      ]
    },
    expectedPatterns: undefined
  },
  {
    name: 'Deny with replacement variables — not extracted',
    policy: {
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Deny',
          Principal: '*',
          Action: 's3:GetObject',
          Resource: '*',
          Condition: {
            StringNotLike: { 'aws:PrincipalArn': '${aws:PrincipalArn}' }
          }
        }
      ]
    },
    expectedPatterns: undefined
  },
  {
    name: 'Deny with non-wildcard principal — not extracted',
    policy: {
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Deny',
          Principal: { AWS: 'arn:aws:iam::123456789012:role/SpecificRole' },
          Action: 's3:GetObject',
          Resource: '*',
          Condition: {
            StringNotLike: { 'aws:PrincipalArn': 'arn:aws:iam::*:role/admin' }
          }
        }
      ]
    },
    expectedPatterns: undefined
  },
  {
    name: 'Deny with NotPrincipal — not extracted',
    policy: {
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Deny',
          NotPrincipal: { AWS: 'arn:aws:iam::123456789012:role/Excluded' },
          Action: 's3:GetObject',
          Resource: '*',
          Condition: {
            StringNotLike: { 'aws:PrincipalArn': 'arn:aws:iam::*:role/admin' }
          }
        }
      ]
    },
    expectedPatterns: undefined
  },
  {
    name: 'Deny with NotAction — not extracted',
    policy: {
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Deny',
          Principal: '*',
          NotAction: 's3:GetObject',
          Resource: '*',
          Condition: {
            StringNotLike: { 'aws:PrincipalArn': 'arn:aws:iam::*:role/admin' }
          }
        }
      ]
    },
    expectedPatterns: undefined
  },
  {
    name: 'Allow statement not extracted as deny entry',
    policy: {
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Allow',
          Principal: '*',
          Action: 's3:GetObject',
          Resource: '*',
          Condition: {
            StringNotLike: { 'aws:PrincipalArn': 'arn:aws:iam::*:role/admin' }
          }
        }
      ]
    },
    expectedPatterns: undefined
  },
  // --- Resource element checks ---
  {
    name: 'Deny with Resource * — extracted',
    policy: {
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Deny',
          Principal: '*',
          Action: 's3:GetObject',
          Resource: '*',
          Condition: {
            StringNotLike: { 'aws:PrincipalArn': 'arn:aws:iam::*:role/admin' }
          }
        }
      ]
    },
    expectedPatterns: undefined,
    expectedDenyDerivedAllowEntries: [
      { actionPatterns: ['s3:GetObject'], principalPatterns: ['arn:aws:iam::*:role/admin'] }
    ]
  },
  {
    name: 'Deny with specific Resource ARN (not *) — not extracted',
    policy: {
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Deny',
          Principal: '*',
          Action: 's3:GetObject',
          Resource: 'arn:aws:s3:::my-bucket/*',
          Condition: {
            StringNotLike: { 'aws:PrincipalArn': 'arn:aws:iam::*:role/admin' }
          }
        }
      ]
    },
    expectedPatterns: undefined
  },
  {
    name: 'Deny with Resource array containing * and specific ARN — extracted',
    policy: {
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Deny',
          Principal: '*',
          Action: 's3:GetObject',
          Resource: ['arn:aws:s3:::my-bucket/*', '*'],
          Condition: {
            StringNotLike: { 'aws:PrincipalArn': 'arn:aws:iam::*:role/admin' }
          }
        }
      ]
    },
    expectedPatterns: undefined,
    expectedDenyDerivedAllowEntries: [
      { actionPatterns: ['s3:GetObject'], principalPatterns: ['arn:aws:iam::*:role/admin'] }
    ]
  },
  {
    name: 'Deny with NotResource — not extracted',
    policy: {
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Deny',
          Principal: '*',
          Action: 's3:GetObject',
          NotResource: '*',
          Condition: {
            StringNotLike: { 'aws:PrincipalArn': 'arn:aws:iam::*:role/admin' }
          }
        }
      ]
    },
    expectedPatterns: undefined
  },
  // --- Integration: allow + deny entries both present ---
  {
    name: 'Allow patterns and deny entries both extracted from same policy',
    policy: {
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Allow',
          Principal: { AWS: '*' },
          Action: 's3:GetObject',
          Resource: 'arn:aws:s3:::my-bucket/*',
          Condition: {
            StringLike: { 'aws:PrincipalArn': 'arn:aws:iam::*:role/deploy/*' }
          }
        },
        {
          Effect: 'Deny',
          Principal: '*',
          Action: 's3:GetObject',
          Resource: '*',
          Condition: {
            StringNotLike: { 'aws:PrincipalArn': 'arn:aws:iam::*:role/deploy/prod-*' }
          }
        }
      ]
    },
    expectedPatterns: ['arn:aws:iam::*:role/deploy/*'],
    expectedDenyDerivedAllowEntries: [
      {
        actionPatterns: ['s3:GetObject'],
        principalPatterns: ['arn:aws:iam::*:role/deploy/prod-*']
      }
    ]
  },
  {
    name: 'No allow patterns but deny entries present — filter returned',
    policy: {
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Deny',
          Principal: '*',
          Action: 'secretsmanager:GetSecretValue',
          Resource: '*',
          Condition: {
            StringNotLike: { 'aws:PrincipalArn': 'arn:aws:iam::*:role/allowed-*' }
          }
        }
      ]
    },
    expectedPatterns: undefined,
    expectedDenyDerivedAllowEntries: [
      {
        actionPatterns: ['secretsmanager:GetSecretValue'],
        principalPatterns: ['arn:aws:iam::*:role/allowed-*']
      }
    ]
  }
]

describe('buildPrincipalArnFilter', () => {
  for (const test of buildFilterTests) {
    const func = test.only ? it.only : it
    func(test.name, () => {
      //Given a resource policy
      const policy = test.policy

      //When we build a filter
      const filter = buildPrincipalArnFilter(policy)

      //Then it should match the expected result
      const hasDenyExpectations =
        (test.expectedDenyDerivedAllowEntries && test.expectedDenyDerivedAllowEntries.length > 0) ||
        (test.expectedDenyEntries && test.expectedDenyEntries.length > 0)

      if (test.expectedPatterns === undefined && !hasDenyExpectations) {
        expect(filter).toBeUndefined()
      } else {
        expect(filter).toBeDefined()
        const actualPatterns = filter!.allowPatterns.map((r) => r.source).sort()
        const expectedRegexSources = (test.expectedPatterns ?? [])
          .map((p) => iamPatternToRegex(p).source)
          .sort()
        expect(actualPatterns).toEqual(expectedRegexSources)
        if (test.expectedExemptAccounts) {
          expect([...filter!.exemptAccounts].sort()).toEqual(
            [...test.expectedExemptAccounts].sort()
          )
        } else {
          expect(filter!.exemptAccounts.size).toBe(0)
        }

        // Check deny-derived allow entries
        const expectedDDA = test.expectedDenyDerivedAllowEntries ?? []
        expect(filter!.denyDerivedAllowEntries.length).toBe(expectedDDA.length)
        for (let i = 0; i < expectedDDA.length; i++) {
          expect(filter!.denyDerivedAllowEntries[i].actionPatterns).toEqual(
            expectedDDA[i].actionPatterns
          )
          const actualPrincipalSources = filter!.denyDerivedAllowEntries[i].principalPatterns
            .map((r) => r.source)
            .sort()
          const expectedPrincipalSources = expectedDDA[i].principalPatterns
            .map((p) => iamPatternToRegex(p).source)
            .sort()
          expect(actualPrincipalSources).toEqual(expectedPrincipalSources)
        }

        // Check deny entries
        const expectedDE = test.expectedDenyEntries ?? []
        expect(filter!.denyEntries.length).toBe(expectedDE.length)
        for (let i = 0; i < expectedDE.length; i++) {
          expect(filter!.denyEntries[i].actionPatterns).toEqual(expectedDE[i].actionPatterns)
          const actualPrincipalSources = filter!.denyEntries[i].principalPatterns
            .map((r) => r.source)
            .sort()
          const expectedPrincipalSources = expectedDE[i].principalPatterns
            .map((p) => iamPatternToRegex(p).source)
            .sort()
          expect(actualPrincipalSources).toEqual(expectedPrincipalSources)
        }
      }
    })
  }
})

// ---------------------------------------------------------------------------
// principalMatchesFilter
// ---------------------------------------------------------------------------

interface PrincipalMatchesFilterTest {
  name: string
  only?: true
  allowPatterns: string[]
  denyDerivedAllowEntries?: { actionPatterns: string[]; principalPatterns: string[] }[]
  denyEntries?: { actionPatterns: string[]; principalPatterns: string[] }[]
  exemptAccounts?: string[]
  principal: string
  action: string
  resourceAccount: string
  expectedResult: boolean
}

const principalMatchesFilterTests: PrincipalMatchesFilterTest[] = [
  // --- Allow patterns (existing, now with action) ---
  {
    name: 'principal matches a wildcard allow pattern',
    allowPatterns: ['arn:aws:iam::*:role/deploy/*'],
    principal: 'arn:aws:iam::123456789012:role/deploy/my-app',
    action: 's3:GetObject',
    resourceAccount: '000000000000',
    expectedResult: true
  },
  {
    name: 'principal does not match any allow pattern',
    allowPatterns: ['arn:aws:iam::*:role/deploy/*'],
    principal: 'arn:aws:iam::123456789012:role/admin/super-admin',
    action: 's3:GetObject',
    resourceAccount: '000000000000',
    expectedResult: false
  },
  {
    name: 'principal matches second of multiple patterns',
    allowPatterns: ['arn:aws:iam::*:role/deploy/*', 'arn:aws:iam::*:role/admin/*'],
    principal: 'arn:aws:iam::123456789012:role/admin/super-admin',
    action: 's3:GetObject',
    resourceAccount: '000000000000',
    expectedResult: true
  },
  {
    name: 'empty allow patterns allows all principals',
    allowPatterns: [],
    principal: 'arn:aws:iam::123456789012:role/anything',
    action: 's3:GetObject',
    resourceAccount: '000000000000',
    expectedResult: true
  },
  // --- Deny-derived allow entries (from Deny + StringNotLike) ---
  {
    name: 'principal matching deny-derived allow for matching action passes',
    allowPatterns: [],
    denyDerivedAllowEntries: [
      {
        actionPatterns: ['secretsmanager:GetSecretValue'],
        principalPatterns: ['arn:aws:iam::*:role/bx_admin', 'arn:aws:iam::*:role/bx_super']
      }
    ],
    principal: 'arn:aws:iam::123456789012:role/bx_admin',
    action: 'secretsmanager:GetSecretValue',
    resourceAccount: '000000000000',
    expectedResult: true
  },
  {
    name: 'principal NOT matching deny-derived allow for matching action is rejected',
    allowPatterns: [],
    denyDerivedAllowEntries: [
      {
        actionPatterns: ['secretsmanager:GetSecretValue'],
        principalPatterns: ['arn:aws:iam::*:role/bx_admin', 'arn:aws:iam::*:role/bx_super']
      }
    ],
    principal: 'arn:aws:iam::123456789012:role/some-other-role',
    action: 'secretsmanager:GetSecretValue',
    resourceAccount: '000000000000',
    expectedResult: false
  },
  {
    name: 'deny-derived allow for non-matching action has no effect',
    allowPatterns: [],
    denyDerivedAllowEntries: [
      {
        actionPatterns: ['secretsmanager:GetSecretValue'],
        principalPatterns: ['arn:aws:iam::*:role/bx_admin']
      }
    ],
    principal: 'arn:aws:iam::123456789012:role/some-other-role',
    action: 'secretsmanager:DescribeSecret',
    resourceAccount: '000000000000',
    expectedResult: true
  },
  {
    name: 'wildcard action in deny-derived allow matches any action',
    allowPatterns: [],
    denyDerivedAllowEntries: [
      { actionPatterns: ['*'], principalPatterns: ['arn:aws:iam::*:role/bx_admin'] }
    ],
    principal: 'arn:aws:iam::123456789012:role/some-other-role',
    action: 's3:GetObject',
    resourceAccount: '000000000000',
    expectedResult: false
  },
  // --- Deny entries (from Deny + StringLike) ---
  {
    name: 'principal matching deny entry for matching action is rejected',
    allowPatterns: [],
    denyEntries: [
      { actionPatterns: ['s3:GetObject'], principalPatterns: ['arn:aws:iam::*:role/blocked-*'] }
    ],
    principal: 'arn:aws:iam::123456789012:role/blocked-role',
    action: 's3:GetObject',
    resourceAccount: '000000000000',
    expectedResult: false
  },
  {
    name: 'principal matching deny entry for non-matching action passes',
    allowPatterns: [],
    denyEntries: [
      { actionPatterns: ['s3:GetObject'], principalPatterns: ['arn:aws:iam::*:role/blocked-*'] }
    ],
    principal: 'arn:aws:iam::123456789012:role/blocked-role',
    action: 's3:PutObject',
    resourceAccount: '000000000000',
    expectedResult: true
  },
  {
    name: 'principal not matching deny entry passes',
    allowPatterns: [],
    denyEntries: [
      { actionPatterns: ['s3:GetObject'], principalPatterns: ['arn:aws:iam::*:role/blocked-*'] }
    ],
    principal: 'arn:aws:iam::123456789012:role/allowed-role',
    action: 's3:GetObject',
    resourceAccount: '000000000000',
    expectedResult: true
  },
  // --- Combined allow + deny ---
  {
    name: 'principal must pass both allow patterns and deny-derived allow',
    allowPatterns: ['arn:aws:iam::*:role/deploy/*'],
    denyDerivedAllowEntries: [
      {
        actionPatterns: ['s3:GetObject'],
        principalPatterns: ['arn:aws:iam::*:role/deploy/prod-*']
      }
    ],
    principal: 'arn:aws:iam::123456789012:role/deploy/staging-app',
    action: 's3:GetObject',
    resourceAccount: '000000000000',
    expectedResult: false
  },
  {
    name: 'principal passes both allow and deny-derived allow',
    allowPatterns: ['arn:aws:iam::*:role/deploy/*'],
    denyDerivedAllowEntries: [
      {
        actionPatterns: ['s3:GetObject'],
        principalPatterns: ['arn:aws:iam::*:role/deploy/prod-*']
      }
    ],
    principal: 'arn:aws:iam::123456789012:role/deploy/prod-app',
    action: 's3:GetObject',
    resourceAccount: '000000000000',
    expectedResult: true
  },
  // --- Multiple deny entries, only one action matches ---
  {
    name: 'multiple deny entries, only matching action entry applies',
    allowPatterns: [],
    denyEntries: [
      {
        actionPatterns: ['s3:GetObject'],
        principalPatterns: ['arn:aws:iam::*:role/blocked-for-get']
      },
      {
        actionPatterns: ['s3:PutObject'],
        principalPatterns: ['arn:aws:iam::*:role/blocked-for-put']
      }
    ],
    principal: 'arn:aws:iam::123456789012:role/blocked-for-get',
    action: 's3:PutObject',
    resourceAccount: '000000000000',
    expectedResult: true
  },
  // --- Exempt account behavior ---
  {
    name: 'same-account principal bypasses allow pattern filtering',
    allowPatterns: ['arn:aws:iam::*:role/deploy/*'],
    principal: 'arn:aws:iam::111111111111:role/other-role',
    action: 's3:GetObject',
    resourceAccount: '111111111111',
    expectedResult: true
  },
  {
    name: 'exempt-account principal bypasses allow pattern filtering',
    allowPatterns: ['arn:aws:iam::*:role/deploy/*'],
    exemptAccounts: ['222222222222'],
    principal: 'arn:aws:iam::222222222222:role/other-role',
    action: 's3:GetObject',
    resourceAccount: '111111111111',
    expectedResult: true
  },
  {
    name: 'same-account principal NOT matching deny-derived allow is still rejected',
    allowPatterns: [],
    denyDerivedAllowEntries: [
      {
        actionPatterns: ['secretsmanager:GetSecretValue'],
        principalPatterns: ['arn:aws:iam::*:role/allowed-*']
      }
    ],
    principal: 'arn:aws:iam::111111111111:role/not-in-allow-list',
    action: 'secretsmanager:GetSecretValue',
    resourceAccount: '111111111111',
    expectedResult: false
  },
  {
    name: 'same-account principal matching deny-derived allow passes',
    allowPatterns: [],
    denyDerivedAllowEntries: [
      {
        actionPatterns: ['secretsmanager:GetSecretValue'],
        principalPatterns: ['arn:aws:iam::*:role/allowed-*']
      }
    ],
    principal: 'arn:aws:iam::111111111111:role/allowed-role',
    action: 'secretsmanager:GetSecretValue',
    resourceAccount: '111111111111',
    expectedResult: true
  },
  {
    name: 'same-account principal is still subject to deny entry filtering',
    allowPatterns: [],
    denyEntries: [
      {
        actionPatterns: ['s3:GetObject'],
        principalPatterns: ['arn:aws:iam::*:role/blocked-*']
      }
    ],
    principal: 'arn:aws:iam::111111111111:role/blocked-role',
    action: 's3:GetObject',
    resourceAccount: '111111111111',
    expectedResult: false
  },
  {
    name: 'exempt-account principal is still subject to deny entry filtering',
    allowPatterns: [],
    exemptAccounts: ['222222222222'],
    denyEntries: [
      {
        actionPatterns: ['s3:GetObject'],
        principalPatterns: ['arn:aws:iam::*:role/blocked-*']
      }
    ],
    principal: 'arn:aws:iam::222222222222:role/blocked-role',
    action: 's3:GetObject',
    resourceAccount: '111111111111',
    expectedResult: false
  },
  {
    name: 'cross-account non-exempt principal does not bypass allow filtering',
    allowPatterns: ['arn:aws:iam::*:role/deploy/*'],
    principal: 'arn:aws:iam::333333333333:role/other-role',
    action: 's3:GetObject',
    resourceAccount: '111111111111',
    expectedResult: false
  }
]

describe('principalMatchesFilter', () => {
  for (const test of principalMatchesFilterTests) {
    const func = test.only ? it.only : it
    func(test.name, () => {
      //Given a filter
      const filter: PrincipalArnFilter = {
        allowPatterns: test.allowPatterns.map(iamPatternToRegex),
        denyDerivedAllowEntries: (test.denyDerivedAllowEntries ?? []).map((e) => ({
          actionPatterns: e.actionPatterns,
          principalPatterns: e.principalPatterns.map(iamPatternToRegex)
        })),
        denyEntries: (test.denyEntries ?? []).map((e) => ({
          actionPatterns: e.actionPatterns,
          principalPatterns: e.principalPatterns.map(iamPatternToRegex)
        })),
        exemptAccounts: new Set(test.exemptAccounts ?? [])
      }

      //When we check if the principal matches for the action
      const result = principalMatchesFilter(
        test.principal,
        test.action,
        test.resourceAccount,
        filter
      )

      //Then it should return the expected result
      expect(result).toBe(test.expectedResult)
    })
  }
})

// isPrincipalExemptFromFilter tests have been merged into principalMatchesFilter above.
// See the "Exempt account behavior" section in principalMatchesFilterTests.
