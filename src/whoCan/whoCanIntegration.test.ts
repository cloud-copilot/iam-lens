import { createStorageClient, TopLevelConfig } from '@cloud-copilot/iam-collect'
import { existsSync, rmSync } from 'fs'
import { assert, beforeAll, describe, expect, it } from 'vitest'
import { IamCollectClient } from '../collect/client.js'
import { makePrincipalIndex } from '../principalIndex/makePrincipalIndex.js'
import { getTestDatasetClient, getTestDatasetConfigs } from '../test-datasets/testClient.js'
import {
  ResourceAccessRequest,
  whoCan,
  WhoCanAllowed,
  WhoCanDenyDetail,
  WhoCanResponse
} from './whoCan.js'
import { WhoCanProcessor } from './WhoCanProcessor.js'

interface WhoCanIntegrationTest {
  only?: true
  name: string
  description?: string
  comment?: string
  data: string
  request: ResourceAccessRequest
  expected: {
    who: WhoCanAllowed[]
    allAccountsChecked?: true
    accountsNotFound?: string[]
    organizationsNotFound?: string[]
    organizationalUnitsNotFound?: string[]
    principalsNotFound?: string[]
  }
  expectedDenyDetails?: WhoCanDenyDetail[]
}

const whoCanIntegrationTests: WhoCanIntegrationTest[] = [
  {
    name: 'within account and no resource policy',
    data: '1',
    request: {
      actions: ['ec2:TerminateInstances'],
      resource: 'arn:aws:ec2:us-east-1:100000000001:instance/i-1234567890abcdef0'
    },
    expected: {
      who: [
        {
          action: 'TerminateInstances',
          principal:
            'arn:aws:iam::100000000001:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_AdministratorAccess_0fed56ec5d997fc5',
          service: 'ec2',
          level: 'write',
          resourceType: 'instance'
        }
      ]
    }
  },
  {
    name: 'within account wildcard action',
    data: '1',
    request: {
      resourceAccount: '100000000002',
      actions: ['ec2:DescribeInstances']
    },
    expected: {
      who: [
        {
          action: 'DescribeInstances',
          principal:
            'arn:aws:iam::100000000002:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_AdministratorAccess_0fed56ec5d997fc5',
          service: 'ec2',
          level: 'list'
        },
        {
          action: 'DescribeInstances',
          principal: 'arn:aws:iam::100000000002:role/EC2Admin',
          service: 'ec2',
          level: 'list'
        }
      ]
    }
  },
  {
    name: 'within an organization',
    data: '1',
    request: {
      resource: 'arn:aws:s3:::who-can-org',
      actions: ['s3:ListBucket']
    },
    expected: {
      who: [
        {
          action: 'ListBucket',
          principal: 'arn:aws:iam::200000000002:user/user1',
          service: 's3',
          level: 'list',
          resourceType: 'bucket'
        },
        {
          action: 'ListBucket',
          principal: 'arn:aws:iam::200000000002:role/S3AbacRole',
          service: 's3',
          level: 'list',
          resourceType: 'bucket'
        },
        {
          action: 'ListBucket',
          principal: 'arn:aws:iam::200000000002:role/S3CrossAccountRole',
          service: 's3',
          level: 'list',
          resourceType: 'bucket'
        },
        {
          action: 'ListBucket',
          principal: 'arn:aws:iam::200000000002:role/VpcBucketRole',
          service: 's3',
          level: 'list',
          resourceType: 'bucket'
        },
        {
          action: 'ListBucket',
          principal:
            'arn:aws:iam::200000000001:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_AdministratorAccess_0fed56ec5d997fc5',
          service: 's3',
          level: 'list',
          resourceType: 'bucket'
        }
      ],
      organizationsNotFound: ['o-33333333']
    }
  },
  {
    name: 'shared with an account',
    data: '1',
    request: {
      resource: 'arn:aws:s3:::who-can-acct',
      actions: ['s3:ListBucket']
    },
    expected: {
      who: [
        {
          action: 'ListBucket',
          level: 'list',
          principal: 'arn:aws:iam::200000000002:role/S3CrossAccountRole',
          service: 's3',
          resourceType: 'bucket'
        },
        {
          action: 'ListBucket',
          principal: 'arn:aws:iam::200000000002:user/user1',
          service: 's3',
          level: 'list',
          resourceType: 'bucket'
        },
        {
          action: 'ListBucket',
          principal:
            'arn:aws:iam::100000000002:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_AdministratorAccess_0fed56ec5d997fc5',
          service: 's3',
          level: 'list',
          resourceType: 'bucket'
        }
      ],
      accountsNotFound: ['999999999999']
    }
  },
  {
    name: 'shared with specific principals',
    data: '1',
    request: {
      resource: 'arn:aws:s3:::who-can-principal',
      actions: ['s3:ListBucket']
    },
    expected: {
      who: [
        {
          action: 'ListBucket',
          level: 'list',
          principal: 'arn:aws:iam::200000000002:role/S3CrossAccountRole',
          service: 's3',
          resourceType: 'bucket'
        },
        {
          action: 'ListBucket',
          principal: 'arn:aws:iam::200000000002:user/user1',
          service: 's3',
          level: 'list',
          resourceType: 'bucket'
        },
        {
          action: 'ListBucket',
          principal:
            'arn:aws:iam::100000000001:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_AdministratorAccess_0fed56ec5d997fc5',
          service: 's3',
          level: 'list',
          resourceType: 'bucket'
        }
      ],
      principalsNotFound: [
        'arn:aws:iam::999999999999:role/missing-role',
        'arn:aws:sts::999999999999:federated-user/Bob'
      ]
    }
  },
  {
    name: 'S3 object wildcard (prefix)',
    data: '1',
    request: {
      resource: 'arn:aws:s3:::wildcard-bucket/reports/*',
      actions: ['s3:GetObject']
    },
    expected: {
      who: [
        {
          action: 'GetObject',
          principal: 'arn:aws:iam::100000000001:role/S3ObjectWildcardRole',
          service: 's3',
          level: 'read',
          allowedPatterns: [
            {
              pattern: 'arn:aws:s3:::wildcard-bucket/reports/*',
              resourceType: 'object'
            },
            {
              pattern: 'arn:aws:s3:::wildcard-bucket/reports/2024/*',
              resourceType: 'object'
            }
          ]
        },
        {
          action: 'GetObject',
          principal:
            'arn:aws:iam::100000000001:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_AdministratorAccess_0fed56ec5d997fc5',
          service: 's3',
          level: 'read',
          allowedPatterns: [
            {
              pattern: '*',
              resourceType: 'object'
            }
          ]
        }
      ]
    }
  },
  {
    name: 'S3 object wildcard (different prefix)',
    data: '1',
    request: {
      resource: 'arn:aws:s3:::wildcard-bucket/other/*',
      actions: ['s3:GetObject']
    },
    expected: {
      who: [
        {
          action: 'GetObject',
          principal:
            'arn:aws:iam::100000000001:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_AdministratorAccess_0fed56ec5d997fc5',
          service: 's3',
          level: 'read',
          allowedPatterns: [
            {
              pattern: '*',
              resourceType: 'object'
            }
          ]
        }
      ]
    }
  },
  {
    name: 'S3 object wildcard (explicit deny subset)',
    data: '1',
    request: {
      resource: 'arn:aws:s3:::wildcard-bucket/reports/private/*',
      actions: ['s3:GetObject'],
      denyDetailsCallback: (details) => details.overallResult === 'ExplicitlyDenied'
    },
    expected: {
      who: [
        {
          action: 'GetObject',
          principal:
            'arn:aws:iam::100000000001:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_AdministratorAccess_0fed56ec5d997fc5',
          service: 's3',
          level: 'read',
          allowedPatterns: [
            {
              pattern: '*',
              resourceType: 'object'
            }
          ]
        }
      ]
    },
    expectedDenyDetails: [
      {
        action: 'GetObject',
        deniedResources: [
          {
            details: [
              {
                denialType: 'Explicit',
                policyIdentifier:
                  'arn:aws:iam::100000000001:role/S3ObjectWildcardDenyRole#S3ObjectWildcardDeny',
                policyType: 'identity',
                statementId: 'DenyPrivate',
                statementIndex: 2
              }
            ],
            pattern: 'arn:aws:s3:::wildcard-bucket/reports/private/*',
            resourceType: 'object'
          }
        ],
        principal: 'arn:aws:iam::100000000001:role/S3ObjectWildcardDenyRole',
        service: 's3',
        type: 'wildcard'
      },
      {
        action: 'GetObject',
        deniedResources: [
          {
            details: [
              {
                denialType: 'Explicit',
                policyIdentifier:
                  'arn:aws:iam::100000000001:role/S3ObjectWildcardRole#S3ObjectWildcards',
                policyType: 'identity',
                statementIndex: 2
              }
            ],
            pattern: 'arn:aws:s3:::wildcard-bucket/reports/private/*',
            resourceType: 'object'
          }
        ],
        principal: 'arn:aws:iam::100000000001:role/S3ObjectWildcardRole',
        service: 's3',
        type: 'wildcard'
      }
    ]
  },
  {
    name: 'S3 object wildcard (explicit deny subset) with grant details',
    data: '1',
    request: {
      resource: 'arn:aws:s3:::wildcard-bucket/reports/private/*',
      actions: ['s3:GetObject'],
      collectGrantDetails: true
    },
    expected: {
      who: [
        {
          action: 'GetObject',
          principal:
            'arn:aws:iam::100000000001:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_AdministratorAccess_0fed56ec5d997fc5',
          service: 's3',
          level: 'read',
          allowedPatterns: [
            {
              pattern: '*',
              resourceType: 'object',
              details: [
                {
                  policyIdentifier: 'arn:aws:iam::100000000001:policy/CustomS3Policy',
                  policyType: 'identity',
                  statementId: 'VisualEditor0',
                  statementIndex: 1
                },
                {
                  policyIdentifier: 'arn:aws:iam::aws:policy/AdministratorAccess',
                  policyType: 'identity',
                  statementIndex: 1
                }
              ]
            }
          ]
        }
      ]
    }
  },
  {
    name: 'S3 object single resource (explicit deny)',
    data: '1',
    request: {
      resource: 'arn:aws:s3:::wildcard-bucket/reports/private/report.pdf',
      actions: ['s3:GetObject'],
      denyDetailsCallback: (details) => details.overallResult === 'ExplicitlyDenied'
    },
    expected: {
      who: [
        {
          action: 'GetObject',
          principal:
            'arn:aws:iam::100000000001:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_AdministratorAccess_0fed56ec5d997fc5',
          service: 's3',
          level: 'read',
          resourceType: 'object'
        }
      ]
    },
    expectedDenyDetails: [
      {
        action: 'GetObject',
        details: [
          {
            denialType: 'Explicit',
            policyIdentifier:
              'arn:aws:iam::100000000001:role/S3ObjectWildcardDenyRole#S3ObjectWildcardDeny',
            policyType: 'identity',
            statementId: 'DenyPrivate',
            statementIndex: 2
          }
        ],
        principal: 'arn:aws:iam::100000000001:role/S3ObjectWildcardDenyRole',
        service: 's3',
        type: 'single'
      },
      {
        action: 'GetObject',
        details: [
          {
            denialType: 'Explicit',
            policyIdentifier:
              'arn:aws:iam::100000000001:role/S3ObjectWildcardRole#S3ObjectWildcards',
            policyType: 'identity',
            statementIndex: 2
          }
        ],
        principal: 'arn:aws:iam::100000000001:role/S3ObjectWildcardRole',
        service: 's3',
        type: 'single'
      }
    ]
  },
  {
    name: 'trust policy with service principal',
    data: '1',
    request: {
      resource: 'arn:aws:iam::200000000002:role/LambdaRole',
      actions: ['sts:AssumeRole']
    },
    expected: {
      who: [
        {
          action: 'AssumeRole',
          principal: 'lambda.amazonaws.com',
          service: 'sts',
          level: 'write',
          resourceType: 'role'
        }
      ]
    }
  },
  {
    name: 'ListBucket with condition',
    data: '1',
    request: {
      resource: 'arn:aws:s3:::vpc-bucket',
      actions: ['s3:ListBucket']
    },
    expected: {
      who: [
        {
          action: 'ListBucket',
          principal: 'arn:aws:iam::200000000002:role/VpcBucketRole',
          service: 's3',
          level: 'list',
          resourceType: 'bucket',
          conditions: {
            identity: {
              allow: [
                {
                  key: 'aws:SourceVpc',
                  op: 'StringEquals',
                  values: ['vpc-123456789']
                }
              ]
            }
          }
        }
      ]
    }
  },
  {
    name: 'ListBucket with condition and no strictContextKeys',
    data: '1',
    request: {
      resource: 'arn:aws:s3:::vpc-bucket',
      actions: ['s3:ListBucket']
    },
    expected: {
      who: [
        {
          action: 'ListBucket',
          principal: 'arn:aws:iam::200000000002:role/VpcBucketRole',
          service: 's3',
          level: 'list',
          resourceType: 'bucket',
          conditions: {
            identity: {
              allow: [
                {
                  key: 'aws:SourceVpc',
                  op: 'StringEquals',
                  values: ['vpc-123456789']
                }
              ]
            }
          }
        }
      ]
    }
  },
  {
    name: 'ListBucket with condition and strictContextKeys aws:SourceVpc',
    data: '1',
    request: {
      resource: 'arn:aws:s3:::vpc-bucket',
      actions: ['s3:ListBucket'],
      strictContextKeys: ['aws:SourceVpc'],
      denyDetailsCallback: (details) => details.overallResult === 'ImplicitlyDenied'
    },
    expected: {
      who: []
    },
    expectedDenyDetails: [
      {
        type: 'single',
        principal: 'arn:aws:iam::200000000002:role/VpcBucketRole',
        service: 's3',
        action: 'ListBucket',
        details: [
          {
            denialType: 'Implicit',
            policyType: 'identity'
          },
          {
            denialType: 'Implicit',
            policyType: 'resource'
          }
        ]
      }
    ]
  },
  {
    name: 'ListBucket with tags and ABAC',
    description:
      'This checks against a bucket with tags that has ABAC enabled so the ABAC role should have access',
    data: '1',
    request: {
      resource: 'arn:aws:s3:::finance-bucket-w-abac',
      actions: ['s3:ListBucket']
    },
    expected: {
      who: [
        {
          action: 'ListBucket',
          level: 'list',
          principal: 'arn:aws:iam::200000000002:role/S3AbacRole',
          service: 's3',
          resourceType: 'bucket'
        },
        {
          action: 'ListBucket',
          level: 'list',
          principal: 'arn:aws:iam::200000000002:role/S3CrossAccountRole',
          service: 's3',
          resourceType: 'bucket'
        },
        {
          action: 'ListBucket',
          level: 'list',
          principal: 'arn:aws:iam::200000000002:user/user1',
          service: 's3',
          resourceType: 'bucket'
        }
      ]
    }
  },
  {
    name: 'ListBucket with tags and ABAC but no matching users',
    description:
      'This checks against a bucket with tags that has ABAC enabled but with different tags, so the ABAC role should not have access',
    data: '1',
    request: {
      resource: 'arn:aws:s3:::sales-bucket-w-abac',
      actions: ['s3:ListBucket']
    },
    expected: {
      who: [
        {
          action: 'ListBucket',
          level: 'list',
          principal: 'arn:aws:iam::200000000002:role/S3CrossAccountRole',
          service: 's3',
          resourceType: 'bucket'
        },
        {
          action: 'ListBucket',
          level: 'list',
          principal: 'arn:aws:iam::200000000002:user/user1',
          service: 's3',
          resourceType: 'bucket'
        }
      ]
    }
  },
  {
    name: 'ListBucket with tags and ABAC, override s3Abac to disabled',
    description:
      'This checks against a bucket with tags that has ABAC enabled but the override is set to disabled, so the ABAC role should not have access',
    data: '1',
    request: {
      resource: 'arn:aws:s3:::finance-bucket-w-abac',
      actions: ['s3:ListBucket'],
      s3AbacOverride: 'disabled'
    },
    expected: {
      who: [
        {
          action: 'ListBucket',
          level: 'list',
          principal: 'arn:aws:iam::200000000002:role/S3CrossAccountRole',
          service: 's3',
          resourceType: 'bucket'
        },
        {
          action: 'ListBucket',
          level: 'list',
          principal: 'arn:aws:iam::200000000002:user/user1',
          service: 's3',
          resourceType: 'bucket'
        }
      ]
    }
  },
  {
    name: 'ListBucket with tags and no ABAC, override s3Abac to enabled',
    description:
      'This checks against a bucket with tags that has ABAC disabled, but override is set to enabled, so the ABAC role should have access',
    data: '1',
    request: {
      resource: 'arn:aws:s3:::finance-bucket',
      actions: ['s3:ListBucket'],
      s3AbacOverride: 'enabled'
    },
    expected: {
      who: [
        {
          action: 'ListBucket',
          level: 'list',
          principal: 'arn:aws:iam::200000000002:role/S3AbacRole',
          service: 's3',
          resourceType: 'bucket'
        },
        {
          action: 'ListBucket',
          level: 'list',
          principal: 'arn:aws:iam::200000000002:role/S3CrossAccountRole',
          service: 's3',
          resourceType: 'bucket'
        },
        {
          action: 'ListBucket',
          level: 'list',
          principal: 'arn:aws:iam::200000000002:user/user1',
          service: 's3',
          resourceType: 'bucket'
        }
      ]
    }
  },
  {
    name: 'single resource with grant details',
    data: '1',
    request: {
      actions: ['ec2:TerminateInstances'],
      resource: 'arn:aws:ec2:us-east-1:100000000001:instance/i-1234567890abcdef0',
      collectGrantDetails: true
    },
    expected: {
      who: [
        {
          action: 'TerminateInstances',
          principal:
            'arn:aws:iam::100000000001:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_AdministratorAccess_0fed56ec5d997fc5',
          service: 'ec2',
          level: 'write',
          resourceType: 'instance',
          details: [
            {
              policyIdentifier: 'arn:aws:iam::aws:policy/AdministratorAccess',
              policyType: 'identity',
              statementIndex: 1
            },
            {
              policyIdentifier:
                'arn:aws:iam::100000000001:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_AdministratorAccess_0fed56ec5d997fc5#AwsSSOInlinePolicy',
              policyType: 'identity',
              statementId: 'Statement1',
              statementIndex: 1
            }
          ]
        }
      ]
    }
  },
  {
    name: 'single resource with grant details (s3 list bucket)',
    data: '1',
    request: {
      resource: 'arn:aws:s3:::vpc-bucket',
      actions: ['s3:ListBucket'],
      collectGrantDetails: true
    },
    expected: {
      who: [
        {
          action: 'ListBucket',
          principal: 'arn:aws:iam::200000000002:role/VpcBucketRole',
          service: 's3',
          level: 'list',
          resourceType: 'bucket',
          conditions: {
            identity: {
              allow: [
                {
                  key: 'aws:SourceVpc',
                  op: 'StringEquals',
                  values: ['vpc-123456789']
                }
              ]
            }
          },
          details: [
            {
              policyIdentifier: 'arn:aws:iam::200000000002:role/VpcBucketRole#ListBucket',
              policyType: 'identity',
              statementIndex: 1
            },
            {
              orgIdentifier: 'r-dh2e',
              policyIdentifier: 'RCPFullAWSAccess',
              policyType: 'rcp',
              statementIndex: 1
            },
            {
              orgIdentifier: 'ou-dh2e-aps19rip',
              policyIdentifier: 'RCPFullAWSAccess',
              policyType: 'rcp',
              statementIndex: 1
            },
            {
              orgIdentifier: '200000000002',
              policyIdentifier: 'RCPFullAWSAccess',
              policyType: 'rcp',
              statementIndex: 1
            },
            {
              orgIdentifier: 'r-dh2e',
              policyIdentifier:
                'arn:aws:organizations::aws:policy/service_control_policy/p-FullAWSAccess',
              policyType: 'scp',
              statementIndex: 1
            },
            {
              orgIdentifier: 'ou-dh2e-aps19rip',
              policyIdentifier:
                'arn:aws:organizations::aws:policy/service_control_policy/p-FullAWSAccess',
              policyType: 'scp',
              statementIndex: 1
            },
            {
              orgIdentifier: '200000000002',
              policyIdentifier:
                'arn:aws:organizations::aws:policy/service_control_policy/p-FullAWSAccess',
              policyType: 'scp',
              statementIndex: 1
            }
          ]
        }
      ]
    }
  },
  {
    name: 'wildcard resource with grant details',
    data: '1',
    request: {
      resource: 'arn:aws:s3:::wildcard-bucket/reports/*',
      actions: ['s3:GetObject'],
      collectGrantDetails: true
    },
    expected: {
      who: [
        {
          action: 'GetObject',
          principal: 'arn:aws:iam::100000000001:role/S3ObjectWildcardRole',
          service: 's3',
          level: 'read',
          allowedPatterns: [
            {
              pattern: 'arn:aws:s3:::wildcard-bucket/reports/*',
              resourceType: 'object',
              details: [
                {
                  policyIdentifier:
                    'arn:aws:iam::100000000001:role/S3ObjectWildcardRole#S3ObjectWildcards',
                  policyType: 'identity',
                  statementIndex: 1
                }
              ]
            },
            {
              pattern: 'arn:aws:s3:::wildcard-bucket/reports/2024/*',
              resourceType: 'object',
              details: [
                {
                  policyIdentifier:
                    'arn:aws:iam::100000000001:role/S3ObjectWildcardRole#S3ObjectWildcards',
                  policyType: 'identity',
                  statementIndex: 1
                }
              ]
            }
          ]
        },
        {
          action: 'GetObject',
          principal:
            'arn:aws:iam::100000000001:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_AdministratorAccess_0fed56ec5d997fc5',
          service: 's3',
          level: 'read',
          allowedPatterns: [
            {
              pattern: '*',
              resourceType: 'object',
              details: [
                {
                  policyIdentifier: 'arn:aws:iam::100000000001:policy/CustomS3Policy',
                  policyType: 'identity',
                  statementId: 'VisualEditor0',
                  statementIndex: 1
                },
                {
                  policyIdentifier: 'arn:aws:iam::aws:policy/AdministratorAccess',
                  policyType: 'identity',
                  statementIndex: 1
                }
              ]
            }
          ]
        }
      ]
    }
  },
  {
    name: 'principalScope with matching account limits results',
    description:
      'Same as "shared with an account" but with principalScope limiting to only account 200000000002',
    data: '1',
    request: {
      resource: 'arn:aws:s3:::who-can-acct',
      actions: ['s3:ListBucket'],
      principalScope: { accounts: ['200000000002'] }
    },
    expected: {
      who: [
        {
          action: 'ListBucket',
          level: 'list',
          principal: 'arn:aws:iam::200000000002:role/S3CrossAccountRole',
          service: 's3',
          resourceType: 'bucket'
        },
        {
          action: 'ListBucket',
          principal: 'arn:aws:iam::200000000002:user/user1',
          service: 's3',
          level: 'list',
          resourceType: 'bucket'
        }
      ],
      accountsNotFound: ['999999999999']
    }
  },
  {
    name: 'principalScope with specific principals limits to those principals',
    description:
      'Same as "shared with specific principals" but scope limits to just one of the cross-account principals. Missing principals from the resource policy are filtered out by the scope intersection.',
    data: '1',
    request: {
      resource: 'arn:aws:s3:::who-can-principal',
      actions: ['s3:ListBucket'],
      principalScope: {
        principals: ['arn:aws:iam::200000000002:role/S3CrossAccountRole']
      }
    },
    expected: {
      who: [
        {
          action: 'ListBucket',
          level: 'list',
          principal: 'arn:aws:iam::200000000002:role/S3CrossAccountRole',
          service: 's3',
          resourceType: 'bucket'
        }
      ]
    }
  },
  {
    name: 'principalScope with no overlap returns empty allowed',
    description: 'When scope accounts do not overlap with resource policy accounts, no results',
    data: '1',
    request: {
      resource: 'arn:aws:ec2:us-east-1:100000000001:instance/i-1234567890abcdef0',
      actions: ['ec2:TerminateInstances'],
      principalScope: { accounts: ['999999999999'] }
    },
    expected: {
      who: []
    }
  },
  {
    name: 'principalScope with same-account principal only does not widen to whole account',
    description:
      'When scope contains only a specific principal ARN, only that principal is tested — the account is not searched broadly',
    data: '1',
    request: {
      resource: 'arn:aws:s3:::who-can-principal',
      actions: ['s3:ListBucket'],
      principalScope: {
        principals: [
          'arn:aws:iam::100000000001:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_AdministratorAccess_0fed56ec5d997fc5'
        ]
      }
    },
    expected: {
      who: [
        {
          action: 'ListBucket',
          level: 'list',
          principal:
            'arn:aws:iam::100000000001:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_AdministratorAccess_0fed56ec5d997fc5',
          service: 's3',
          resourceType: 'bucket'
        }
      ]
    }
  },
  {
    name: 'principalScope with account and principal for same account does not duplicate results',
    description:
      'When scope has both accounts and principals for the same account, the principal is covered by the account loop and should not appear twice',
    data: '1',
    request: {
      resource: 'arn:aws:s3:::who-can-acct',
      actions: ['s3:ListBucket'],
      principalScope: {
        accounts: ['100000000002'],
        principals: [
          'arn:aws:iam::100000000002:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_AdministratorAccess_0fed56ec5d997fc5'
        ]
      }
    },
    expected: {
      who: [
        {
          action: 'ListBucket',
          principal:
            'arn:aws:iam::100000000002:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_AdministratorAccess_0fed56ec5d997fc5',
          service: 's3',
          level: 'list',
          resourceType: 'bucket'
        }
      ],
      accountsNotFound: ['999999999999']
    }
  },
  {
    name: 'principalScope with service principal when resource policy names it',
    description:
      'LambdaRole trust policy names lambda.amazonaws.com. Scoping to that service principal should find it.',
    data: '1',
    request: {
      resource: 'arn:aws:iam::200000000002:role/LambdaRole',
      actions: ['sts:AssumeRole'],
      principalScope: {
        principals: ['lambda.amazonaws.com']
      }
    },
    expected: {
      who: [
        {
          action: 'AssumeRole',
          principal: 'lambda.amazonaws.com',
          service: 'sts',
          level: 'write',
          resourceType: 'role'
        }
      ]
    }
  },
  {
    name: 'principalScope with service principal when resource policy does not name it',
    description:
      'The who-can-acct bucket policy does not name any service principal. Scoping to lambda.amazonaws.com should find nothing.',
    data: '1',
    request: {
      resource: 'arn:aws:s3:::who-can-acct',
      actions: ['s3:ListBucket'],
      principalScope: {
        principals: ['lambda.amazonaws.com']
      }
    },
    expected: {
      who: [],
      accountsNotFound: ['999999999999']
    }
  },
  {
    name: 'principalScope with bad OU path returns empty results',
    description:
      'When the scope contains an OU path that does not exist, it resolves to no accounts and produces no results',
    data: '1',
    request: {
      resource: 'arn:aws:s3:::who-can-acct',
      actions: ['s3:ListBucket'],
      principalScope: {
        ous: ['o-11111111/r-dh2e/ou-nonexistent']
      }
    },
    expected: {
      who: [],
      accountsNotFound: ['999999999999']
    }
  },
  {
    name: 'principalScope with empty scope returns empty results',
    description:
      'An empty principalScope ({}) resolves to no accounts and no principals, so nothing is tested',
    data: '1',
    request: {
      resource: 'arn:aws:s3:::who-can-acct',
      actions: ['s3:ListBucket'],
      principalScope: {}
    },
    expected: {
      who: [],
      accountsNotFound: ['999999999999']
    }
  },

  // ===== PrincipalArn filter integration tests (dataset 2) =====

  {
    name: 'same-account exact PrincipalArn trust policy',
    description:
      'Trust policy with Principal:"*" and StringEquals aws:PrincipalArn narrows to exactly one same-account principal. Duplicate canary: the principal must appear exactly once.',
    data: '2',
    request: {
      resource: 'arn:aws:iam::400000000002:role/exact-match-target',
      actions: ['sts:AssumeRole']
    },
    expected: {
      who: [
        {
          action: 'AssumeRole',
          principal: 'arn:aws:iam::400000000002:role/local-alpha',
          service: 'sts',
          level: 'write',
          resourceType: 'role'
        }
      ]
    }
  },
  {
    name: 'cross-account wildcard PrincipalArn trust policy',
    description:
      'Trust policy with Principal:"*" and ArnLike aws:PrincipalArn narrows to cross-account principals matching the wildcard pattern.',
    data: '2',
    request: {
      resource: 'arn:aws:iam::400000000002:role/wildcard-match-target',
      actions: ['sts:AssumeRole']
    },
    expected: {
      who: [
        {
          action: 'AssumeRole',
          principal: 'arn:aws:iam::400000000001:role/alpha-role',
          service: 'sts',
          level: 'write',
          resourceType: 'role'
        }
      ]
    }
  },
  {
    name: 'wildcard trust policy with PrincipalServiceName condition',
    description:
      'Trust policy with Principal:"*" and StringEquals aws:PrincipalServiceName extracts the named service principal. Functional delta from main branch.',
    data: '2',
    request: {
      resource: 'arn:aws:iam::400000000002:role/service-name-target',
      actions: ['sts:AssumeRole']
    },
    expected: {
      who: [
        {
          action: 'AssumeRole',
          principal: 'lambda.amazonaws.com',
          service: 'sts',
          level: 'write',
          resourceType: 'role'
        }
      ]
    }
  },
  {
    name: 'mixed explicit account grant plus wildcard PrincipalArn',
    description:
      'Trust policy with two statements: one granting an explicit account, another with wildcard + ArnLike PrincipalArn. Expected: union of account-granted principals and pattern-matched principals. Index/non-index divergence canary.',
    data: '2',
    request: {
      resource: 'arn:aws:iam::400000000002:role/mixed-grant-target',
      actions: ['sts:AssumeRole']
    },
    expected: {
      who: [
        {
          action: 'AssumeRole',
          principal: 'arn:aws:iam::400000000001:role/alpha-role',
          service: 'sts',
          level: 'write',
          resourceType: 'role'
        },
        {
          action: 'AssumeRole',
          principal: 'arn:aws:iam::400000000001:role/beta-role',
          service: 'sts',
          level: 'write',
          resourceType: 'role'
        },
        {
          action: 'AssumeRole',
          principal: 'arn:aws:iam::400000000002:role/local-alpha',
          service: 'sts',
          level: 'write',
          resourceType: 'role'
        },
        {
          action: 'AssumeRole',
          principal: 'arn:aws:iam::400000000002:role/local-beta',
          service: 'sts',
          level: 'write',
          resourceType: 'role'
        }
      ]
    }
  },
  {
    name: 'NotPrincipal trust policy excludes named principal',
    description:
      'Trust policy with Allow + NotPrincipal excludes the named principal. PrincipalArn filter is not built (safety: NotPrincipal). All eligible principals except the excluded one should appear. Same-account roles can assume without identity-side sts:AssumeRole permission.',
    data: '2',
    request: {
      resource: 'arn:aws:iam::400000000002:role/not-principal-target',
      actions: ['sts:AssumeRole']
    },
    expected: {
      who: [
        {
          action: 'AssumeRole',
          principal: 'arn:aws:iam::400000000001:role/alpha-role',
          service: 'sts',
          level: 'write',
          resourceType: 'role'
        },
        {
          action: 'AssumeRole',
          principal: 'arn:aws:iam::400000000001:role/beta-role',
          service: 'sts',
          level: 'write',
          resourceType: 'role'
        },
        {
          action: 'AssumeRole',
          principal: 'arn:aws:iam::400000000002:role/deny-derived-allow-target',
          service: 'sts',
          level: 'write',
          resourceType: 'role'
        },
        {
          action: 'AssumeRole',
          principal: 'arn:aws:iam::400000000002:role/deny-explicit-target',
          service: 'sts',
          level: 'write',
          resourceType: 'role'
        },
        {
          action: 'AssumeRole',
          principal: 'arn:aws:iam::400000000002:role/duplicate-specific-target',
          service: 'sts',
          level: 'write',
          resourceType: 'role'
        },
        {
          action: 'AssumeRole',
          principal: 'arn:aws:iam::400000000002:role/exact-match-target',
          service: 'sts',
          level: 'write',
          resourceType: 'role'
        },
        {
          action: 'AssumeRole',
          principal: 'arn:aws:iam::400000000002:role/local-alpha',
          service: 'sts',
          level: 'write',
          resourceType: 'role'
        },
        {
          action: 'AssumeRole',
          principal: 'arn:aws:iam::400000000002:role/mixed-grant-target',
          service: 'sts',
          level: 'write',
          resourceType: 'role'
        },
        {
          action: 'AssumeRole',
          principal: 'arn:aws:iam::400000000002:role/no-condition-target',
          service: 'sts',
          level: 'write',
          resourceType: 'role'
        },
        {
          action: 'AssumeRole',
          principal: 'arn:aws:iam::400000000002:role/not-principal-target',
          service: 'sts',
          level: 'write',
          resourceType: 'role'
        },
        {
          action: 'AssumeRole',
          principal: 'arn:aws:iam::400000000002:role/principal-account-stringlike-target',
          service: 'sts',
          level: 'write',
          resourceType: 'role'
        },
        {
          action: 'AssumeRole',
          principal: 'arn:aws:iam::400000000002:role/replacement-var-target',
          service: 'sts',
          level: 'write',
          resourceType: 'role'
        },
        {
          action: 'AssumeRole',
          principal: 'arn:aws:iam::400000000002:role/resource-acct-bypass-target',
          service: 'sts',
          level: 'write',
          resourceType: 'role'
        },
        {
          action: 'AssumeRole',
          principal: 'arn:aws:iam::400000000002:role/s3-reader',
          service: 'sts',
          level: 'write',
          resourceType: 'role'
        },
        {
          action: 'AssumeRole',
          principal: 'arn:aws:iam::400000000002:role/service-name-target',
          service: 'sts',
          level: 'write',
          resourceType: 'role'
        },
        {
          action: 'AssumeRole',
          principal: 'arn:aws:iam::400000000002:role/service-name-wins-target',
          service: 'sts',
          level: 'write',
          resourceType: 'role'
        },
        {
          action: 'AssumeRole',
          principal: 'arn:aws:iam::400000000002:role/tagged-role',
          service: 'sts',
          level: 'write',
          resourceType: 'role'
        },
        {
          action: 'AssumeRole',
          principal: 'arn:aws:iam::400000000002:role/wildcard-match-target',
          service: 'sts',
          level: 'write',
          resourceType: 'role'
        }
      ],
      allAccountsChecked: true
    }
  },
  {
    name: 'wildcard trust policy with no conditions (safety valve)',
    description:
      'Trust policy with Principal:"*" and no conditions. PrincipalArn filter is not built. All principals with sts:AssumeRole permission are checked. Same-account roles can assume without identity-side sts:AssumeRole permission.',
    data: '2',
    request: {
      resource: 'arn:aws:iam::400000000002:role/no-condition-target',
      actions: ['sts:AssumeRole']
    },
    expected: {
      who: [
        {
          action: 'AssumeRole',
          principal: 'arn:aws:iam::400000000001:role/alpha-role',
          service: 'sts',
          level: 'write',
          resourceType: 'role'
        },
        {
          action: 'AssumeRole',
          principal: 'arn:aws:iam::400000000001:role/beta-role',
          service: 'sts',
          level: 'write',
          resourceType: 'role'
        },
        {
          action: 'AssumeRole',
          principal: 'arn:aws:iam::400000000002:role/deny-derived-allow-target',
          service: 'sts',
          level: 'write',
          resourceType: 'role'
        },
        {
          action: 'AssumeRole',
          principal: 'arn:aws:iam::400000000002:role/deny-explicit-target',
          service: 'sts',
          level: 'write',
          resourceType: 'role'
        },
        {
          action: 'AssumeRole',
          principal: 'arn:aws:iam::400000000002:role/duplicate-specific-target',
          service: 'sts',
          level: 'write',
          resourceType: 'role'
        },
        {
          action: 'AssumeRole',
          principal: 'arn:aws:iam::400000000002:role/exact-match-target',
          service: 'sts',
          level: 'write',
          resourceType: 'role'
        },
        {
          action: 'AssumeRole',
          principal: 'arn:aws:iam::400000000002:role/local-alpha',
          service: 'sts',
          level: 'write',
          resourceType: 'role'
        },
        {
          action: 'AssumeRole',
          principal: 'arn:aws:iam::400000000002:role/local-beta',
          service: 'sts',
          level: 'write',
          resourceType: 'role'
        },
        {
          action: 'AssumeRole',
          principal: 'arn:aws:iam::400000000002:role/mixed-grant-target',
          service: 'sts',
          level: 'write',
          resourceType: 'role'
        },
        {
          action: 'AssumeRole',
          principal: 'arn:aws:iam::400000000002:role/no-condition-target',
          service: 'sts',
          level: 'write',
          resourceType: 'role'
        },
        {
          action: 'AssumeRole',
          principal: 'arn:aws:iam::400000000002:role/not-principal-target',
          service: 'sts',
          level: 'write',
          resourceType: 'role'
        },
        {
          action: 'AssumeRole',
          principal: 'arn:aws:iam::400000000002:role/principal-account-stringlike-target',
          service: 'sts',
          level: 'write',
          resourceType: 'role'
        },
        {
          action: 'AssumeRole',
          principal: 'arn:aws:iam::400000000002:role/replacement-var-target',
          service: 'sts',
          level: 'write',
          resourceType: 'role'
        },
        {
          action: 'AssumeRole',
          principal: 'arn:aws:iam::400000000002:role/resource-acct-bypass-target',
          service: 'sts',
          level: 'write',
          resourceType: 'role'
        },
        {
          action: 'AssumeRole',
          principal: 'arn:aws:iam::400000000002:role/s3-reader',
          service: 'sts',
          level: 'write',
          resourceType: 'role'
        },
        {
          action: 'AssumeRole',
          principal: 'arn:aws:iam::400000000002:role/service-name-target',
          service: 'sts',
          level: 'write',
          resourceType: 'role'
        },
        {
          action: 'AssumeRole',
          principal: 'arn:aws:iam::400000000002:role/service-name-wins-target',
          service: 'sts',
          level: 'write',
          resourceType: 'role'
        },
        {
          action: 'AssumeRole',
          principal: 'arn:aws:iam::400000000002:role/tagged-role',
          service: 'sts',
          level: 'write',
          resourceType: 'role'
        },
        {
          action: 'AssumeRole',
          principal: 'arn:aws:iam::400000000002:role/wildcard-match-target',
          service: 'sts',
          level: 'write',
          resourceType: 'role'
        }
      ],
      allAccountsChecked: true
    }
  },

  // ===== Deny-side and edge-case PrincipalArn filter tests (dataset 2) =====

  {
    name: 'deny-derived allow via StringNotLike narrows to matching principals',
    description:
      'Trust policy with Allow (broad PrincipalArn) + Deny with StringNotLike PrincipalArn. The deny blocks everyone NOT matching the pattern, creating an effective allow-list. Only principals matching the deny pattern survive. Deny-derived filtering applies to ALL principals including resource-account.',
    data: '2',
    request: {
      resource: 'arn:aws:iam::400000000002:role/deny-derived-allow-target',
      actions: ['sts:AssumeRole']
    },
    expected: {
      who: [
        {
          action: 'AssumeRole',
          principal: 'arn:aws:iam::400000000001:role/alpha-role',
          service: 'sts',
          level: 'write',
          resourceType: 'role'
        }
      ],
      allAccountsChecked: true
    }
  },
  {
    name: 'explicit deny via StringLike blocks matching principal including resource-account',
    description:
      'Trust policy with Allow (broad PrincipalArn) + Deny with StringLike PrincipalArn targeting local-alpha. Verifies that resource-account principals are NOT exempt from deny-side filtering (asymmetry with allow-side exemption). local-alpha should be denied even though it is in the resource account.',
    data: '2',
    request: {
      resource: 'arn:aws:iam::400000000002:role/deny-explicit-target',
      actions: ['sts:AssumeRole']
    },
    expected: {
      who: [
        {
          action: 'AssumeRole',
          principal: 'arn:aws:iam::400000000001:role/alpha-role',
          service: 'sts',
          level: 'write',
          resourceType: 'role'
        },
        {
          action: 'AssumeRole',
          principal: 'arn:aws:iam::400000000001:role/beta-role',
          service: 'sts',
          level: 'write',
          resourceType: 'role'
        },
        {
          action: 'AssumeRole',
          principal: 'arn:aws:iam::400000000002:role/deny-derived-allow-target',
          service: 'sts',
          level: 'write',
          resourceType: 'role'
        },
        {
          action: 'AssumeRole',
          principal: 'arn:aws:iam::400000000002:role/deny-explicit-target',
          service: 'sts',
          level: 'write',
          resourceType: 'role'
        },
        {
          action: 'AssumeRole',
          principal: 'arn:aws:iam::400000000002:role/duplicate-specific-target',
          service: 'sts',
          level: 'write',
          resourceType: 'role'
        },
        {
          action: 'AssumeRole',
          principal: 'arn:aws:iam::400000000002:role/exact-match-target',
          service: 'sts',
          level: 'write',
          resourceType: 'role'
        },
        {
          action: 'AssumeRole',
          principal: 'arn:aws:iam::400000000002:role/local-beta',
          service: 'sts',
          level: 'write',
          resourceType: 'role'
        },
        {
          action: 'AssumeRole',
          principal: 'arn:aws:iam::400000000002:role/mixed-grant-target',
          service: 'sts',
          level: 'write',
          resourceType: 'role'
        },
        {
          action: 'AssumeRole',
          principal: 'arn:aws:iam::400000000002:role/no-condition-target',
          service: 'sts',
          level: 'write',
          resourceType: 'role'
        },
        {
          action: 'AssumeRole',
          principal: 'arn:aws:iam::400000000002:role/not-principal-target',
          service: 'sts',
          level: 'write',
          resourceType: 'role'
        },
        {
          action: 'AssumeRole',
          principal: 'arn:aws:iam::400000000002:role/principal-account-stringlike-target',
          service: 'sts',
          level: 'write',
          resourceType: 'role'
        },
        {
          action: 'AssumeRole',
          principal: 'arn:aws:iam::400000000002:role/replacement-var-target',
          service: 'sts',
          level: 'write',
          resourceType: 'role'
        },
        {
          action: 'AssumeRole',
          principal: 'arn:aws:iam::400000000002:role/resource-acct-bypass-target',
          service: 'sts',
          level: 'write',
          resourceType: 'role'
        },
        {
          action: 'AssumeRole',
          principal: 'arn:aws:iam::400000000002:role/s3-reader',
          service: 'sts',
          level: 'write',
          resourceType: 'role'
        },
        {
          action: 'AssumeRole',
          principal: 'arn:aws:iam::400000000002:role/service-name-target',
          service: 'sts',
          level: 'write',
          resourceType: 'role'
        },
        {
          action: 'AssumeRole',
          principal: 'arn:aws:iam::400000000002:role/service-name-wins-target',
          service: 'sts',
          level: 'write',
          resourceType: 'role'
        },
        {
          action: 'AssumeRole',
          principal: 'arn:aws:iam::400000000002:role/tagged-role',
          service: 'sts',
          level: 'write',
          resourceType: 'role'
        },
        {
          action: 'AssumeRole',
          principal: 'arn:aws:iam::400000000002:role/wildcard-match-target',
          service: 'sts',
          level: 'write',
          resourceType: 'role'
        }
      ],
      allAccountsChecked: true
    }
  },
  {
    name: 'replacement variable in PrincipalArn prevents filter from being built',
    description:
      'Trust policy has two wildcard-Allow statements: one with a replacement variable in PrincipalArn (unusable for static filtering) and one with a literal pattern. Because the first statement lacks a usable filter, buildPrincipalArnFilter returns undefined and no pre-filtering occurs. All principals are simulated; alpha-role matches stmt2 literal pattern, tagged-role matches stmt1 because its team tag resolves to its own ARN.',
    data: '2',
    request: {
      resource: 'arn:aws:iam::400000000002:role/replacement-var-target',
      actions: ['sts:AssumeRole']
    },
    expected: {
      who: [
        {
          action: 'AssumeRole',
          principal: 'arn:aws:iam::400000000001:role/alpha-role',
          service: 'sts',
          level: 'write',
          resourceType: 'role'
        },
        {
          action: 'AssumeRole',
          principal: 'arn:aws:iam::400000000002:role/tagged-role',
          service: 'sts',
          level: 'write',
          resourceType: 'role'
        }
      ],
      allAccountsChecked: true
    }
  },
  {
    name: 'principalScope intersects with PrincipalArn filter',
    description:
      'Mixed-grant trust policy (account grant for 400000000001 + wildcard ArnLike for local-*) combined with principalScope limiting to account 400000000001. Only the intersection is returned: principals in 400000000001 that the trust policy allows. The pattern-matched local-* principals in 400000000002 are excluded by scope.',
    data: '2',
    request: {
      resource: 'arn:aws:iam::400000000002:role/mixed-grant-target',
      actions: ['sts:AssumeRole'],
      principalScope: {
        accounts: ['400000000001']
      }
    },
    expected: {
      who: [
        {
          action: 'AssumeRole',
          principal: 'arn:aws:iam::400000000001:role/alpha-role',
          service: 'sts',
          level: 'write',
          resourceType: 'role'
        },
        {
          action: 'AssumeRole',
          principal: 'arn:aws:iam::400000000001:role/beta-role',
          service: 'sts',
          level: 'write',
          resourceType: 'role'
        }
      ]
    }
  },

  // ===== Resource-account bypass, service-name precedence, PrincipalAccount StringLike, KMS =====

  {
    name: 'resource-account principals bypass allow-side PrincipalArn filter',
    description:
      'Trust policy grants the resource account explicitly (stmt1) and has a wildcard PrincipalArn pattern matching only cross-account roles (stmt2). Resource-account principals do not match the PrincipalArn pattern but must still appear because (a) they bypass the allow-side filter via the resource-account / exemptAccounts exemption and (b) the account grant in stmt1 allows them in simulation. Note: Principal:{"AWS":"ACCOUNT"} (unlike Principal:"*") requires identity-side sts:AssumeRole — only roles with that permission appear.',
    data: '2',
    request: {
      resource: 'arn:aws:iam::400000000002:role/resource-acct-bypass-target',
      actions: ['sts:AssumeRole']
    },
    expected: {
      who: [
        {
          action: 'AssumeRole',
          principal: 'arn:aws:iam::400000000001:role/alpha-role',
          service: 'sts',
          level: 'write',
          resourceType: 'role'
        },
        {
          action: 'AssumeRole',
          principal: 'arn:aws:iam::400000000002:role/local-alpha',
          service: 'sts',
          level: 'write',
          resourceType: 'role'
        },
        {
          action: 'AssumeRole',
          principal: 'arn:aws:iam::400000000002:role/local-beta',
          service: 'sts',
          level: 'write',
          resourceType: 'role'
        },
        {
          action: 'AssumeRole',
          principal: 'arn:aws:iam::400000000002:role/tagged-role',
          service: 'sts',
          level: 'write',
          resourceType: 'role'
        }
      ]
    }
  },
  {
    name: 'named service principal wins over unnamed service-only keys',
    description:
      'Trust policy with both aws:PrincipalIsAWSService=true and aws:PrincipalServiceName=lambda.amazonaws.com in the same statement. The named service key (PrincipalServiceName) takes precedence over the unnamed service-only key (PrincipalIsAWSService) and the statement is treated as granting the named service principal, not as an unnamed service-only statement to skip.',
    data: '2',
    request: {
      resource: 'arn:aws:iam::400000000002:role/service-name-wins-target',
      actions: ['sts:AssumeRole']
    },
    expected: {
      who: [
        {
          action: 'AssumeRole',
          principal: 'lambda.amazonaws.com',
          service: 'sts',
          level: 'write',
          resourceType: 'role'
        }
      ]
    }
  },
  {
    name: 'literal PrincipalAccount via StringLike narrows to matching account',
    description:
      'Trust policy with StringLike aws:PrincipalAccount = "400000000001" (literal value, no wildcards). The StringLike-with-literal narrowing is new and was previously only unit-tested. Expected: only principals in account 400000000001 with sts:AssumeRole permission.',
    data: '2',
    request: {
      resource: 'arn:aws:iam::400000000002:role/principal-account-stringlike-target',
      actions: ['sts:AssumeRole']
    },
    expected: {
      who: [
        {
          action: 'AssumeRole',
          principal: 'arn:aws:iam::400000000001:role/alpha-role',
          service: 'sts',
          level: 'write',
          resourceType: 'role'
        },
        {
          action: 'AssumeRole',
          principal: 'arn:aws:iam::400000000001:role/beta-role',
          service: 'sts',
          level: 'write',
          resourceType: 'role'
        }
      ]
    }
  },
  {
    name: 'KMS kms:CallerAccount positive — principals in matching account are allowed',
    description:
      'KMS key policy with kms:CallerAccount = 400000000001. Only principals in that account with kms:Decrypt identity permission should be allowed. This is the first end-to-end KMS coverage for the CallerAccount narrowing logic.',
    data: '2',
    request: {
      resource: 'arn:aws:kms:us-east-1:400000000002:key/test-key-positive',
      actions: ['kms:Decrypt']
    },
    expected: {
      who: [
        {
          action: 'Decrypt',
          principal: 'arn:aws:iam::400000000001:role/alpha-role',
          service: 'kms',
          level: 'write',
          resourceType: 'key'
        },
        {
          action: 'Decrypt',
          principal: 'arn:aws:iam::400000000001:role/beta-role',
          service: 'kms',
          level: 'write',
          resourceType: 'key'
        }
      ]
    }
  },
  {
    name: 'KMS kms:CallerAccount negative — non-existent account returns empty',
    description:
      'KMS key policy with kms:CallerAccount = 999999999999 (account not in dataset). Expected: no principals found, account reported as not found.',
    data: '2',
    request: {
      resource: 'arn:aws:kms:us-east-1:400000000002:key/test-key-negative',
      actions: ['kms:Decrypt']
    },
    expected: {
      who: [],
      accountsNotFound: ['999999999999']
    }
  },
  {
    name: 'duplicate specific principal from explicit principal + PrincipalArn condition',
    description:
      'Trust policy where the same principal appears in specificPrincipals twice: once from an explicit Principal element (stmt1) and once from a StringEquals aws:PrincipalArn condition (stmt2). The result must contain the principal exactly once.',
    data: '2',
    request: {
      resource: 'arn:aws:iam::400000000002:role/duplicate-specific-target',
      actions: ['sts:AssumeRole']
    },
    expected: {
      who: [
        {
          action: 'AssumeRole',
          principal: 'arn:aws:iam::400000000002:role/local-alpha',
          service: 'sts',
          level: 'write',
          resourceType: 'role'
        }
      ]
    }
  },
  {
    name: 'S3 bucket with no bucket policy — same-account identity-based access found',
    description:
      'S3 bucket with no bucket policy. Same-account principals with identity-based s3:ListBucket permission should still be found. Without checkAllForCurrentAccount the index path may miss same-account principals that only have identity-based access.',
    data: '2',
    request: {
      resource: 'arn:aws:s3:::no-policy-bucket',
      actions: ['s3:ListBucket']
    },
    expected: {
      who: [
        {
          action: 'ListBucket',
          principal: 'arn:aws:iam::400000000002:role/s3-reader',
          service: 's3',
          level: 'list',
          resourceType: 'bucket'
        }
      ]
    }
  }
]

beforeAll(async () => {
  for (const datasetId of new Set(whoCanIntegrationTests.map((test) => test.data))) {
    const client = await getTestDatasetClient(datasetId)
    await makePrincipalIndex(client)
  }
})

/**
 * Sort who can results for comparison in tests
 *
 * @param who Array of WhoCanAllowed objects to sort
 * @returns Sorted array of WhoCanAllowed objects
 */
function sortWhoCanResults(who: WhoCanAllowed[]) {
  const sorted = who.map((result) => {
    const allowedPatterns = result.allowedPatterns
      ? [...result.allowedPatterns]
          .map((pattern) => ({
            ...pattern,
            details: pattern.details ? [...pattern.details].sort(compareGrantDetails) : undefined
          }))
          .sort((a, b) => {
            if (a.pattern < b.pattern) return -1
            if (a.pattern > b.pattern) return 1
            if (a.resourceType < b.resourceType) return -1
            if (a.resourceType > b.resourceType) return 1
            return 0
          })
      : undefined

    return {
      ...result,
      details: result.details ? [...result.details].sort(compareGrantDetails) : undefined,
      allowedPatterns
    }
  })

  return sorted.sort((a, b) => {
    if (a.principal < b.principal) return -1
    if (a.principal > b.principal) return 1
    if (a.service < b.service) return -1
    if (a.service > b.service) return 1
    if (a.action < b.action) return -1
    if (a.action > b.action) return 1
    return 0
  })
}

type GrantDetail = {
  policyType: string
  policyIdentifier?: string
  statementId?: string
  statementIndex: number
}

type DenialDetail = {
  policyType: string
  policyIdentifier?: string
  statementId?: string
  denialType: string
}

function sortDenyDetails(details: WhoCanDenyDetail[] | undefined): WhoCanDenyDetail[] {
  const sorted = (details || []).map((detail) => {
    if (detail.type === 'single') {
      return {
        ...detail,
        details: [...detail.details].sort(compareDenialDetails)
      }
    }

    return {
      ...detail,
      deniedResources: [...detail.deniedResources]
        .map((resource) => ({
          ...resource,
          details: [...resource.details].sort(compareDenialDetails)
        }))
        .sort((a, b) => {
          if (a.pattern < b.pattern) return -1
          if (a.pattern > b.pattern) return 1
          if (a.resourceType < b.resourceType) return -1
          if (a.resourceType > b.resourceType) return 1
          return 0
        })
    }
  })

  return sorted.sort((a, b) => {
    if (a.principal < b.principal) return -1
    if (a.principal > b.principal) return 1
    if (a.service < b.service) return -1
    if (a.service > b.service) return 1
    if (a.action < b.action) return -1
    if (a.action > b.action) return 1
    return 0
  })
}

function compareDenialDetails(a: DenialDetail, b: DenialDetail) {
  if (a.policyType < b.policyType) return -1
  if (a.policyType > b.policyType) return 1
  const aPolicy = a.policyIdentifier ?? ''
  const bPolicy = b.policyIdentifier ?? ''
  if (aPolicy < bPolicy) return -1
  if (aPolicy > bPolicy) return 1
  const aStmt = a.statementId ?? ''
  const bStmt = b.statementId ?? ''
  return 0
}

function compareGrantDetails(a: GrantDetail, b: GrantDetail) {
  if (a.policyType < b.policyType) return -1
  if (a.policyType > b.policyType) return 1
  const aPolicy = a.policyIdentifier ?? ''
  const bPolicy = b.policyIdentifier ?? ''
  if (aPolicy < bPolicy) return -1
  if (aPolicy > bPolicy) return 1
  const aStmt = a.statementId ?? ''
  const bStmt = b.statementId ?? ''
  if (aStmt < bStmt) return -1
  if (aStmt > bStmt) return 1
  return a.statementIndex - b.statementIndex
}

/**
 * Runs all test cases for a dataset through a single processor with the given
 * tuning, then asserts each settled result matches the expected output.
 *
 * @param datasetId - The test dataset to use.
 * @param withIndex - Whether to use the principal index.
 * @param tuningLabel - Human-readable label for the tuning configuration.
 * @param tuning - Processor tuning overrides.
 */
async function runParallelProcessorTest(
  datasetId: string,
  withIndex: boolean,
  tuningLabel: string,
  tuning: {
    workerThreads?: number
    mainThreadConcurrency?: number
    perWorkerConcurrency?: number
    maxRequestsInProgress?: number
  }
): Promise<void> {
  //Given a set of configs
  const configs = getTestDatasetConfigs(datasetId)

  const resultsMap = new Map<string, WhoCanResponse | string>()
  const requestIdMap = new Map<string, { testIndex: number; testName: string }>()

  //And a processor with the specified tuning
  const processor = await WhoCanProcessor.create({
    collectConfigs: configs,
    partition: 'aws',
    tuning,
    ignorePrincipalIndex: !withIndex,
    onRequestSettled: async (event) => {
      if (event.status === 'fulfilled') {
        resultsMap.set(event.requestId, event.result)
      } else {
        resultsMap.set(event.requestId, event.error.message)
      }
    }
  })

  try {
    //When we send all the requests
    for (let i = 0; i < whoCanIntegrationTests.length; i++) {
      const test = whoCanIntegrationTests[i]
      const { name, request, data } = test
      if (data !== datasetId) {
        continue
      }

      const requestId = processor.enqueueWhoCan({
        actions: request.actions,
        resource: request.resource,
        resourceAccount: request.resourceAccount,
        principalScope: request.principalScope,
        strictContextKeys: request.strictContextKeys,
        denyDetailsCallback: request.denyDetailsCallback
      })
      requestIdMap.set(requestId, { testIndex: i, testName: name })
    }

    //And wait for all results to be processed
    await processor.waitForIdle()

    //Then all results should be present and without errors
    for (const [requestId, requestInfo] of requestIdMap.entries()) {
      const result = resultsMap.get(requestId)
      expect(
        result,
        `No result found for ${requestInfo.testName} (index ${requestInfo.testIndex})`
      ).toBeDefined()

      if (typeof result === 'string') {
        assert.fail(`Error for ${requestInfo.testName} (index ${requestInfo.testIndex}): ${result}`)
      }
    }

    //And the results should match the expected output for each test
    for (const [requestId, result] of resultsMap.entries()) {
      const { testIndex, testName } = requestIdMap.get(requestId)!
      const test = whoCanIntegrationTests[testIndex]
      const { expected, expectedDenyDetails } = test
      if (typeof result !== 'string') {
        if (test.request.s3AbacOverride) {
          // Skip verifying results for tests with s3AbacOverride in the parallel test since it is a processor level setting and won't match
          continue
        }
        const message = `Results do not match for test "${testName}" (index ${testIndex})`
        assertWhoCanResponse(
          result,
          removeExpectedGrantDetails(expected),
          expectedDenyDetails,
          message
        )
      }
    }
  } finally {
    await processor.shutdown()
  }
}

const processorTuningConfigs = [
  {
    label: 'default',
    tuning: { workerThreads: 2, mainThreadConcurrency: 0, perWorkerConcurrency: 10 }
  },
  {
    label: 'serial admission (maxRequestsInProgress: 1)',
    tuning: {
      workerThreads: 1,
      mainThreadConcurrency: 0,
      perWorkerConcurrency: 10,
      maxRequestsInProgress: 1
    }
  },
  {
    label: 'limited parallelism (maxRequestsInProgress: 2)',
    tuning: {
      workerThreads: 1,
      mainThreadConcurrency: 0,
      perWorkerConcurrency: 10,
      maxRequestsInProgress: 2
    }
  },
  {
    label: 'main thread only (workerThreads: 0)',
    tuning: { workerThreads: 0, mainThreadConcurrency: 50 }
  }
]

describe('whoCan Integration Tests', () => {
  for (const withIndex of [false, true]) {
    describe('running tests in parallel', () => {
      const uniqueDatasetIds = new Set(whoCanIntegrationTests.map((test) => test.data))
      for (const datasetId of uniqueDatasetIds) {
        for (const { label, tuning } of processorTuningConfigs) {
          it(`dataset ${datasetId}, ${label} (withIndex: ${withIndex})`, async () => {
            await runParallelProcessorTest(datasetId, withIndex, label, tuning)
          })
        }
      }
    })

    for (const test of whoCanIntegrationTests) {
      const { name, request, expected, expectedDenyDetails, only, data } = test

      // Set worker threads to 1 for tests so it gets tested but doesn't saturate CPUs
      request.workerThreads = 1
      const func = only ? it.only : it
      const testName = `${name} (withIndex: ${withIndex})`
      func(testName, async () => {
        //Given a client
        const configs = getTestDatasetConfigs(data)
        // await createOrDestroyIndex(configs, withIndex)

        //When we call whoCan
        const requestCopy = { ...request }
        requestCopy.ignorePrincipalIndex = !withIndex
        const result = await whoCan(configs, 'aws', requestCopy)

        //Then we expect the result to match the expected output
        assertWhoCanResponse(result, expected, expectedDenyDetails)
      })
    }
  }
})

function removeExpectedGrantDetails(
  expected: WhoCanIntegrationTest['expected']
): WhoCanIntegrationTest['expected'] {
  // This is used for snapshot testing where we want to exclude the deny details from the snapshot but still test them in the test itself
  const copy = JSON.parse(JSON.stringify(expected))
  for (const who of copy.who) {
    if (who.allowedPatterns) {
      for (const pattern of who.allowedPatterns) {
        delete pattern.details
      }
    }
    delete who.details
  }
  return copy
}

/**
 * Helper function to assert that the WhoCanResponse matches the expected output, including sorting results for comparison
 *
 * @param result - The actual WhoCanResponse returned by the whoCan function.
 * @param expected - The expected output for the test case.
 * @param expectedDenyDetails - The expected deny details for the test case, if any.
 * @param message - Optional message to include in assertion errors for better context.
 */
function assertWhoCanResponse(
  result: WhoCanResponse,
  expected: WhoCanIntegrationTest['expected'],
  expectedDenyDetails: WhoCanDenyDetail[] | 'ignore' | undefined,
  message?: string
) {
  expect(sortWhoCanResults(result.allowed), message).toEqual(sortWhoCanResults(expected.who))
  expect(result.allAccountsChecked, message).toEqual(!!expected.allAccountsChecked)
  expect(result.organizationalUnitsNotFound, message).toEqual(
    expected.organizationalUnitsNotFound || []
  )
  expect(result.accountsNotFound, message).toEqual(expected.accountsNotFound || [])
  expect(result.organizationsNotFound, message).toEqual(expected.organizationsNotFound || [])
  expect(result.principalsNotFound.sort(), message).toEqual(
    expected.principalsNotFound?.sort() || []
  )
  if (expectedDenyDetails !== 'ignore') {
    if (expectedDenyDetails) {
      expect(sortDenyDetails(result.denyDetails), message).toEqual(
        sortDenyDetails(expectedDenyDetails)
      )
    } else {
      expect(result.denyDetails, message).toBeUndefined()
    }
  }
}
