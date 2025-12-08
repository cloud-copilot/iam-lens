import { createStorageClient } from '@cloud-copilot/iam-collect'
import { existsSync, rmSync } from 'fs'
import { describe, expect, it } from 'vitest'
import { IamCollectClient } from '../collect/client.js'
import { makePrincipalIndex } from '../principalIndex/makePrincipalIndex.js'
import { getTestDatasetConfigs } from '../test-datasets/testClient.js'
import { ResourceAccessRequest, whoCan, WhoCanAllowed } from './whoCan.js'

const whoCanIntegrationTests: {
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
}[] = [
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
          level: 'write'
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
          level: 'list'
        },
        {
          action: 'ListBucket',
          principal: 'arn:aws:iam::200000000002:role/S3AbacRole',
          service: 's3',
          level: 'list'
        },
        {
          action: 'ListBucket',
          principal: 'arn:aws:iam::200000000002:role/VpcBucketRole',
          service: 's3',
          level: 'list'
        },
        {
          action: 'ListBucket',
          principal:
            'arn:aws:iam::200000000001:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_AdministratorAccess_0fed56ec5d997fc5',
          service: 's3',
          level: 'list'
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
          principal: 'arn:aws:iam::200000000002:user/user1',
          service: 's3',
          level: 'list'
        },
        {
          action: 'ListBucket',
          principal:
            'arn:aws:iam::100000000002:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_AdministratorAccess_0fed56ec5d997fc5',
          service: 's3',
          level: 'list'
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
          principal: 'arn:aws:iam::200000000002:user/user1',
          service: 's3',
          level: 'list'
        },
        {
          action: 'ListBucket',
          principal:
            'arn:aws:iam::100000000001:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_AdministratorAccess_0fed56ec5d997fc5',
          service: 's3',
          level: 'list'
        }
      ],
      principalsNotFound: [
        'arn:aws:iam::999999999999:role/missing-role',
        'arn:aws:sts::999999999999:federated-user/Bob'
      ]
    }
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
          level: 'write'
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
          service: 's3'
        },
        {
          action: 'ListBucket',
          level: 'list',
          principal: 'arn:aws:iam::200000000002:user/user1',
          service: 's3'
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
          principal: 'arn:aws:iam::200000000002:user/user1',
          service: 's3'
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
          principal: 'arn:aws:iam::200000000002:user/user1',
          service: 's3'
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
          service: 's3'
        },
        {
          action: 'ListBucket',
          level: 'list',
          principal: 'arn:aws:iam::200000000002:user/user1',
          service: 's3'
        }
      ]
    }
  }
]

/**
 * Sort who can results for comparison in tests
 *
 * @param who Array of WhoCanAllowed objects to sort
 * @returns Sorted array of WhoCanAllowed objects
 */
function sortWhoCanResults(who: WhoCanAllowed[]) {
  return who.sort((a, b) => {
    if (a.principal < b.principal) return -1
    if (a.principal > b.principal) return 1
    if (a.action < b.action) return -1
    if (a.action > b.action) return 1
    return 0
  })
}

// These tests all run sequentially because first they run without the principals index
// and then they run with it.
describe.sequential('whoCan Integration Tests', () => {
  for (const withIndex of [false, true]) {
    for (const test of whoCanIntegrationTests) {
      const { name, request, expected, only, data } = test
      const func = only ? it.only : it
      const testName = `${name} (withIndex: ${withIndex})`
      func(testName, async () => {
        //Given a client
        const configs = getTestDatasetConfigs(data)

        const path = (configs[0]?.storage as any).path!
        const indexesDir = `${path}/aws/aws/indexes`

        if (!withIndex) {
          //If withIndex is false, delete all principal index files matching the pattern
          const fs = await import('fs')
          const path = await import('path')

          const filesToDelete: string[] = []

          // Check if indexes directory exists
          if (fs.existsSync(indexesDir)) {
            const files = fs.readdirSync(indexesDir)

            // Find all files matching the pattern: principal-index-*.json
            for (const file of files) {
              if (file.startsWith('principal-index-') && file.endsWith('.json')) {
                filesToDelete.push(path.join(indexesDir, file))
              }
            }
          }

          // Delete all found files
          for (const file of filesToDelete) {
            rmSync(file, { force: true })
          }
        } else {
          //If withIndex is true, make sure it is there
          const originalIndexPath = `${indexesDir}/principal-index-principals.json`
          const exists = existsSync(originalIndexPath)
          if (!exists) {
            const client = new IamCollectClient(createStorageClient(configs, 'aws', true))
            await makePrincipalIndex(client)
          }
        }

        //When we call whoCan
        const result = await whoCan(configs, 'aws', request)

        //Then we expect the result to match the expected output
        expect(sortWhoCanResults(result.allowed)).toEqual(sortWhoCanResults(expected.who))
        expect(result.allAccountsChecked).toEqual(!!expected.allAccountsChecked)
        expect(result.organizationalUnitsNotFound).toEqual(
          expected.organizationalUnitsNotFound || []
        )
        expect(result.accountsNotFound).toEqual(expected.accountsNotFound || [])
        expect(result.organizationsNotFound).toEqual(expected.organizationsNotFound || [])
        expect(result.principalsNotFound.sort()).toEqual(expected.principalsNotFound?.sort() || [])
      })
    }
  }
})
