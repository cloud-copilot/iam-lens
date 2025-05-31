import { describe, expect, it } from 'vitest'
import { IamCollectClient } from '../collect/client.js'
import {
  AccountsToCheck,
  accountsToCheckBasedOnResourcePolicy,
  actionsForWhoCan,
  findResourceTypeForArn,
  ResourceAccessRequest,
  uniqueAccountsToCheck
} from './whoCan.js'

const findResourceTypeForArnTests: {
  only?: boolean
  input: string
  expected: {
    service: string
    key: string
  }
}[] = [
  {
    input: 'arn:aws:s3:::my-bucket',
    expected: {
      service: 's3',
      key: 'bucket'
    }
  },
  {
    input: 'arn:aws:s3:::my-bucket/a',
    expected: {
      service: 's3',
      key: 'object'
    }
  },
  {
    input: 'arn:aws:s3:::my-bucket/a/b/c',
    expected: {
      service: 's3',
      key: 'object'
    }
  },
  {
    input: 'arn:aws:iam::123456789012:user/DavidKerber',
    expected: {
      service: 'iam',
      key: 'user'
    }
  },
  {
    input: 'arn:aws:iam::123456789012:user/Admin/DavidKerber',
    expected: {
      service: 'iam',
      key: 'user'
    }
  },
  {
    input: 'arn:aws:iam::123456789012:group/Admins',
    expected: {
      service: 'iam',
      key: 'group'
    }
  },
  {
    input: 'arn:aws:ec2:us-west-2:123456789012:instance/i-0123456789abcdef0',
    expected: {
      service: 'ec2',
      key: 'instance'
    }
  },
  {
    input: 'arn:aws:dynamodb:us-east-1:123456789012:table/Books',
    expected: {
      service: 'dynamodb',
      key: 'table'
    }
  },
  {
    input: 'arn:aws:kinesis:us-east-1:123456789012:stream/data-stream',
    expected: {
      service: 'kinesis',
      key: 'stream'
    }
  },
  {
    input: 'arn:aws:sns:us-east-1:123456789012:my-topic',
    expected: {
      service: 'sns',
      key: 'topic'
    }
  },
  {
    input: 'arn:aws:logs:us-east-1:123456789012:log-group:/aws/lambda/myFunction',
    expected: {
      service: 'logs',
      key: 'log-group'
    }
  },
  {
    input:
      'arn:aws:logs:us-east-1:123456789012:log-group:/aws/lambda/myFunction:log-stream:fh389r7cj292h',
    expected: {
      service: 'logs',
      key: 'log-stream'
    }
  },
  {
    input: 'arn:aws:ecr:us-west-2:123456789012:repository/my-repo',
    expected: { service: 'ecr', key: 'repository' }
  },
  {
    input: 'arn:aws:ecr:us-west-2:123456789012:repository/my-repo:latest',
    expected: { service: 'ecr', key: 'repository' }
  },
  {
    input:
      'arn:aws:ecr:us-west-2:123456789012:repository/my-repo@sha256:abcdef123456abcdef123456abcdef123456abcdef123456abcdef123456abcdef1234',
    expected: { service: 'ecr', key: 'repository' }
  },
  {
    input: 'arn:aws:lambda:us-east-1:123456789012:function:my-function',
    expected: { service: 'lambda', key: 'function' }
  },
  {
    input: 'arn:aws:lambda:us-east-1:123456789012:function:my-function:PROD',
    expected: { service: 'lambda', key: 'function version' }
  },
  {
    input: 'arn:aws:iam::aws:policy/ReadOnlyAccess',
    expected: { service: 'iam', key: 'policy' }
  },
  {
    input: 'arn:aws:kms:us-east-1:123456789012:alias/my-key',
    expected: { service: 'kms', key: 'alias' }
  },
  {
    input: 'arn:aws:kms:us-east-1:123456789012:key/1234abcd-12ab-34cd-56ef-1234567890ab',
    expected: { service: 'kms', key: 'key' }
  },
  {
    input: 'arn:aws:states:us-east-1:123456789012:stateMachine:MyStateMachine',
    expected: { service: 'states', key: 'statemachine' }
  },
  {
    input: 'arn:aws:sqs:us-east-1:123456789012:my-queue',
    expected: { service: 'sqs', key: 'queue' }
  }
]

describe('findResourceTypeForArn', () => {
  for (const test of findResourceTypeForArnTests) {
    const func = test.only ? it.only : it
    func(`should find the right type for ${test.input}`, async () => {
      // Given an ARN
      const arn = test.input

      // When findResourceTypeForArn is called
      const [service, details] = await findResourceTypeForArn(arn)

      // Then it should return the expected service and key
      expect(service).toEqual(test.expected.service)
      expect(details.key).toEqual(test.expected.key)
    })
  }
})

describe('actionsForWhoCan', () => {
  it('if given actions, should return the actions as long as they are valid', async () => {
    // Given a request with valid and invalid actions
    const request: ResourceAccessRequest = {
      resource: 'arn:aws:s3:::my-bucket',
      actions: ['s3:GetObject', 's3:PutObject', 'invalid:Action', 's3:NonExistent']
    }

    // When actionsForWhoCan is called
    const result = await actionsForWhoCan(request)

    // Then it should return only the valid actions
    expect(result).toContain('s3:GetObject')
    expect(result).toContain('s3:PutObject')
    expect(result).not.toContain('invalid:Action')
    expect(result).not.toContain('s3:NonExistent')
  })

  it('if not given actions, should return all actions for the resource type', async () => {
    // Given a request with no actions
    const request = {
      resource: 'arn:aws:s3:::my-bucket',
      actions: []
    }

    // When actionsForWhoCan is called
    const result = await actionsForWhoCan(request)

    // Then it should return some known actions for the resource type
    expect(result).toContain('s3:GetBucketPolicy')
    expect(result).toContain('s3:GetBucketLocation')
    expect(result).toContain('s3:GetBucketPublicAccessBlock')
  })

  it('should return sts assume role actions for IAM roles', async () => {
    // Given a request with no actions
    const request = {
      resource: 'arn:aws:iam::123456789012:role/MyRole',
      actions: []
    }

    // When actionsForWhoCan is called
    const result = await actionsForWhoCan(request)

    // Then it should return some known actions for the resource type
    // Expect some IAM role actions and all three sts assume role actions
    expect(result).toContain('iam:GetRole')
    expect(result).toContain('iam:PassRole')
    expect(result).toContain('sts:AssumeRole'.toLowerCase())
    expect(result).toContain('sts:AssumeRoleWithWebIdentity'.toLowerCase())
    expect(result).toContain('sts:AssumeRoleWithSAML'.toLowerCase())
  })
})

const accountsToCheckBasedOnResourcePolicyTests: {
  only?: boolean
  name: string
  resourcePolicy: any
  resourceAccountId: string
  expected: Partial<AccountsToCheck>
}[] = [
  {
    name: 'should return all accounts if resource policy allows it',
    resourcePolicy: {
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
    resourceAccountId: '123456789012',
    expected: {
      allAccounts: true,
      specificAccounts: ['123456789012'],
      specificPrincipals: [],
      specificOrganizations: [],
      specificOrganizationalUnits: []
    }
  },
  {
    name: 'should pick up a specific account ID principal',
    resourcePolicy: {
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Allow',
          Principal: { AWS: '111111111111' },
          Action: '*',
          Resource: '*'
        }
      ]
    },
    resourceAccountId: '000000000000',
    expected: {
      allAccounts: false,
      specificAccounts: ['000000000000', '111111111111'],
      specificPrincipals: [],
      specificOrganizations: [],
      specificOrganizationalUnits: []
    }
  },
  {
    name: 'should extract account from root ARN principal',
    resourcePolicy: {
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Allow',
          Principal: { AWS: 'arn:aws:iam::222222222222:root' },
          Action: 'sts:AssumeRole',
          Resource: '*'
        }
      ]
    },
    resourceAccountId: '000000000000',
    expected: {
      allAccounts: false,
      specificAccounts: ['000000000000', '222222222222'],
      specificPrincipals: [],
      specificOrganizations: [],
      specificOrganizationalUnits: []
    }
  },
  {
    name: 'should extract account from account number',
    resourcePolicy: {
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Allow',
          Principal: { AWS: '222222222222' },
          Action: 'sts:AssumeRole',
          Resource: '*'
        }
      ]
    },
    resourceAccountId: '000000000000',
    expected: {
      allAccounts: false,
      specificAccounts: ['000000000000', '222222222222'],
      specificPrincipals: [],
      specificOrganizations: [],
      specificOrganizationalUnits: []
    }
  },
  {
    name: 'should pick up organization ID condition',
    resourcePolicy: {
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Allow',
          Principal: { AWS: '*' },
          Action: '*',
          Resource: '*',
          Condition: { StringEquals: { 'aws:PrincipalOrgID': ['o-aaaaaaaaaa', 'o-bbbbbbbbbb'] } }
        }
      ]
    },
    resourceAccountId: '000000000000',
    expected: {
      allAccounts: false,
      specificAccounts: ['000000000000'],
      specificPrincipals: [],
      specificOrganizations: ['o-aaaaaaaaaa', 'o-bbbbbbbbbb'],
      specificOrganizationalUnits: []
    }
  },
  {
    name: 'should pick up organizational unit paths with ForAnyValue operator',
    resourcePolicy: {
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Allow',
          Principal: { AWS: '*' },
          Action: '*',
          Resource: '*',
          Condition: {
            'ForAnyValue:StringEquals': { 'aws:PrincipalOrgPaths': ['o-aaa/r-bbb/ou-ccc'] }
          }
        }
      ]
    },
    resourceAccountId: '000000000000',
    expected: {
      allAccounts: false,
      specificAccounts: ['000000000000'],
      specificPrincipals: [],
      specificOrganizations: [],
      specificOrganizationalUnits: ['o-aaa/r-bbb/ou-ccc']
    }
  },
  {
    name: 'should pick up aws:PrincipalAccount condition',
    resourcePolicy: {
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Allow',
          Principal: { AWS: '*' },
          Action: '*',
          Resource: '*',
          Condition: { StringEquals: { 'aws:PrincipalAccount': ['444444444444'] } }
        }
      ]
    },
    resourceAccountId: '000000000000',
    expected: {
      allAccounts: false,
      specificAccounts: ['000000000000', '444444444444'],
      specificPrincipals: [],
      specificOrganizations: [],
      specificOrganizationalUnits: []
    }
  },
  {
    name: 'should include service principal as specificPrincipal',
    resourcePolicy: {
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Allow',
          Principal: { Service: 'lambda.amazonaws.com' },
          Action: '*',
          Resource: '*'
        }
      ]
    },
    resourceAccountId: '555555555555',
    expected: {
      allAccounts: false,
      specificAccounts: ['555555555555'],
      specificPrincipals: ['lambda.amazonaws.com'],
      specificOrganizations: [],
      specificOrganizationalUnits: []
    }
  },
  {
    name: 'should include full ARN principal as specificPrincipal',
    resourcePolicy: {
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Allow',
          Principal: { AWS: 'arn:aws:iam::666666666666:role/MyRole' },
          Action: '*',
          Resource: '*'
        }
      ]
    },
    resourceAccountId: '000000000000',
    expected: {
      allAccounts: false,
      specificAccounts: ['000000000000'],
      specificPrincipals: ['arn:aws:iam::666666666666:role/MyRole'],
      specificOrganizations: [],
      specificOrganizationalUnits: []
    }
  },
  {
    name: 'if there is a NotPrincipal, check all accounts',
    resourcePolicy: {
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Allow',
          NotPrincipal: { AWS: 'arn:aws:iam::666666666666:role/MyRole' },
          Action: '*',
          Resource: '*'
        }
      ]
    },
    resourceAccountId: '000000000000',
    expected: {
      allAccounts: true,
      specificAccounts: ['000000000000'],
      specificPrincipals: [],
      specificOrganizations: [],
      specificOrganizationalUnits: []
    }
  }
]

describe('accountsToCheckBasedOnResourcePolicy', () => {
  for (const test of accountsToCheckBasedOnResourcePolicyTests) {
    const func = test.only ? it.only : it
    func(test.name, async () => {
      // Given a resource policy and account ID
      const { resourcePolicy, resourceAccountId } = test

      // When accountsToCheckBasedOnResourcePolicy is called
      const result = await accountsToCheckBasedOnResourcePolicy(resourcePolicy, resourceAccountId)

      // Then it should return the expected accounts
      const expected = test.expected
      expect(result.allAccounts).toEqual(!!expected.allAccounts)
      expect(result.specificAccounts).toEqual(expected.specificAccounts || [])
      expect(result.specificPrincipals).toEqual(expected.specificPrincipals || [])
      expect(result.specificOrganizations).toEqual(expected.specificOrganizations || [])
      expect(result.specificOrganizationalUnits).toEqual(expected.specificOrganizationalUnits || [])
    })
  }
})

describe('uniqueAccountsToCheck', () => {
  it('should return all accounts when allAccounts is true', async () => {
    // Given accountsToCheck with allAccounts set to true
    const accountsToCheck: AccountsToCheck = {
      allAccounts: true,
      specificAccounts: [],
      specificPrincipals: [],
      specificOrganizations: [],
      specificOrganizationalUnits: []
    }

    // And a client that returns a list of accounts
    const allAccounts = ['11111111111', '222222222222', '333333333333']
    const client = {
      allAccounts: async () => allAccounts
      // ...other stubs
    } as unknown as IamCollectClient

    // When uniqueAccountsToCheck is called
    const result = await uniqueAccountsToCheck(client, accountsToCheck)

    // Then it should return an array with a single entry 'all'
    expect(result.accounts).toEqual(allAccounts)
  })

  it('should return unique accounts from specificAccounts', async () => {
    // Given accountsToCheck with specificAccounts
    const accountsToCheck: AccountsToCheck = {
      allAccounts: false,
      specificAccounts: ['100000000001', '100000000002', '100000000003'],
      specificPrincipals: [],
      specificOrganizations: [],
      specificOrganizationalUnits: []
    }

    // And a client that returns which accounts exist
    const client = {
      accountExists: async (accountId: string) => accountId !== '100000000003'
      // ...other stubs
    } as unknown as IamCollectClient

    // When uniqueAccountsToCheck is called
    const result = await uniqueAccountsToCheck(client, accountsToCheck)

    // Then it should return the unique accounts from specificAccounts
    expect(result.accounts).toEqual(['100000000001', '100000000002'])
  })

  it('should return accounts from an OU', async () => {
    // Given accountsToCheck with specificOrganizationalUnits
    const accountsToCheck: AccountsToCheck = {
      allAccounts: false,
      specificAccounts: [],
      specificPrincipals: [],
      specificOrganizations: [],
      specificOrganizationalUnits: ['o-aaa/r-bbb/ou-ccc']
    }

    // And a client that returns accounts for the OU path
    const client = {
      getAccountsForOrgPath: async (orgId: string, ouPath: string[]) => [true, ['111', '222']]
      // ...other stubs
    } as unknown as IamCollectClient

    // When uniqueAccountsToCheck is called
    const result = await uniqueAccountsToCheck(client, accountsToCheck)

    // Then it should return the accounts from the OU
    expect(result.accounts).toEqual(['111', '222'])
    expect(result.organizationalUnitsNotFound).toEqual([])
  })

  it('should return OUs not found', async () => {
    // Given accountsToCheck with specificOrganizationalUnits
    const accountsToCheck: AccountsToCheck = {
      allAccounts: false,
      specificAccounts: [],
      specificPrincipals: [],
      specificOrganizations: [],
      specificOrganizationalUnits: ['o-aaa/r-bbb/ou-missing']
    }

    // And a client that returns not found for the OU path
    const client = {
      getAccountsForOrgPath: async (orgId: string, ouPath: string[]) => [false, []]
      // ...other stubs
    } as unknown as IamCollectClient

    // When uniqueAccountsToCheck is called
    const result = await uniqueAccountsToCheck(client, accountsToCheck)

    // Then it should return the OU as not found
    expect(result.accounts).toEqual([])
    expect(result.organizationalUnitsNotFound).toEqual(['o-aaa/r-bbb/ou-missing'])
  })

  it('should return accounts from an organization', async () => {
    // Given accountsToCheck with specificOrganizations
    const accountsToCheck: AccountsToCheck = {
      allAccounts: false,
      specificAccounts: [],
      specificPrincipals: [],
      specificOrganizations: ['o-xyz'],
      specificOrganizationalUnits: []
    }

    // And a client that returns accounts for the organization
    const client = {
      getAccountsForOrganization: async (orgId: string) => [true, ['123', '456']]
      // ...other stubs
    } as unknown as IamCollectClient

    // When uniqueAccountsToCheck is called
    const result = await uniqueAccountsToCheck(client, accountsToCheck)

    // Then it should return the accounts from the organization
    expect(result.accounts).toEqual(['123', '456'])
    expect(result.organizationsNotFound).toEqual([])
  })

  it('should return organizations not found', async () => {
    // Given accountsToCheck with specificOrganizations
    const accountsToCheck: AccountsToCheck = {
      allAccounts: false,
      specificAccounts: [],
      specificPrincipals: [],
      specificOrganizations: ['o-missing'],
      specificOrganizationalUnits: []
    }

    // And a client that returns not found for the organization
    const client = {
      getAccountsForOrganization: async (orgId: string) => [false, []]
      // ...other stubs
    } as unknown as IamCollectClient

    // When uniqueAccountsToCheck is called
    const result = await uniqueAccountsToCheck(client, accountsToCheck)

    // Then it should return the organization as not found
    expect(result.accounts).toEqual([])
    expect(result.organizationsNotFound).toEqual(['o-missing'])
  })
})
