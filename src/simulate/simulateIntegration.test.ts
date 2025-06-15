import { EvaluationResult } from '@cloud-copilot/iam-simulate'
import { describe, expect, it } from 'vitest'
import { getTestDatasetClient } from '../test-datasets/testClient.js'
import { simulateRequest, SimulationRequest } from './simulate.js'

const simulateIntegrationTest: {
  only?: true
  name: string
  comment?: string

  data: string
  request: SimulationRequest

  expected: EvaluationResult
  expectedError?: string
}[] = [
  {
    name: 'same account resource request with resource policy',
    data: '1',
    request: {
      resourceArn: 'arn:aws:s3:::iam-data-482734',
      resourceAccount: undefined,
      action: 's3:GetBucketPolicy',
      principal:
        'arn:aws:iam::100000000002:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_AdministratorAccess_0fed56ec5d997fc5',
      customContextKeys: {}
    },
    expected: 'Allowed'
  },
  {
    name: 'cross account allowed only by resource policy',
    data: '1',
    request: {
      resourceArn: 'arn:aws:s3:::iam-data-482734',
      resourceAccount: undefined,
      action: 's3:ListBucket',
      principal:
        'arn:aws:iam::100000000001:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_AdministratorAccess_0fed56ec5d997fc5',
      customContextKeys: {}
    },
    expected: 'Allowed'
  },
  {
    name: 'request blocked by SCP',
    data: '1',
    request: {
      resourceArn: 'arn:aws:s3:::iam-data-482734',
      resourceAccount: undefined,
      action: 's3:PutBucketPolicy',
      principal:
        'arn:aws:iam::100000000002:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_AdministratorAccess_0fed56ec5d997fc5',
      customContextKeys: {}
    },
    expected: 'ExplicitlyDenied'
  },
  {
    name: 'request blocked by RCP',
    data: '1',
    request: {
      resourceArn: 'arn:aws:s3:::restricted-bucket',
      resourceAccount: undefined,
      action: 's3:GetBucketPolicy',
      principal:
        'arn:aws:iam::100000000002:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_AdministratorAccess_0fed56ec5d997fc5',
      customContextKeys: {}
    },
    expected: 'ExplicitlyDenied'
  },
  {
    name: 'Wildcard blocked by SCP',
    data: '1',
    request: {
      resourceArn: undefined,
      resourceAccount: undefined,
      action: 's3:ListAllMyBuckets',
      principal: 'arn:aws:iam::100000000002:user/user1',
      customContextKeys: {}
    },
    expected: 'ExplicitlyDenied'
  },
  {
    name: 'Wildcard blocked by RCP',
    data: '1',
    request: {
      resourceArn: undefined,
      resourceAccount: undefined,
      action: 's3:ListAllMyBuckets',
      principal: 'arn:aws:iam::100000000002:user/user2',
      customContextKeys: {}
    },
    expected: 'ExplicitlyDenied'
  },
  {
    name: 'Implicit deny by Permission Boundary',
    data: '1',
    request: {
      resourceArn: 'arn:aws:ec2:us-east-1:100000000002:instance/i-1234567890abcdef0',
      resourceAccount: undefined,
      action: 'ec2:TerminateInstances',
      principal: 'arn:aws:iam::100000000002:role/EC2Admin',
      customContextKeys: {}
    },
    expected: 'ImplicitlyDenied'
  },
  {
    name: 'Cross org request allowed',
    comment: "This uses a user in the root account, so SCPs don't apply",
    data: '1',
    request: {
      resourceArn: 'arn:aws:s3:::iam-data-482734',
      resourceAccount: undefined,
      action: 's3:ListBucket',
      principal:
        'arn:aws:iam::200000000001:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_AdministratorAccess_0fed56ec5d997fc5',
      customContextKeys: {}
    },
    expected: 'Allowed'
  },
  {
    name: 'Cross org blocked by SCP',
    data: '1',
    request: {
      resourceArn: 'arn:aws:s3:::iam-data-482734',
      resourceAccount: undefined,
      action: 's3:ListBucket',
      principal: 'arn:aws:iam::200000000002:user/user1',
      customContextKeys: {}
    },
    expected: 'ExplicitlyDenied'
  },
  {
    name: 'Cross org blocked by RCP',
    data: '1',
    request: {
      resourceArn: 'arn:aws:s3:::iam-data-482734/data.txt',
      resourceAccount: undefined,
      action: 's3:GetObject',
      principal:
        'arn:aws:iam::200000000001:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_AdministratorAccess_0fed56ec5d997fc5',
      customContextKeys: {}
    },
    expected: 'ExplicitlyDenied'
  },
  {
    name: 'Delete AWS Managed Policy',
    data: '1',
    request: {
      resourceArn: 'arn:aws:iam::aws:policy/AdministratorAccess',
      resourceAccount: '200000000001',
      action: 'iam:DeletePolicy',
      principal:
        'arn:aws:iam::200000000001:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_AdministratorAccess_0fed56ec5d997fc5',
      customContextKeys: {}
    },
    expected: 'ImplicitlyDenied'
  }
]

describe('simulateIntegrationTest', () => {
  for (const test of simulateIntegrationTest) {
    const { name, only, data, request, expected } = test
    const testFn = only ? it.only : it

    testFn(name, async () => {
      // Given a client
      const collectClient = getTestDatasetClient(test.data)

      if (test.expectedError) {
        //If an error is expected
        // Then it should match the expected error
        await expect(simulateRequest(request, collectClient)).rejects.toThrow(
          new RegExp('/' + test.expectedError + '/')
        )
      } else {
        // When we run the simulation
        const result = await simulateRequest(request, collectClient)

        // Then the result should not have errors
        expect(result.errors).toBeUndefined()

        // And the result should match the expected result
        if (result.analysis?.result !== expected) {
          console.log(JSON.stringify(result.analysis?.rcpAnalysis, null, 2))
        }
        expect(result.analysis?.result).toEqual(test.expected)
      }
    })
  }
})
