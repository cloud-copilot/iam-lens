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
      customContextKeys: {},
      simulationMode: 'Strict'
    },
    expected: 'Allowed'
  },
  {
    name: 'same account resource request implicitly denied by session policy',
    data: '1',
    request: {
      resourceArn: 'arn:aws:s3:::iam-data-482734',
      resourceAccount: undefined,
      action: 's3:GetBucketPolicy',
      principal:
        'arn:aws:iam::100000000002:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_AdministratorAccess_0fed56ec5d997fc5',
      customContextKeys: {},
      simulationMode: 'Strict',
      sessionPolicy: {
        Version: '2012-10-17',
        Statement: {
          Effect: 'Allow',
          Action: 'ec2:*',
          Resource: '*'
        }
      }
    },
    expected: 'ImplicitlyDenied'
  },
  {
    name: 'same account resource request explicitly denied by session policy',
    data: '1',
    request: {
      resourceArn: 'arn:aws:s3:::iam-data-482734',
      resourceAccount: undefined,
      action: 's3:GetBucketPolicy',
      principal:
        'arn:aws:iam::100000000002:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_AdministratorAccess_0fed56ec5d997fc5',
      customContextKeys: {},
      simulationMode: 'Strict',
      sessionPolicy: {
        Version: '2012-10-17',
        Statement: [
          {
            Effect: 'Allow',
            Action: '*',
            Resource: '*'
          },
          {
            Effect: 'Deny',
            Action: 's3:*',
            Resource: '*'
          }
        ]
      }
    },
    expected: 'ExplicitlyDenied'
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
      customContextKeys: {},
      simulationMode: 'Strict'
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
      customContextKeys: {},
      simulationMode: 'Strict'
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
      customContextKeys: {},
      simulationMode: 'Strict'
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
      customContextKeys: {},
      simulationMode: 'Strict'
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
      customContextKeys: {},
      simulationMode: 'Strict'
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
      customContextKeys: {},
      simulationMode: 'Strict'
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
      customContextKeys: {},
      simulationMode: 'Strict'
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
      customContextKeys: {},
      simulationMode: 'Strict'
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
      customContextKeys: {},
      simulationMode: 'Strict'
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
      customContextKeys: {},
      simulationMode: 'Strict'
    },
    expected: 'ImplicitlyDenied'
  },
  {
    name: 'Get VPCE from aws:SourceVpc allowed',
    data: '1',
    request: {
      resourceArn: 'arn:aws:s3:::iam-data-482734',
      resourceAccount: undefined,
      action: 's3:GetBucketPolicy',
      principal:
        'arn:aws:iam::100000000002:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_AdministratorAccess_0fed56ec5d997fc5',
      customContextKeys: {
        'aws:SourceVpc': 'vpc-00000000001'
      },
      simulationMode: 'Strict'
    },
    expected: 'Allowed'
  },
  {
    name: 'Get VPCE from aws:SourceVpc ExplicitlyDenied',
    data: '1',
    request: {
      resourceArn: 'arn:aws:s3:::iam-data-482734',
      resourceAccount: undefined,
      action: 's3:GetBucketPolicy',
      principal:
        'arn:aws:iam::100000000002:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_AdministratorAccess_0fed56ec5d997fc5',
      customContextKeys: {
        'aws:SourceVpc': 'vpc-00000000002'
      },
      simulationMode: 'Strict'
    },
    expected: 'ExplicitlyDenied'
  },
  {
    name: 'Get VPCE from aws:SourceVpc ImplicitlyDenied',
    data: '1',
    request: {
      resourceArn: 'arn:aws:s3:::iam-data-482734',
      resourceAccount: undefined,
      action: 's3:GetBucketPolicy',
      principal:
        'arn:aws:iam::100000000002:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_AdministratorAccess_0fed56ec5d997fc5',
      customContextKeys: {
        'aws:SourceVpc': 'vpc-00000000003'
      },
      simulationMode: 'Strict'
    },
    expected: 'ImplicitlyDenied'
  },
  {
    name: 'Get VPCE from aws:SourceVpce Allowed',
    data: '1',
    request: {
      resourceArn: 'arn:aws:s3:::iam-data-482734',
      resourceAccount: undefined,
      action: 's3:GetBucketPolicy',
      principal:
        'arn:aws:iam::100000000002:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_AdministratorAccess_0fed56ec5d997fc5',
      customContextKeys: {
        'aws:SourceVpce': 'vpce-00000000001'
      },
      simulationMode: 'Strict'
    },
    expected: 'Allowed'
  },
  {
    name: 'Get VPCE from aws:SourceVpce ExplicitlyDenied',
    data: '1',
    request: {
      resourceArn: 'arn:aws:s3:::iam-data-482734',
      resourceAccount: undefined,
      action: 's3:GetBucketPolicy',
      principal:
        'arn:aws:iam::100000000002:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_AdministratorAccess_0fed56ec5d997fc5',
      customContextKeys: {
        'aws:SourceVpce': 'vpce-00000000002'
      },
      simulationMode: 'Strict'
    },
    expected: 'ExplicitlyDenied'
  },
  {
    name: 'Get VPCE from aws:SourceVpce ImplicitlyDenied',
    data: '1',
    request: {
      resourceArn: 'arn:aws:s3:::iam-data-482734',
      resourceAccount: undefined,
      action: 's3:GetBucketPolicy',
      principal:
        'arn:aws:iam::100000000002:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_AdministratorAccess_0fed56ec5d997fc5',
      customContextKeys: {
        'aws:SourceVpce': 'vpce-00000000003'
      },
      simulationMode: 'Strict'
    },
    expected: 'ImplicitlyDenied'
  },
  {
    name: 'Get S3 Object with bucket policy allowing access',
    data: '1',
    request: {
      resourceArn: 'arn:aws:s3:::who-can-principal/an-object.txt',
      resourceAccount: undefined,
      action: 's3:GetObject',
      principal:
        'arn:aws:iam::100000000001:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_AdministratorAccess_0fed56ec5d997fc5',
      customContextKeys: {},
      simulationMode: 'Strict'
    },
    expected: 'Allowed'
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
        const { result } = await simulateRequest(request, collectClient)

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

describe('simulatePrincipalDoesNotExist', () => {
  it('should throw an error if the principal does not exist', async () => {
    // Given a request with a non-existent principal
    const collectClient = getTestDatasetClient('1')
    const request: SimulationRequest = {
      resourceArn: 'arn:aws:s3:::iam-data-482734',
      resourceAccount: undefined,
      action: 's3:GetBucketPolicy',
      principal: 'arn:aws:iam::100000000002:role/NonExistentRole',
      customContextKeys: {},
      simulationMode: 'Strict'
    }

    // When we run the simulation
    await expect(simulateRequest(request, collectClient)).rejects.toThrow(
      new RegExp('Principal arn:aws:iam::100000000002:role/NonExistentRole does not exist.*')
    )
  })

  it('should not throw an error if ignoreMissingPrincipal is true', async () => {
    // Given a request with a non-existent principal and ignoreMissingPrincipal set to true
    const collectClient = getTestDatasetClient('1')
    const request: SimulationRequest = {
      resourceArn: 'arn:aws:s3:::iam-data-482734',
      resourceAccount: undefined,
      action: 's3:GetBucketPolicy',
      principal: 'arn:aws:iam::100000000002:role/NonExistentRole',
      customContextKeys: {},
      simulationMode: 'Strict',
      ignoreMissingPrincipal: true
    }

    // When we run the simulation
    const { result } = await simulateRequest(request, collectClient)

    // Then the result should not have errors
    expect(result.errors).toBeUndefined()
  })
})

describe('s3 ABAC', () => {
  it('strict mode should not allow ABAC access when ABAC is not enabled on the bucket and tags match', async () => {
    // Given a client with test data
    const collectClient = getTestDatasetClient('1')

    // And a request to access a bucket with matching tags but ABAC not enabled
    const request: SimulationRequest = {
      resourceArn: 'arn:aws:s3:::finance-bucket',
      resourceAccount: undefined,
      action: 's3:GetBucketPolicy',
      principal: 'arn:aws:iam::200000000002:role/s3abacrole',
      customContextKeys: {},
      simulationMode: 'Strict'
    }

    // When we run the simulation
    const { result } = await simulateRequest(request, collectClient)

    // Then the result should not have errors
    expect(result.errors).toBeUndefined()

    // And the result should be ImplicitlyDenied (ABAC conditions are not evaluated when ABAC is not enabled)
    expect(result.analysis?.result).toEqual('ImplicitlyDenied')
  })

  it('strict mode should allow ABAC access when ABAC is enabled on the bucket and tags match', async () => {
    // Given a client with test data
    const collectClient = getTestDatasetClient('1')

    // And a request to access a bucket with matching tags and ABAC enabled
    const request: SimulationRequest = {
      resourceArn: 'arn:aws:s3:::finance-bucket-w-abac',
      resourceAccount: undefined,
      action: 's3:GetBucketPolicy',
      principal: 'arn:aws:iam::200000000002:role/s3abacrole',
      customContextKeys: {},
      simulationMode: 'Strict'
    }

    // When we run the simulation
    const { result } = await simulateRequest(request, collectClient)

    // Then the result should not have errors
    expect(result.errors).toBeUndefined()

    // And the result should be Allowed (ABAC conditions match)
    expect(result.analysis?.result).toEqual('Allowed')
  })

  it('strict mode should not allow ABAC access when ABAC is not enabled on the bucket and the tags do not match', async () => {
    // Given a client with test data
    const collectClient = getTestDatasetClient('1')

    // And a request to access a bucket with non-matching tags and ABAC not enabled
    const request: SimulationRequest = {
      resourceArn: 'arn:aws:s3:::sales-bucket',
      resourceAccount: undefined,
      action: 's3:GetBucketPolicy',
      principal: 'arn:aws:iam::200000000002:role/s3abacrole',
      customContextKeys: {},
      simulationMode: 'Strict'
    }

    // When we run the simulation
    const { result } = await simulateRequest(request, collectClient)

    // Then the result should not have errors
    expect(result.errors).toBeUndefined()

    // And the result should be ImplicitlyDenied (no matching policy)
    expect(result.analysis?.result).toEqual('ImplicitlyDenied')
  })

  it('strict mode should not allow ABAC access when ABAC is enabled on the bucket and the tags do not match', async () => {
    // Given a client with test data
    const collectClient = getTestDatasetClient('1')

    // And a request to access a bucket with non-matching tags even though ABAC is enabled
    const request: SimulationRequest = {
      resourceArn: 'arn:aws:s3:::sales-bucket-w-abac',
      resourceAccount: undefined,
      action: 's3:GetBucketPolicy',
      principal: 'arn:aws:iam::200000000002:role/s3abacrole',
      customContextKeys: {},
      simulationMode: 'Strict'
    }

    // When we run the simulation
    const { result } = await simulateRequest(request, collectClient)

    // Then the result should not have errors
    expect(result.errors).toBeUndefined()

    // And the result should be ImplicitlyDenied (tags don't match the condition)
    expect(result.analysis?.result).toEqual('ImplicitlyDenied')
  })

  ///
  it('discovery mode should not allow ABAC access when ABAC is not enabled on the bucket and tags match', async () => {
    // Given a client with test data
    const collectClient = getTestDatasetClient('1')

    // And a request to access a bucket with matching tags but ABAC not enabled
    const request: SimulationRequest = {
      resourceArn: 'arn:aws:s3:::finance-bucket',
      resourceAccount: undefined,
      action: 's3:GetBucketPolicy',
      principal: 'arn:aws:iam::200000000002:role/s3abacrole',
      customContextKeys: {},
      simulationMode: 'Discovery'
    }

    // When we run the simulation
    const { result } = await simulateRequest(request, collectClient)

    // Then the result should not have errors
    expect(result.errors).toBeUndefined()

    // And the result should be ImplicitlyDenied (ABAC conditions are not evaluated when ABAC is not enabled)
    expect(result.analysis?.result).toEqual('ImplicitlyDenied')
  })

  it('discovery mode should not allow ABAC access to a bucket object when ABAC is not enabled on the bucket and tags match', async () => {
    // Given a client with test data
    const collectClient = getTestDatasetClient('1')

    // And a request to access a bucket object with matching tags but ABAC not enabled
    const request: SimulationRequest = {
      resourceArn: 'arn:aws:s3:::finance-bucket/report.pdf',
      resourceAccount: undefined,
      action: 's3:GetBucketPolicy',
      principal: 'arn:aws:iam::200000000002:role/s3abacrole',
      customContextKeys: {},
      simulationMode: 'Discovery'
    }

    // When we run the simulation
    const { result } = await simulateRequest(request, collectClient)

    // Then the result should not have errors
    expect(result.errors).toBeUndefined()

    // And the result should be ImplicitlyDenied (ABAC conditions are not evaluated when ABAC is not enabled)
    expect(result.analysis?.result).toEqual('ImplicitlyDenied')
  })

  it('discovery mode should allow ABAC access to a bucket object when ABAC is enabled on the bucket and tags match', async () => {
    // Given a client with test data
    const collectClient = getTestDatasetClient('1')

    // And a request to access a bucket with matching tags and ABAC enabled
    const request: SimulationRequest = {
      resourceArn: 'arn:aws:s3:::finance-bucket-w-abac/report.pdf',
      resourceAccount: undefined,
      action: 's3:GetBucketPolicy',
      principal: 'arn:aws:iam::200000000002:role/s3abacrole',
      customContextKeys: {},
      simulationMode: 'Discovery'
    }

    // When we run the simulation
    const { result } = await simulateRequest(request, collectClient)

    // Then the result should not have errors
    expect(result.errors).toBeUndefined()

    // And the result should be Allowed (ABAC conditions match)
    expect(result.analysis?.result).toEqual('Allowed')
  })

  it('discovery mode should allow ABAC access when ABAC is enabled on the bucket and tags match', async () => {
    // Given a client with test data
    const collectClient = getTestDatasetClient('1')

    // And a request to access a bucket with matching tags and ABAC enabled
    const request: SimulationRequest = {
      resourceArn: 'arn:aws:s3:::finance-bucket-w-abac',
      resourceAccount: undefined,
      action: 's3:GetBucketPolicy',
      principal: 'arn:aws:iam::200000000002:role/s3abacrole',
      customContextKeys: {},
      simulationMode: 'Discovery'
    }

    // When we run the simulation
    const { result } = await simulateRequest(request, collectClient)

    // Then the result should not have errors
    expect(result.errors).toBeUndefined()

    // And the result should be Allowed (ABAC conditions match)
    expect(result.analysis?.result).toEqual('Allowed')
  })

  it('discovery mode should not allow ABAC access when ABAC is not enabled on the bucket and the tags do not match', async () => {
    // Given a client with test data
    const collectClient = getTestDatasetClient('1')

    // And a request to access a bucket with non-matching tags and ABAC not enabled
    const request: SimulationRequest = {
      resourceArn: 'arn:aws:s3:::sales-bucket',
      resourceAccount: undefined,
      action: 's3:GetBucketPolicy',
      principal: 'arn:aws:iam::200000000002:role/s3abacrole',
      customContextKeys: {},
      simulationMode: 'Discovery'
    }

    // When we run the simulation
    const { result } = await simulateRequest(request, collectClient)

    // Then the result should not have errors
    expect(result.errors).toBeUndefined()

    // And the result should be ImplicitlyDenied (no matching policy)
    expect(result.analysis?.result).toEqual('ImplicitlyDenied')
  })

  it('discovery mode should not allow ABAC access when ABAC is enabled on the bucket and the tags do not match', async () => {
    // Given a client with test data
    const collectClient = getTestDatasetClient('1')

    // And a request to access a bucket with non-matching tags even though ABAC is enabled
    const request: SimulationRequest = {
      resourceArn: 'arn:aws:s3:::sales-bucket-w-abac',
      resourceAccount: undefined,
      action: 's3:GetBucketPolicy',
      principal: 'arn:aws:iam::200000000002:role/s3abacrole',
      customContextKeys: {},
      simulationMode: 'Discovery'
    }

    // When we run the simulation
    const { result } = await simulateRequest(request, collectClient)

    // Then the result should not have errors
    expect(result.errors).toBeUndefined()

    // And the result should be ImplicitlyDenied (tags don't match the condition)
    expect(result.analysis?.result).toEqual('ImplicitlyDenied')
  })

  describe('overrides', () => {
    it('strict mode should use ABAC override when ABAC is not enabled on the bucket and tags match', async () => {
      // Given a client with test data
      const collectClient = getTestDatasetClient('1')

      // And a request to access a bucket with matching tags but ABAC not enabled
      const request: SimulationRequest = {
        resourceArn: 'arn:aws:s3:::finance-bucket',
        resourceAccount: undefined,
        action: 's3:GetBucketPolicy',
        principal: 'arn:aws:iam::200000000002:role/s3abacrole',
        customContextKeys: {},
        simulationMode: 'Strict',
        s3AbacOverride: 'enabled'
      }

      // When we run the simulation
      const { result } = await simulateRequest(request, collectClient)

      // Then the result should not have errors
      expect(result.errors).toBeUndefined()

      // And the result should be Allowed (ABAC override is enabled)
      expect(result.analysis?.result).toEqual('Allowed')
    })

    it('strict mode should use ABAC override when ABAC is enabled on the bucket and tags match', async () => {
      // Given a client with test data
      const collectClient = getTestDatasetClient('1')

      // And a request to access a bucket with matching tags and ABAC enabled
      const request: SimulationRequest = {
        resourceArn: 'arn:aws:s3:::finance-bucket-w-abac',
        resourceAccount: undefined,
        action: 's3:GetBucketPolicy',
        principal: 'arn:aws:iam::200000000002:role/s3abacrole',
        customContextKeys: {},
        simulationMode: 'Strict',
        s3AbacOverride: 'disabled'
      }

      // When we run the simulation
      const { result } = await simulateRequest(request, collectClient)

      // Then the result should not have errors
      expect(result.errors).toBeUndefined()

      // And the result should be ImplicitlyDenied because ABAC is disabled by the override
      expect(result.analysis?.result).toEqual('ImplicitlyDenied')
    })
  })
})
